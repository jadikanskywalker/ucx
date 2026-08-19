#!/bin/bash

# Cross-node ucx_perftest runner supporting both UCT and UCP modes.
# Single-combo worker for bench/scripts/sweep_perftest.sh -- run directly
# with sbatch for a one-off test too.
#
# Usage:
#   sbatch bench/scripts/run_perftest.sh TEST [TYPE [TRANSPORT [DEVICE [LAYOUT [LOG_LEVEL]]]]]
#
# Arguments:
#   TEST       ucx_perftest test name (required), e.g. put_lat, am_lat
#   TYPE       UCT or UCP (default: UCT)
#   TRANSPORT  UCT: -x flag value  / UCP: UCX_TLS value
#              (default: cxi for UCT, empty for UCP)
#   DEVICE     UCT: -d flag value  / UCP: UCX_NET_DEVICES value
#              (default: cxi0 for UCT, empty for UCP)
#   LAYOUT     Data layout passed via -D: short, bcopy, or zcopy (default: short)
#   LOG_LEVEL  UCX_LOG_LEVEL value (default: warn)
#
# UCT mode:  ucx_perftest -x TRANSPORT -d DEVICE -t TEST -D LAYOUT
# UCP mode:  UCX_TLS=TRANSPORT UCX_NET_DEVICES=DEVICE ucx_perftest -t TEST -D LAYOUT
#
# Rank 0: discovers hsn0 IP, publishes to NFS file, starts server.
# Rank 1: polls for NFS file, sleeps 1 s to let server bind, connects.
#
# Output lands in bench/out/<test>_<type>_<transport>_<device>_<layout>.<jobid>/
# so a sweep of many combos can be told apart without cross-referencing job IDs.

UCX=/users/jadhicks/ucx

TEST="${1:-}"
TYPE="${2:-UCT}"

case "$TYPE" in
    UCT)
        TRANSPORT="${3:-cxi}"
        DEVICE="${4:-cxi0}"
        ;;
    UCP)
        TRANSPORT="${3:-}"
        DEVICE="${4:-}"
        ;;
    *)
        echo "Error: TYPE must be UCT or UCP (got: '$TYPE')" >&2
        exit 1
        ;;
esac

LAYOUT="${5:-short}"
LOG_LEVEL="${6:-warn}"

if [[ -z "$TEST" ]]; then
    echo "Error: TEST argument is required." >&2
    echo "Usage: sbatch $0 TEST [TYPE [TRANSPORT [DEVICE [LAYOUT [LOG_LEVEL]]]]]" >&2
    echo "  TEST       ucx_perftest test (e.g. put_lat, am_lat)" >&2
    echo "  TYPE       UCT or UCP             (default: UCT)" >&2
    echo "  TRANSPORT  transport / UCX_TLS    (default: cxi for UCT, '' for UCP)" >&2
    echo "  DEVICE     device / UCX_NET_DEVS  (default: cxi0 for UCT, '' for UCP)" >&2
    echo "  LAYOUT     short, bcopy, or zcopy (default: short)" >&2
    echo "  LOG_LEVEL  UCX_LOG_LEVEL          (default: warn)" >&2
    exit 1
fi

COMBO="${TEST}_${TYPE}_${TRANSPORT:-any}_${DEVICE:-any}_${LAYOUT}"
OUT="$UCX/bench/out/$COMBO.$SLURM_JOB_ID"
mkdir -p "$OUT" "$UCX/bench/out/slurm"

cat > "$OUT/wrap.sh" << EOF
#!/bin/bash

export UCX_LOG_LEVEL="$LOG_LEVEL"
OUT_DIR="$OUT"
IP_FILE="\$OUT_DIR/ip"

if [[ "\$SLURM_PROCID" == "0" ]]; then
    IP=\$(ip addr show hsn0 | grep 'inet ' | awk '{print \$2}' | cut -d/ -f1 | head -1)
    echo "[rank 0] node: \$(hostname)  hsn0 IP: \$IP"
    echo "\$IP" > "\$IP_FILE"

    if [[ "$TYPE" == "UCT" ]]; then
        echo "[rank 0] server: ucx_perftest -x $TRANSPORT -d $DEVICE -t $TEST -D $LAYOUT"
        ucx_perftest -x "$TRANSPORT" -d "$DEVICE" -t "$TEST" -D "$LAYOUT" \
            >"\$OUT_DIR/server.out" 2>"\$OUT_DIR/server.err"
    else
        [[ -n "$TRANSPORT" ]] && export UCX_TLS="$TRANSPORT"
        [[ -n "$DEVICE"    ]] && export UCX_NET_DEVICES="$DEVICE"
        echo "[rank 0] server: ucx_perftest -t $TEST -D $LAYOUT"
        ucx_perftest -t "$TEST" -D "$LAYOUT" \
            >"\$OUT_DIR/server.out" 2>"\$OUT_DIR/server.err"
    fi
else
    echo "[rank 1] node: \$(hostname)  waiting for server IP..."
    while [[ ! -f "\$IP_FILE" ]]; do sleep 0.1; done
    SERVER_IP=\$(cat "\$IP_FILE")
    echo "[rank 1] server IP: \$SERVER_IP — sleeping 1 s for server to bind..."
    sleep 1

    if [[ "$TYPE" == "UCT" ]]; then
        echo "[rank 1] client: ucx_perftest \$SERVER_IP -x $TRANSPORT -d $DEVICE -t $TEST -D $LAYOUT"
        ucx_perftest "\$SERVER_IP" -x "$TRANSPORT" -d "$DEVICE" -t "$TEST" -D "$LAYOUT" \
            >"\$OUT_DIR/client.out" 2>"\$OUT_DIR/client.err"
    else
        [[ -n "$TRANSPORT" ]] && export UCX_TLS="$TRANSPORT"
        [[ -n "$DEVICE"    ]] && export UCX_NET_DEVICES="$DEVICE"
        echo "[rank 1] client: ucx_perftest \$SERVER_IP -t $TEST -D $LAYOUT"
        ucx_perftest "\$SERVER_IP" -t "$TEST" -D "$LAYOUT" \
            >"\$OUT_DIR/client.out" 2>"\$OUT_DIR/client.err"
    fi
fi
EOF
chmod +x "$OUT/wrap.sh"

srun --time=00:01:00 --output=/users/jadhicks/ucx/bench/out/slurm/%x-%j-$TEST-$TRANSPORT.out "$OUT/wrap.sh"
