#!/bin/bash
#SBATCH --job-name=ucx-bench
#SBATCH --nodes=2
#SBATCH --ntasks=2
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=8
#SBATCH --time=00:10:00
#SBATCH --output=/cosmos/nfs/home/jadhicks/ucx/bench/out/slurm/perftest-%j.out

# Cross-node ucx_perftest runner supporting both UCT and UCP modes, and
# both the cxi and tcp transports, for tcp-vs-cxi comparison.
#
# Generalized from tmp/test_cxi_perftest.sh.
#
# Usage:
#   sbatch bench/run_perftest.sh TEST [TYPE [LAYOUT [LOG_LEVEL [TRANSPORT [DEVICE]]]]]
#
# Arguments:
#   TEST       ucx_perftest test name (required), e.g. put_lat, am_lat
#   TYPE       UCT or UCP (default: UCT)
#   LAYOUT     Data layout passed via -D: short, bcopy, or zcopy (default: short)
#   LOG_LEVEL  UCX_LOG_LEVEL value (default: warn)
#   TRANSPORT  UCT: -x flag value  / UCP: UCX_TLS value       (default: cxi)
#   DEVICE     UCT: -d flag value  / UCP: UCX_NET_DEVICES value
#              (default: cxi0 if TRANSPORT=cxi, hsn0 if TRANSPORT=tcp, else empty)
#
# UCT mode:  ucx_perftest -x TRANSPORT -d DEVICE -t TEST -D LAYOUT
# UCP mode:  UCX_TLS=TRANSPORT UCX_NET_DEVICES=DEVICE ucx_perftest -t TEST -D LAYOUT
#
# Rank 0: discovers hsn0 IP, publishes to NFS file, starts server.
# Rank 1: polls for NFS file, sleeps 1 s to let server bind, connects.
#
# Output: bench/out/<TYPE>_<TEST>_<LAYOUT>_<TRANSPORT>/{server,client}.{out,err}
# (re-running the same combination overwrites its previous output directory).

UCX=/cosmos/nfs/home/jadhicks/ucx

TEST="${1:-}"
TYPE="${2:-UCT}"
LAYOUT="${3:-short}"
LOG_LEVEL="${4:-warn}"
TRANSPORT="${5:-cxi}"

case "$TRANSPORT" in
    cxi) DEFAULT_DEVICE="cxi0" ;;
    tcp) DEFAULT_DEVICE="hsn0" ;;
    *)   DEFAULT_DEVICE=""     ;;
esac
DEVICE="${6:-$DEFAULT_DEVICE}"

if [[ "$TYPE" != "UCT" && "$TYPE" != "UCP" ]]; then
    echo "Error: TYPE must be UCT or UCP (got: '$TYPE')" >&2
    exit 1
fi

if [[ -z "$TEST" ]]; then
    echo "Error: TEST argument is required." >&2
    echo "Usage: sbatch $0 TEST [TYPE [LAYOUT [LOG_LEVEL [TRANSPORT [DEVICE]]]]]" >&2
    echo "  TEST       ucx_perftest test (e.g. put_lat, am_lat)" >&2
    echo "  TYPE       UCT or UCP             (default: UCT)" >&2
    echo "  LAYOUT     short, bcopy, or zcopy (default: short)" >&2
    echo "  LOG_LEVEL  UCX_LOG_LEVEL          (default: warn)" >&2
    echo "  TRANSPORT  transport / UCX_TLS    (default: cxi)" >&2
    echo "  DEVICE     device / UCX_NET_DEVS  (default: cxi0 for cxi, hsn0 for tcp)" >&2
    exit 1
fi

OUT="$UCX/bench/out/${TYPE}_${TEST}_${LAYOUT}_${TRANSPORT}"
rm -rf "$OUT"
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

srun "$OUT/wrap.sh"
