#!/bin/bash
#SBATCH --job-name=ucx-perftest
#SBATCH --nodes=2
#SBATCH --ntasks=2
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=8
#SBATCH --time=00:10:00
#SBATCH --output=/cosmos/nfs/home/jadhicks/ucx/tmp/out/slurm/perftest-%j.out

# Cross-node ucx_perftest runner supporting both UCT and UCP modes.
#
# Usage:
#   sbatch tmp/test_cxi_perftest.sh TEST [TYPE [TRANSPORT [DEVICE [LAYOUT [LOG_LEVEL [SIZE [ITERS [WARMUP]]]]]]]]
#
# Arguments:
#   TEST       ucx_perftest test name (required), e.g. put_lat, am_lat
#   TYPE       UCT or UCP (default: UCT)
#   LAYOUT     Data layout passed via -D: short, bcopy, or zcopy (default: short)
#   LOG_LEVEL  UCX_LOG_LEVEL value (default: warn)
#   TRANSPORT  UCT: -x flag value  / UCP: UCX_TLS value
#              (default: cxi for UCT, empty for UCP)
#   DEVICE     UCT: -d flag value  / UCP: UCX_NET_DEVICES value
#              (default: cxi0 for UCT, empty for UCP)
#   SIZE       Message size via -s (default: perftest's own default, 8)
#   ITERS      Iteration count via -n (default: perftest's own default, 1000000)
#   WARMUP     Warmup iteration count via -w (default: perftest's own default, 10000)
#
# UCT mode:  ucx_perftest -x TRANSPORT -d DEVICE -t TEST -D LAYOUT [-s SIZE] [-n ITERS] [-w WARMUP]
# UCP mode:  UCX_TLS=TRANSPORT UCX_NET_DEVICES=DEVICE ucx_perftest -t TEST -D LAYOUT [-s SIZE] [-n ITERS] [-w WARMUP]
#
# Rank 0: discovers hsn0 IP, publishes to NFS file, starts server.
# Rank 1: polls for NFS file, sleeps 1 s to let server bind, connects.

UCX=/cosmos/nfs/home/jadhicks/ucx

TEST="${1:-}"
TYPE="${2:-UCT}"

case "$TYPE" in
    UCT)
        TRANSPORT="${5:-cxi}"
        DEVICE="${6:-cxi0}"
        ;;
    UCP)
        TRANSPORT="${5:-}"
        DEVICE="${6:-}"
        ;;
    *)
        echo "Error: TYPE must be UCT or UCP (got: '$TYPE')" >&2
        exit 1
        ;;
esac

LAYOUT="${3:-short}"
LOG_LEVEL="${4:-warn}"
SIZE="${7:-}"
ITERS="${8:-}"
WARMUP="${9:-}"

EXTRA_ARGS=()
[[ -n "$SIZE"   ]] && EXTRA_ARGS+=(-s "$SIZE")
[[ -n "$ITERS"  ]] && EXTRA_ARGS+=(-n "$ITERS")
[[ -n "$WARMUP" ]] && EXTRA_ARGS+=(-w "$WARMUP")
EXTRA_STR="${EXTRA_ARGS[*]}"

if [[ -z "$TEST" ]]; then
    echo "Error: TEST argument is required." >&2
    echo "Usage: sbatch $0 TEST [TYPE [TRANSPORT [DEVICE [LAYOUT [LOG_LEVEL [SIZE [ITERS [WARMUP]]]]]]]]" >&2
    echo "  TEST       ucx_perftest test (e.g. put_lat, am_lat)" >&2
    echo "  TYPE       UCT or UCP             (default: UCT)" >&2
    echo "  LAYOUT     short, bcopy, or zcopy (default: short)" >&2
    echo "  LOG_LEVEL  UCX_LOG_LEVEL          (default: warn)" >&2
    echo "  TRANSPORT  transport / UCX_TLS    (default: cxi for UCT, '' for UCP)" >&2
    echo "  DEVICE     device / UCX_NET_DEVS  (default: cxi0 for UCT, '' for UCP)" >&2
    echo "  SIZE       message size, -s       (default: perftest's own, 8)" >&2
    echo "  ITERS      iterations, -n         (default: perftest's own, 1000000)" >&2
    echo "  WARMUP     warmup iterations, -w  (default: perftest's own, 10000)" >&2
    exit 1
fi

OUT="$UCX/tmp/out/perftest.$SLURM_JOB_ID"
mkdir -p "$OUT" "$UCX/tmp/out"

cat > "$OUT/wrap.sh" << EOF
#!/bin/bash

export UCX_TM_THRESH=0
export UCX_LOG_LEVEL="$LOG_LEVEL"
OUT_DIR="$OUT"
IP_FILE="\$OUT_DIR/ip"

if [[ "\$SLURM_PROCID" == "0" ]]; then
    IP=\$(ip addr show hsn0 | grep 'inet ' | awk '{print \$2}' | cut -d/ -f1 | head -1)
    echo "[rank 0] node: \$(hostname)  hsn0 IP: \$IP"
    echo "\$IP" > "\$IP_FILE"

    if [[ "$TYPE" == "UCT" ]]; then
        echo "[rank 0] server: ucx_perftest -x $TRANSPORT -d $DEVICE -t $TEST -D $LAYOUT"
        stdbuf -oL -eL ucx_perftest -x "$TRANSPORT" -d "$DEVICE" -t "$TEST" -D "$LAYOUT" $EXTRA_STR \
            >"\$OUT_DIR/server.out" 2>"\$OUT_DIR/server.err"
    else
        [[ -n "$TRANSPORT" ]] && export UCX_TLS="$TRANSPORT"
        [[ -n "$DEVICE"    ]] && export UCX_NET_DEVICES="$DEVICE"
        echo "[rank 0] server: ucx_perftest -t $TEST -D $LAYOUT $EXTRA_STR"
        stdbuf -oL -eL ucx_perftest -t "$TEST" -D "$LAYOUT" $EXTRA_STR \
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
        stdbuf -oL -eL ucx_perftest "\$SERVER_IP" -x "$TRANSPORT" -d "$DEVICE" -t "$TEST" -D "$LAYOUT" $EXTRA_STR \
            >"\$OUT_DIR/client.out" 2>"\$OUT_DIR/client.err"
    else
        [[ -n "$TRANSPORT" ]] && export UCX_TLS="$TRANSPORT"
        [[ -n "$DEVICE"    ]] && export UCX_NET_DEVICES="$DEVICE"
        echo "[rank 1] client: ucx_perftest \$SERVER_IP -t $TEST -D $LAYOUT $EXTRA_STR"
        stdbuf -oL -eL ucx_perftest "\$SERVER_IP" -t "$TEST" -D "$LAYOUT" $EXTRA_STR \
            >"\$OUT_DIR/client.out" 2>"\$OUT_DIR/client.err"
    fi
fi
EOF
chmod +x "$OUT/wrap.sh"

srun "$OUT/wrap.sh"
