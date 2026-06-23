#!/bin/bash
#SBATCH --job-name=ucx-perftest
#SBATCH --nodes=2
#SBATCH --ntasks=2
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=8
#SBATCH --time=00:10:00

# Cross-node ucx_perftest runner supporting both UCT and UCP modes.
#
# Usage:
#   sbatch tmp/test_cxi_perftest.sh TEST [TYPE [TRANSPORT [DEVICE]]]
#
# Arguments:
#   TEST       ucx_perftest test name (required), e.g. put_lat, ucp_put_lat
#   TYPE       UCT or UCP (default: UCT)
#   TRANSPORT  UCT: -x flag value  / UCP: UCX_TLS value
#              (default: cxi for UCT, empty for UCP)
#   DEVICE     UCT: -d flag value  / UCP: UCX_NET_DEVICES value
#              (default: cxi0 for UCT, empty for UCP)
#
# UCT mode:  ucx_perftest -x TRANSPORT -d DEVICE -t TEST
# UCP mode:  UCX_TLS=TRANSPORT UCX_NET_DEVICES=DEVICE ucx_perftest -t TEST
#            (env vars omitted when empty)
#
# Rank 0: discovers hsn0 IP, publishes to NFS file, starts server.
# Rank 1: polls for NFS file, sleeps 1 s to let server bind, connects.
#
# Output: tmp/out/perftest.<jobid>.<node>.{out,err}

UCX=/cosmos/nfs/home/jadhicks/ucx

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

if [[ -z "$TEST" ]]; then
    echo "Error: TEST argument is required." >&2
    echo "Usage: sbatch $0 TEST [TYPE [TRANSPORT [DEVICE]]]" >&2
    echo "  TEST       ucx_perftest test (e.g. put_lat, ucp_put_lat)" >&2
    echo "  TYPE       UCT or UCP             (default: UCT)" >&2
    echo "  TRANSPORT  transport / UCX_TLS    (default: cxi for UCT, '' for UCP)" >&2
    echo "  DEVICE     device / UCX_NET_DEVS  (default: cxi0 for UCT, '' for UCP)" >&2
    exit 1
fi

mkdir -p "$UCX/tmp/out"

# Per-job NFS files for rank coordination.
IP_FILE="$UCX/tmp/out/perftest_ip.$SLURM_JOB_ID"
WRAPPER="$UCX/tmp/out/perftest_wrapper.$SLURM_JOB_ID.sh"

# Write a per-rank wrapper executed by srun on each node.
# Outer variables (TYPE, TEST, TRANSPORT, DEVICE, IP_FILE) expand here at
# sbatch time; runtime variables (\$SLURM_PROCID, \$IP, \$SERVER_IP) expand
# on the node.
cat > "$WRAPPER" << EOF
#!/bin/bash
# sbatch-time constants: TYPE=$TYPE  TEST=$TEST  TRANSPORT=$TRANSPORT  DEVICE=$DEVICE

IP_FILE="$IP_FILE"

if [[ "\$SLURM_PROCID" == "0" ]]; then
    # Rank 0: discover hsn0 IP, publish it, start server.
    IP=\$(ip addr show hsn0 | grep 'inet ' | awk '{print \$2}' | cut -d/ -f1 | head -1)
    echo "[rank 0] node: \$(hostname)  hsn0 IP: \$IP"
    echo "\$IP" > "\$IP_FILE"

    if [[ "$TYPE" == "UCT" ]]; then
        echo "[rank 0] server: ucx_perftest -x $TRANSPORT -d $DEVICE -t $TEST"
        ucx_perftest -x "$TRANSPORT" -d "$DEVICE" -t "$TEST"
    else
        [[ -n "$TRANSPORT" ]] && export UCX_TLS="$TRANSPORT"
        [[ -n "$DEVICE"    ]] && export UCX_NET_DEVICES="$DEVICE"
        echo "[rank 0] server: UCX_TLS=\${UCX_TLS:-<unset>} UCX_NET_DEVICES=\${UCX_NET_DEVICES:-<unset>} ucx_perftest -t $TEST"
        ucx_perftest -t "$TEST"
    fi
else
    # Rank 1: wait for IP, then connect as client.
    echo "[rank 1] node: \$(hostname)  waiting for server IP..."
    while [[ ! -f "\$IP_FILE" ]]; do sleep 0.1; done
    SERVER_IP=\$(cat "\$IP_FILE")
    echo "[rank 1] server IP: \$SERVER_IP — sleeping 1 s for server to bind..."
    sleep 1

    if [[ "$TYPE" == "UCT" ]]; then
        echo "[rank 1] client: ucx_perftest \$SERVER_IP -x $TRANSPORT -d $DEVICE -t $TEST"
        ucx_perftest "\$SERVER_IP" -x "$TRANSPORT" -d "$DEVICE" -t "$TEST"
    else
        [[ -n "$TRANSPORT" ]] && export UCX_TLS="$TRANSPORT"
        [[ -n "$DEVICE"    ]] && export UCX_NET_DEVICES="$DEVICE"
        echo "[rank 1] client: UCX_TLS=\${UCX_TLS:-<unset>} UCX_NET_DEVICES=\${UCX_NET_DEVICES:-<unset>} ucx_perftest \$SERVER_IP -t $TEST"
        ucx_perftest "\$SERVER_IP" -t "$TEST"
    fi
fi
EOF
chmod +x "$WRAPPER"

srun --output="$UCX/tmp/out/perftest.%j.%N.out" \
     --error="$UCX/tmp/out/perftest.%j.%N.err" \
     "$WRAPPER"

rm -f "$IP_FILE" "$WRAPPER"
