#!/bin/bash
#SBATCH --job-name=ucx-perf-debug
#SBATCH --nodes=2
#SBATCH --ntasks=2
#SBATCH --ntasks-per-node=1
#SBATCH --time=00:02:00

TEST="${1:am_lat}"
LAYOUT="${2:short}"

UCX=/cosmos/nfs/home/jadhicks/ucx
OUT=$UCX/tmp/out/perfdebug.$SLURM_JOB_ID
mkdir -p "$OUT"

IP_FILE="$OUT/ip"
cat > "$OUT/wrap.sh" << 'WRAP'
#!/bin/bash
OUT_DIR="$1"
IP_FILE="$OUT_DIR/ip"
if [[ "$SLURM_PROCID" == "0" ]]; then
    IP=$(ip addr show hsn0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -1)
    echo "$IP" > "$IP_FILE"
    UCX_LOG_LEVEL=info ucx_perftest -x cxi -d cxi0 -t am_lat -D zcopy \
        >"$OUT_DIR/server.out" 2>"$OUT_DIR/server.err"
else
    while [[ ! -f "$IP_FILE" ]]; do sleep 0.1; done
    SERVER=$(cat "$IP_FILE")
    sleep 1
    UCX_LOG_LEVEL=info ucx_perftest "$SERVER" -x cxi -d cxi0 -t am_lat -D zcopy \
        >"$OUT_DIR/client.out" 2>"$OUT_DIR/client.err"
fi
WRAP
chmod +x "$OUT/wrap.sh"
srun "$OUT/wrap.sh" "$OUT"
