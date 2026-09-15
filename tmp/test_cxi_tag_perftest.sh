#!/bin/bash
#SBATCH --job-name=ucx-cxi-tag-perftest
#SBATCH --nodes=2
#SBATCH --ntasks=2
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=8
#SBATCH --time=00:10:00
#SBATCH --output=/cosmos/nfs/home/jadhicks/ucx/tmp/out/slurm/tag_perftest-%j.out

# Cross-node UCP tag-match latency/bandwidth with UCX_TM_THRESH=0 -- the
# recommended CXI deployment setting (Option 1 in the design plan), and the
# run job 100716 was attempting before the double-completion crash that
# started this investigation. Runs tag_lat/tag_bw (hardware tag offload)
# alongside am_lat (software AM path, no tag offload) for a direct
# before/after comparison point.
#
# Usage: sbatch tmp/test_cxi_tag_perftest.sh

UCX=/cosmos/nfs/home/jadhicks/ucx
OUT="$UCX/tmp/out/tag_perftest.$SLURM_JOB_ID"
mkdir -p "$OUT" "$UCX/tmp/out"

cat > "$OUT/wrap.sh" << 'EOF'
#!/bin/bash
OUT_DIR="__OUT__"
IP_FILE="$OUT_DIR/ip"
export UCX_TM_THRESH=0
export UCX_LOG_LEVEL=warn

run_test() {
    local test="$1" label="$2"
    shift 2
    if [[ "$SLURM_PROCID" == "0" ]]; then
        echo "[rank 0] server: ucx_perftest -t $test $*"
        stdbuf -oL -eL ucx_perftest -t "$test" "$@" \
            >"$OUT_DIR/server.$label.out" 2>"$OUT_DIR/server.$label.err"
    else
        while [[ ! -f "$IP_FILE" ]]; do sleep 0.1; done
        local server_ip
        server_ip=$(cat "$IP_FILE")
        sleep 1
        echo "[rank 1] client: ucx_perftest $server_ip -t $test $*"
        stdbuf -oL -eL ucx_perftest "$server_ip" -t "$test" "$@" \
            >"$OUT_DIR/client.$label.out" 2>"$OUT_DIR/client.$label.err"
    fi
}

if [[ "$SLURM_PROCID" == "0" ]]; then
    IP=$(ip addr show hsn0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -1)
    echo "[rank 0] node: $(hostname)  hsn0 IP: $IP"
    echo "$IP" > "$IP_FILE"
else
    echo "[rank 1] node: $(hostname)  waiting for server IP..."
fi

run_test tag_lat tag_lat
run_test tag_bw  tag_bw -s 65536
run_test am_lat  am_lat
EOF
sed -i "s|__OUT__|$OUT|" "$OUT/wrap.sh"
chmod +x "$OUT/wrap.sh"

srun "$OUT/wrap.sh"
