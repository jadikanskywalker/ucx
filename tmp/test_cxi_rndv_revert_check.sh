#!/bin/bash
#SBATCH --job-name=ucx-cxi-rndv-revert
#SBATCH --nodes=2
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=8
#SBATCH --time=00:08:00
#SBATCH --output=/cosmos/nfs/home/jadhicks/ucx/tmp/out/slurm/test_cxi_rndv_revert-%j.out

UCX=/cosmos/nfs/home/jadhicks/ucx
mkdir -p "$UCX/tmp/out"

srun --output="$UCX/tmp/out/test_cxi_rndv_revert.%j.%N.out" \
    bash -c "
cd \$UCX/tmp/out
UCX_HANDLE_ERRORS=bt UCX_LOG_LEVEL=debug \
    timeout 120 stdbuf -o0 -e0 $UCX/test/gtest/gtest \
    --gtest_filter='*cxi_tag*' 2>&1
echo \"exit status: \$?\"
"
