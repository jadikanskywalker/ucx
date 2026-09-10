#!/bin/bash
#SBATCH --job-name=ucx-cxi-rndv-gdb
#SBATCH --nodes=2
#SBATCH --ntasks-per-node=1
#SBATCH --time=00:08:00
#SBATCH --output=/cosmos/nfs/home/jadhicks/ucx/tmp/out/slurm/test_cxi_rndv_gdb-%j.out

UCX=/cosmos/nfs/home/jadhicks/ucx
mkdir -p "$UCX/tmp/out"

srun --output="$UCX/tmp/out/test_cxi_rndv_gdb.%j.%N.out" \
    bash -c "
echo \"host: \$(hostname)\"
UCX_LOG_LEVEL=debug gdb -q -batch \
    -ex 'set pagination off' \
    -ex 'handle SIGSEGV stop nopass' \
    -ex run \
    -ex 'echo ===BACKTRACE===\n' \
    -ex 'bt full' \
    -ex 'echo ===REGISTERS===\n' \
    -ex 'info registers' \
    -ex 'echo ===DISAS===\n' \
    -ex 'x/8i \$pc-32' \
    -ex quit \
    --args $UCX/test/gtest/gtest --gtest_filter='*cxi_tag_rndv.direct_match_small*'
"
