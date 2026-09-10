#!/bin/bash
#SBATCH --job-name=ucx-cxi-tag
#SBATCH --nodes=2
#SBATCH --ntasks-per-node=1
#SBATCH --time=00:05:00
#SBATCH --output=/cosmos/nfs/home/jadhicks/ucx/tmp/out/slurm/test_cxi_tag_unlink-%j.out

UCX=/cosmos/nfs/home/jadhicks/ucx
mkdir -p "$UCX/tmp/out"

srun --output="$UCX/tmp/out/test_cxi_tag_unlink.%j.%N.out" \
    bash -c "
echo '=== host ==='
hostname

echo ''
echo '=== gtest test_cxi_tag (verbose, watching for UNLINK debug output) ==='
UCX_LOG_LEVEL=debug $UCX/test/gtest/gtest --gtest_filter='*test_cxi_tag*' 2>&1 | grep -iE 'PASSED|FAILED|OK\]|FAILED\]|C_EVENT_UNLINK|cxi TAG|RUN\s'

echo ''
echo '=== gtest full *cxi* regression ==='
$UCX/test/gtest/gtest --gtest_filter='*cxi*' 2>&1 | tail -30
"
