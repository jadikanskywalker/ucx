#!/bin/bash
#SBATCH --job-name=ucx-cxi
#SBATCH --nodes=2
#SBATCH --ntasks-per-node=1
#SBATCH --time=00:05:00
#SBATCH --output=/cosmos/nfs/home/jadhicks/ucx/tmp/out/slurm/test_cxi-%j.out

UCX=/cosmos/nfs/home/jadhicks/ucx
mkdir -p "$UCX/tmp/out"

srun --output="$UCX/tmp/out/test_cxi.%j.%N.out" \
    bash -c "
echo '=== env ==='
echo \"host: \$(hostname)  rank: \$SLURM_PROCID\"
echo \"SLINGSHOT_SVC_IDS=\$SLINGSHOT_SVC_IDS\"
echo \"SLINGSHOT_VNIS=\$SLINGSHOT_VNIS\"

echo ''
echo '=== ucx_info -d ==='
UCX_TLS=cxi ucx_info -d 2>&1

echo ''
echo '=== gtest *cxi* ==='
$UCX/test/gtest/gtest --gtest_filter='*cxi*' 2>&1
"
