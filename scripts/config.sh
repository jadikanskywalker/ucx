# /bin/bash

cd $HOME/ucx

./autogen.sh

# /cosmos/nfs/home/jadhicks/ucx/contrib/../configure \
#     --with-cxi \
#     --without-verbs \
#     --without-efa \
#     --without-rdmacm \
#     --disable-logging \
#     --disable-debug \
#     --disable-assertions \
#     --disable-params-check \
#     --prefix=$PWD/build

/cosmos/nfs/home/jadhicks/ucx/contrib/../configure \
    --with-cxi \
    --without-verbs \
    --without-efa \
    --without-rdmacm \
    --enable-gtest \
    --enable-examples \
    --enable-test-apps \
    --with-valgrind=guess \
    --enable-profiling \
    --enable-frame-pointer \
    --enable-stats \
    --enable-debug-data \
    --enable-mt \
    --prefix=$PWD/build

export CPPFLAGS="$CRAY_ROCM_INCLUDE_OPTS"
make -j24
make install
