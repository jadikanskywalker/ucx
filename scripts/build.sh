# /bin/bash

./contrib/configure-devel \
    --with-cxi \
    --without-verbs \
    --without-efa \
    --without-rdmacm \
    --with-tcp \
    --enable-examples \
    --enable-debug \
    --prefix=$HOME/ucx/build
export CPPFLAGS="$CRAY_ROCM_INCLUDE_OPTS"

make -j24
make install
