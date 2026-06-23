# /bin/bash

cd $HOME/ucx

./autogen.sh
./contrib/configure-devel \
    --with-cxi \
    --without-verbs \
    --without-efa \
    --without-rdmacm \
    --enable-examples \
    --enable-debug \
    --disable-gtest \
    --prefix=$HOME/ucx/build

export CPPFLAGS="$CRAY_ROCM_INCLUDE_OPTS"
make -j24
make install
