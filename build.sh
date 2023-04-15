mkdir -p bin

CXX="${CXX:-g++}"
CC="${CC:-gcc}"

FLAGS="-O0 -g -rdynamic"
OS="$(uname -o)"

if [ "$OS" = "Msys" ]; then
    FLAGS="$FLAGS -lws2_32"
else
    FLAGS="$FLAGS -lpthread"
fi

if [ "$SILENT" == "true" ]; then
    FLAGS="$FLAGS -DSILENT=1"
fi

$CXX master.cpp $FLAGS -Wno-conversion -o bin/gsmaster
$CC ping.c -O3 -s -o bin/ping