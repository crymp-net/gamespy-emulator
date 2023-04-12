mkdir -p bin

CXX="${CXX:-g++}"
CC="${CC:gcc}"

FLAGS="-Os -s"
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
$CC ping.c $FLAGS -o bin/ping