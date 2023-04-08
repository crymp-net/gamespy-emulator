mkdir -p bin

CXX="${CXX:-g++}"
FLAGS=""
OS="$(uname -o)"

if [ "$LOCAL" = "1" ]; then
    FLAGS="$FLAGS -DIS_LOCAL=1"
fi

if [ "$OS" = "Msys" ]; then
    FLAGS="$FLAGS -lws2_32"
else
    FLAGS="$FLAGS -lpthread"
fi

$CXX master.cpp $FLAGS -Wno-conversion -O2 -s -o bin/gsmaster
