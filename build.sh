mkdir -p bin

g++ master.cpp -lpthread -DIS_LOCAL=1 -Wno-conversion -O2 -s -o bin/gsmaster
