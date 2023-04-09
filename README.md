# Crymp.net's Gamespy Master server emulator

This repository contains C++ source code of Gamespy master server emulator used by [Crymp.net](https://crymp.net/).

It consists of 3 main components:

- __master__: UDP server where server can send updates
- __browser__: TCP server where clients query for server list and server info
- __proxy__: synchronizes servers received on __master__ to Crymp.net HTTP API

Browser can ran in two modes:

- remote listing: all server info is mirrored from Crymp.net HTTP API
- local listing: all server info comes from __master__ component, isolated from Crymp.net HTTP API

## Running

To run the emulator, run `bin/gsmaster -h crymp.net -p 80`, this will synchronize with `crymp.net:80`, to disable remote listing, set `-r 0` flags. To properly synchronize with Crymp.net, `PROXY_SECRET` must be set in the environment before running the executable.

### Building

To build the project, run `./build.sh`, this will auto-detect between Windows and Linux and build proper binary in `bin/`. To use a different C++ compiler, use `CXX=clang++ ./build.sh` or to use Microsoft Visual Studio, create a new empty project and just import all files found in this project.

## Used libraries

- aluigi's reverse engineered enctypex of GameSpy
- nlohmann's JSON library