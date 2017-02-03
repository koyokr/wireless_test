#!/bin/bash

mkdir -p build && cd $_

cmake -DCMAKE_BUILD_TYPE=Release ../
make
