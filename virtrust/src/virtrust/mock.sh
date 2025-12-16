#!/usr/bin/env bash

rm -rf build

sleep 1

cmake -S . -B build -DCMAKE_BUILD_TYPE=Coverage -DUSE_MOCK_TSB_AGENT=ON -DENABLE_MOCK=ON

 cd build

make -j 16

make test

cmake --build build --target coverage