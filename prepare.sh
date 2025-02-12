#!/bin/bash

cmake -B build -DEA64=YES -S src/
cmake --build build --config MinSizeRel -j 8