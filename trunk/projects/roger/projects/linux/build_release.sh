#!/bin/sh

make build=release arch=armv7ahf roger_clean roger_all
make build=release arch=x86_64 roger_clean roger_all
