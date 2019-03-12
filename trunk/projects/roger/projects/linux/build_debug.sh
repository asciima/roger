#!/bin/sh

make build=debug arch=armv7a roger_clean roger_all
make build=debug arch=x86_64 roger_clean roger_all
