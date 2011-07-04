#!/bin/sh

ERL=erl
EBIN_DIR=$PWD/ebin

$ERL -pa $EBIN_DIR \
        -boot flower
