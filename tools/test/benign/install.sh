#!/bin/sh
set -e
PREFIX=${PREFIX:-/usr/local}
mkdir -p "$PREFIX/bin"
cp ./tool "$PREFIX/bin/tool"
chmod 755 "$PREFIX/bin/tool"
echo 'Kuruldu'
