#!/bin/sh

set -eu

if [ -d ../.git ]; then
  revh=$(git rev-parse --short HEAD 2>/dev/null || true)
  datecode=$(git log -1 --format=%ct HEAD 2>/dev/null || true)
  if [ -n "$revh" ] && [ -n "$datecode" ]; then
    sed -e "s/@SERNO@/${revh}/" serno.h.in > serno.h
    sed -e "s/@DATECODE@/${datecode}/" datecode.h.in > datecode.h
    exit 0
  fi
fi
sed -e "s/@SERNO@/unknown/" serno.h.in > serno.h
sed -e "s/@DATECODE@/0/" datecode.h.in > datecode.h

