#!/bin/sh
# Assemble the runnable peer tree from the converted vendor bytecode.
#   peer/lua    vendor Lua 5.1 bytecode (standard format), flat module names
#   peer/shim   our replacements for Trifork's native Lua modules
#   peer/data   DATADIR: identity + pairing state
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC="$ROOT/work/lua_std"
DST="$ROOT/peer/lua"

[ -d "$SRC/mdg" ] || { echo "run the converter first (work/lua_std missing)"; exit 1; }

rm -rf "$DST"
mkdir -p "$DST" "$ROOT/peer/data"

# vendor MDG stack
for f in "$SRC"/mdg/*.luac; do
  cp "$f" "$DST/$(basename "$f" .luac).lua"
done

# protobuf runtime (protoc-gen-lua port) — keep vendor copies, they match pb.so
for m in protobuf encoder decoder descriptor containers listener text_format type_checkers wire_format; do
  cp "$SRC/modules/$m.luac" "$DST/$m.lua"
done
# socket/ssl/ltn12/mime come from LuaRocks instead: vendor copies target the
# patched native layer and would shadow the installed ones.

cp "$ROOT/work/extracted/luafiles/trusted-CAs.pem" "$DST/trusted-CAs.pem"
cp "$ROOT/work/extracted/luafiles/brainpoolP320r1-curve.pem" "$DST/brainpoolP320r1-curve.pem"

echo "peer/lua: $(ls "$DST" | wc -l | tr -d ' ') files"
