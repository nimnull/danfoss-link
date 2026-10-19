#!/usr/bin/env python3
"""Convert Trifork 'format 204' Lua 5.1 bytecode to standard luac 5.1 chunks.

Format 204 == stock Lua 5.1 undump layout, except every int / size_t field is
a big-endian 7-bit varint (continuation bit 0x80) instead of fixed 4/8 bytes (header still claims sizeof(int)=4,
sizeof(size_t)=4). Debug info is stripped. Instructions and lua_Number stay
fixed width.

Usage: luac204.py <in.luac> <out.luac>
"""
import os
import struct
import sys


# target sizeof(size_t): stock Lua 5.1 refuses chunks that disagree with the
# host. 64-bit hosts need 8; set DLRE_SIZE_T=4 for 32-bit targets.
SIZE_T_BYTES = int(os.environ.get("DLRE_SIZE_T", "8"))
SIZE_T_FMT = "<Q" if SIZE_T_BYTES == 8 else "<I"


class R:
    def __init__(self, b):
        self.b = b
        self.i = 0

    def take(self, n):
        if self.i + n > len(self.b):
            raise EOFError(f"want {n} at {self.i}/{len(self.b)}")
        v = self.b[self.i:self.i + n]
        self.i += n
        return v

    def byte(self):
        return self.take(1)[0]

    def varint(self):
        """Big-endian 7-bit groups, high bit = continuation."""
        val = 0
        for _ in range(6):
            c = self.byte()
            val = (val << 7) | (c & 0x7F)
            if not c & 0x80:
                return val
        raise ValueError("varint too long")


class W:
    def __init__(self):
        self.out = bytearray()

    def raw(self, b):
        self.out += b

    def byte(self, v):
        self.out.append(v)

    def int(self, v):
        self.out += struct.pack("<i", v)

    def size(self, v):
        self.out += struct.pack(SIZE_T_FMT, v)


CHUNK_NAME = None


def string(r, w, is_source=False):
    n = r.varint()
    if is_source and n == 0 and CHUNK_NAME:
        # Debug info is stripped; label the chunk so tracebacks name the module.
        name = ("@" + CHUNK_NAME).encode() + b"\0"
        w.size(len(name))
        w.raw(name)
        return
    w.size(n)
    if n:
        w.raw(r.take(n))


def function(r, w):
    string(r, w, True)           # source
    w.int(r.varint())            # linedefined
    w.int(r.varint())            # lastlinedefined
    for _ in range(4):           # nups, numparams, is_vararg, maxstacksize
        w.byte(r.byte())

    n = r.varint()               # code
    w.int(n)
    w.raw(r.take(4 * n))

    n = r.varint()               # constants
    w.int(n)
    for _ in range(n):
        t = r.byte()
        w.byte(t)
        if t == 0:               # nil
            pass
        elif t == 1:             # boolean
            w.byte(r.byte())
        elif t == 3:             # number
            w.raw(r.take(8))
        elif t == 4:             # string
            string(r, w)
        else:
            raise ValueError(f"bad constant type {t} at {r.i}")

    n = r.varint()               # nested prototypes
    w.int(n)
    for _ in range(n):
        function(r, w)

    n = r.varint()               # debug: lineinfo
    w.int(n)
    for _ in range(n):
        w.int(r.varint())
    n = r.varint()               # debug: locvars
    w.int(n)
    for _ in range(n):
        string(r, w)
        w.int(r.varint())
        w.int(r.varint())
    n = r.varint()               # debug: upvalues
    w.int(n)
    for _ in range(n):
        string(r, w)


def convert(data):
    r = R(data)
    hdr = bytearray(r.take(12))
    if bytes(hdr[:4]) != b"\x1bLua":
        raise ValueError("not a lua chunk")
    if hdr[4] != 0x51:
        raise ValueError(f"lua version {hdr[4]:#x} unsupported")
    if hdr[5] != 0xCC:
        raise ValueError(f"format {hdr[5]} is not 204")
    hdr[5] = 0          # standard format
    hdr[8] = SIZE_T_BYTES   # sizeof(size_t) we emit
    w = W()
    w.raw(bytes(hdr))
    function(r, w)
    if r.i != len(data):
        raise ValueError(f"trailing bytes: consumed {r.i}/{len(data)}")
    return bytes(w.out)


if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    CHUNK_NAME = sys.argv[3] if len(sys.argv) > 3 else os.path.basename(src).replace(".luac", ".lua")
    open(dst, "wb").write(convert(open(src, "rb").read()))
