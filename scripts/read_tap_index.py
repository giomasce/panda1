#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Dump a tap index file in a (sort of) human readable format; read
# from stdin, print on stdout

import struct
import sys

def main():
    [header] = struct.unpack("I", sys.stdin.read(4))
    assert header in [4, 8]
    while True:
        fmt = "QQQQ" if header == 8 else "IIII"
        line = sys.stdin.read(4*header)
        if line == '':
            return
        [caller, pc, cr3, count] = struct.unpack(fmt, line)
        print "%016x %016x %016x %d" % (caller, pc, cr3, count)

if __name__ == '__main__':
    main()
