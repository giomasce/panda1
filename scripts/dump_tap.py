#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import struct
import sys

def main():

    if len(sys.argv) != 6:
        print >> sys.stderr, "usage: %s <tap_index> <tap_dump> <caller> <pc> <asid>" % sys.argv[0]
        print >> sys.stderr, "  Dump the content of the tap <caller> <pc> <asid> using index <tap_index> from dump <tap_dump>"
        print >> sys.stderr, "  <caller>, <pc> and <asid> are expected in hexadecimal"
        sys.exit(1)

    _, tap_index, tap_dump, caller, pc, asid = sys.argv
    caller = int(caller, 16)
    pc = int(pc, 16)
    asid = int(asid, 16)

    fin = open(tap_index, 'rb')
    [header] = struct.unpack("I", fin.read(4))
    assert header in [4, 8]
    offset = 0
    while True:
        fmt = "QQQQ" if header == 8 else "IIII"
        line = fin.read(4*header)
        if line == '':
            return
        [this_caller, this_pc, this_asid, count] = struct.unpack(fmt, line)
        if (caller, pc, asid) == (this_caller, this_pc, this_asid):
            fdump = open(tap_dump, 'rb')
            fdump.seek(offset)
            sys.stdout.write(fdump.read(count))
        offset += count

if __name__ == '__main__':
    main()
