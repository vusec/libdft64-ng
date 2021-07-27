#!/usr/bin/python3
import os
import sys
import shutil

binary = sys.argv[1]
addr = 0x7fff00101000 #BIN_START
prelink = "prelink"
prelinkbin = shutil.which(prelink)
if not prelinkbin:
    sys.exit("Error: " + prelink + " not found in PATH. Please install it.")
ret = os.system(prelinkbin + " -r" + str(addr) + " " + binary)
if ret != 0:
    sys.exit("Error: Prelinking the binary failed.")

din = open(binary, "rb").read()
din = din[:0x10] + b'\x02' + din[0x11:]
fout = open(binary, "wb")
fout.write(din)
