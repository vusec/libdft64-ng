#!/usr/bin/python2
import os
import sys
import shutil

binary = sys.argv[1]
addr = 0x7fff00101000 #BIN_START
os.system("prelink -r" + str(addr) + " " + binary)

din = open(binary, "rb").read()
din = din[:0x10] + '\x02' + din[0x11:]
fout = open(binary, "wb")
fout.write(din)
