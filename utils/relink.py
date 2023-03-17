#!/usr/bin/python3
import os
import sys
import shutil
import subprocess

binary = sys.argv[1]

bashbin = shutil.which("bash")
filebin = shutil.which("file")
num_pies_cmd = bashbin + " -c \"" + filebin + " " + binary + " | grep 'pie executable\|shared object' | wc -l\""
num_pies = int(subprocess.check_output(num_pies_cmd, shell=True).decode("utf-8"), 10)
if num_pies == 0:
    sys.exit("Error: It looks like " + binary + " is not a PIE executable. This is either because it was not built as one, or it was, but has already been relinked.")

addr = 0x7fff00101000 #BIN_START
prelink = "prelink"
prelinkbin = shutil.which(prelink)
if not prelinkbin:
    sys.exit("Error: " + prelink + " not found in PATH. Please install it.")
print("[libdft] Relinking " + binary)
ret = os.system(prelinkbin + " -r" + str(addr) + " " + binary)
if ret != 0:
    sys.exit("Error: Prelinking the binary failed.")

din = open(binary, "rb").read()
din = din[:0x10] + b'\x02' + din[0x11:]
fout = open(binary, "wb")
fout.write(din)
