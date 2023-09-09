#!/usr/bin/env python
"""
This program scans the output of pahole(1) for suitable kernel objects to
use in UAF vulnerability exploitation.
"""
import argparse
import json
import os.path
import random
import re
import string
import subprocess
from datetime import datetime


SLABS = [8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096, 8192]
SUFFIX_LEN = 10

def get_tmp_filename():
    random.seed(datetime.now().timestamp())
    suffix = ''.join(random.choice(string.ascii_letters) for i in range(SUFFIX_LEN))
    return "/tmp/objscan_{}".format(suffix)

def find_slab_idx(size):
    i = 0
    found = False
    while i < len(SLABS) and size > SLABS[i]:
        i += 1

    if i < len(SLABS):
        found = True

    return found, i

def get_all_objects(fname):
    fd = open(fname, "w", encoding="utf-8")
    subprocess.run(["pahole", "--sizes"], stdout=fd)
    fd.close()

def looks_good(obj):
    proc = subprocess.Popen(["pahole", "-E", obj], stdout=subprocess.PIPE)
    count = 0
    good = False
    while True:
        count += 1
        # Skip the name of the struct
        if count == 1:
            continue
        line = proc.stdout.readline()
        if not line:
            break
        line = str(line, "UTF-8")
        # function pointers
        if re.search(".*\(.*\)", line):
            good = True
            break
        # list_head structs
        if re.search("struct +list_head", line):
            good = True
            break
        # pointers to structs with `op` in their names
        if re.search("struct +.*(ops|operations) +\*", line):
            good = True
            break
    return good

def get_obj_for_slab(out, tmp, target):
    prv_size = SLABS[target-1]
    tgt_size = SLABS[target]
    fdr = open(tmp, "r", encoding="utf-8")
    fdw = open(out, "w", encoding="utf-8")
    while True:
        line = fdr.readline()
        if not line:
            break
        obj, size = re.findall("([_A-Za-z0-9]+)\t", line)
        size = int(size)
        if size <= prv_size or size > tgt_size:
            continue
        if looks_good(obj):
            fdw.write(f"{obj}\n")

    fdr.close()
    fdw.close()

def get_obj_by_size(size):
    found, idx = find_slab_idx(int(size))
    if not found:
        print("No slab available for given size: {} bytes".format(size))
        exit(-1)
    tmp = get_tmp_filename()
    get_all_objects(tmp)
    out = "objscan_kmalloc_{}.txt".format(SLABS[idx])
    get_obj_for_slab(out, tmp, idx)
    os.remove(tmp)
    print("Result in file {}".format(out))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                    prog='objscan',
                    description='Looks for a suitable kernel object')
    parser.add_argument('-s', '--size', required=True,
                        help='Size of the object to find')
    args = parser.parse_args()
    get_obj_by_size(args.size)
