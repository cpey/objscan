#!/usr/bin/env python
"""
This program scans the output of pahole(1) for suitable kernel objects to
use in UAF vulnerability exploitation.
"""
import argparse
import os.path
import random
import re
import string
import subprocess
import sys
from datetime import datetime


SLABS = [8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096, 8192]
SUFFIX_LEN = 10
IS_FINE_REGEX = [
    # function pointers
    ".*\(\*.*\)",
    # list_head structs
    "struct +list_head",
    # pointers to structs with `op` in their names
    "struct +.*(ops|operations) +\*",
]
IS_ELASTIC_REGEX = "char +.*\[\]"
COMMENT_LINE_REGEX = "\t/\*((?!/\*).)* \*/$"
CLOSING_LINE_REGEX = "};"
EMPTY_LINE_REGEX = "$"


class Scanner:
    objs_fname = None
    temporary_file = False

    def __init__(self, in_file):
        self.objs_fname = in_file
        if not self.objs_fname:
            self.objs_fname = self.get_tmp_filename()
            self.get_all_objects()
            self.temporary_file = True

    def __del__(self):
        if self.temporary_file:
            os.remove(self.objs_fname)

    def get_tmp_filename(self):
        random.seed(datetime.now().timestamp())
        suffix = ''.join(random.choice(string.ascii_letters) for i in range(SUFFIX_LEN))
        return "/tmp/objscan-{}".format(suffix)

    def store_result(self, fdw, result):
        if fdw:
            fdw.write(result)
        else:
            print(result, end="")

    def find_slab_idx(self, size):
        i = 0
        found = False
        while i < len(SLABS) and size > SLABS[i]:
            i += 1

        if i < len(SLABS):
            found = True

        return found, i

    def get_all_objects(self):
        fd = open(self.objs_fname, "w", encoding="utf-8")
        subprocess.run(["pahole", "--sizes"], stdout=fd)
        fd.close()

    def check_member_is_fine(self, line):
        i = 0
        good = False
        while i<len(IS_FINE_REGEX) and not good:
            if re.search(IS_FINE_REGEX[i], line):
                good = True
                break
            i += 1
        return good

    def looks_good(self, obj, elastic):
        proc = subprocess.Popen(["pahole", "-E", obj], stdout=subprocess.PIPE)
        comment_line = re.compile(COMMENT_LINE_REGEX)
        closing_line = re.compile(CLOSING_LINE_REGEX)
        empty_line = re.compile(EMPTY_LINE_REGEX)
        good = False
        last_member = None
        member = ''
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            line = str(line, "UTF-8")
            if comment_line.match(line):
                continue
            if closing_line.match(line):
                continue
            if empty_line.match(line):
                continue
            member = line
            if not good:
                good = self.check_member_is_fine(member)
            if not elastic and good:
                break

        if good and elastic and not re.search(IS_ELASTIC_REGEX, member):
            good = False
        return good

    def get_obj_for_slab(self, target, elastic, out):
        prv_size = SLABS[target-1]
        tgt_size = SLABS[target]
        fdr = open(self.objs_fname, "r", encoding="utf-8")
        fdw = None
        if out:
            fdw = open(out, "w", encoding="utf-8")

        while True:
            line = fdr.readline()
            if not line:
                break
            obj, size = re.findall("([_A-Za-z0-9]+)\t", line)
            size = int(size)
            if prv_size < size <= tgt_size:
                if self.looks_good(obj, False):
                    self.store_result(fdw, f"{obj}\n")
            elif size <= prv_size and elastic:
                if self.looks_good(obj, True):
                    self.store_result(fdw, f"{obj} [e]\n")

        fdr.close()
        if out:
            fdw.close()

    def get_obj_for_size(self, size, elastic, out_fname):
        found, idx = self.find_slab_idx(int(size))
        if not found:
            print(f"No slab exists for given size: {size} bytes")
            return -1
        self.get_obj_for_slab(idx, elastic, out_fname)

    def get_slab_for_size(self, size):
        found, idx = self.find_slab_idx(int(size))
        if not found:
            print(f"No slab exists for given size: {size} bytes")
            return -1
        return SLABS[idx]

class ObjScan():
    sc = None
    in_file = None

    def __init__(self, in_file):
        self.in_file = in_file
        self.sc = Scanner(in_file)

    def get_output_filename(self, size, elastic):
        slab = self.sc.get_slab_for_size(size)
        if elastic:
            out = f"objscan_elastic_kmalloc_{slab}"
        else:
            out = f"objscan_kmalloc_{slab}"
        if self.in_file:
            out = f"{out}_for_{self.in_file}.txt"
        else:
            out = f"{out}.txt"
        return out

    def get_obj_for_size(self, size, stdout, elastic):
        out = None
        if not stdout:
            out = self.get_output_filename(size, elastic)
        self.sc.get_obj_for_size(size, elastic, out)
        if out:
            print(f"Result in file {out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                    prog='objscan',
                    description='Looks for a suitable kernel object')
    parser.add_argument('-i', '--input', required=False,
                        help='Use the specified pahole output')
    parser.add_argument('-s', '--size', required=True,
                        help='Scan for objects of the the specified size')
    parser.add_argument('-e', '--elastic', required=False, action='store_true',
                        default=False, help='Scan for elastic objects')
    parser.add_argument('-o', "--stdout", required=False, action='store_true',
                        default=False, help='Write resul to the standard'
                        ' output')
    args = parser.parse_args()
    sc = ObjScan(args.input)
    sc.get_obj_for_size(args.size, args.stdout, args.elastic)
