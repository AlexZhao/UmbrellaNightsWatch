#!/usr/bin/python
# Copyright Alex Zhao
# Python Script used to Scanning on disk executable/linkable shared object on linux system
# Basic Virus/Malware/Binary Inject Scanner
# Based on screwdriver static compiled binutils
# [+]
# [-]

import sys;

if __name__ == '__main__':
    scan_directory = "./"

    if sys.argv[1]:
        scan_direcotry = sys.argv[1]

    # 1st Check readelf/objdump/... toolset is static linked
    

    # 2nd Check elf injection for executable 

    # 3rd Check dynamic lib injection with dlopen/dlsym/dlclose to check dyn loading

