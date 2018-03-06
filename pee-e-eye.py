#! /usr/bin/python

# pee-e-eye.py

# this script allows the user to perform a quick examination of a portable executable file for an initial basic static analysis.

# worzel_gummudge

import sys
import pefile
import peutils
import getopt
import string

peFile = ""
dumpImports = False
dumpExports = False
dumpSectionNames = False
identify = False
resourceStrings = False
strings = False

# this functon displays the program's usage
def usage():
    print "pee-e-eye 1.0"
    print
    print "usage: ./pee-e-eye.py pefile option"
    print "-p --peFile              - portable executable under examination"
    print "-i --dumpImports         - dumps the import table"
    print "-e --dumpExports         - dumps the export table"
    print "-s --dumpSectionNames    - dumps the executable's section names"
    print "-n --identify            - identifies the portable executable signature"
    print "-r --resourceStrings     - extracts strings from the resource section"
    print "-t --strings             - prints out strings"
    print "-h --help                - prints this usage message"
    print "example: ./pee-e-eye.py -p '/root/Desktop/malsamples/#ETUP.EXE' -i"
    sys.exit(0)

def main():
    global peFile
    global dumpImports
    global dumpExports
    global dumpSectionNames
    global identify
    global resourceStrings
    global strings
    global pe

    if not len(sys.argv[1:]):
        usage()
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hp:iesnrt", ["help", "peFile", "dumpImports", "dumpExports", "dumpSectionNames", "identify", "resourceStrings", "strings"])
    except getopt.GetoptError as err:
        print str(err)
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-p", "--pe_file"):
            peFile = a
        elif o in ("-i", "--dump_imports"):
            dumpImports = True
        elif o in ("-e", "--dump_exports"):
            dumpExports = True
        elif o in ("-s", "--dumpSectionNames"):
            dumpSectionNames = True
        elif o in ("-n", "--identify"):
            identify = True
        elif o in ("-r", "--resourceStrings"):
            resourceStrings = True
        elif o in ("-t", "--strings"):
            strings = True
        else:
            assert False, "Unhandled Option"

    try:
        pe = pefile.PE(peFile)
    except OSError as exception:
        print "[!]Error: File does not exist"
        sys.exit(0)
    except PEFormatError as exception:
        print "[!]Error: Not PE file"
        sys.exit(0)

    if len(peFile) and dumpImports > 0:
        dImports()
        sys.exit(1)
    if len(peFile) and dumpExports > 0:
        dExports()
        sys.exit(1)
    if len(peFile) and dumpSectionNames > 0:
        dSectionNames()
        sys.exit(1)
    if len(peFile) and identify > 0:
        idPacker()
        sys.exit(1)
    if len(peFile) and resourceStrings > 0:
        rStrings()
        sys.exit(1)
    if len(peFile) and strings > 0:
        for s in strngs(peFile):
            print s
        sys.exit(1)

# this function dumps the file imports
def dImports():
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print '[+]', entry.dll
            for imp in entry.imports:
                print '\t', hex(imp.address), imp.name
    except:
        print "[!] The Portable Executable has no Imports"

# this function dumps the files's exports
def dExports():
    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print '[+]', hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal
    except:
        print "[!] The Portable Executable has no Exports"

# this function dumps the file's section names
def dSectionNames():
    try:
        for section in pe.sections:
            print '[+]', section.Name, section.VirtualAddress, section.SizeOfRawData
    except:
        print "[!] Error: No Sections Found"

# this function identifies packers/ encoders used on the pe file
def idPacker():
    try:
        signatures = peutils.SignatureDatabase('/root/Desktop/projects/userdb.txt')
        matches = signatures.match(pe, ep_only = True)
        if len(matches) == 0:
            print "[!] No matches found"
        print '[+] The Portable Executable File matches the following signatures:'
        for match in matches:
            print '\t', match
    except:
        raise

# this funtion dumps resource strings
def rStrings():
    try:
        resStrings = list()
        rt_string_idx = [
                entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_STRING'])
        rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
        for entry in rt_string_directory.directory.entries:
            data_rva = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            print '[+] Direectory entry at RVA', hex(data_rva), 'of size', hex(size)
            data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
            offset = 0
            while True:
                if offset >= size:
                    break
                ustr_length = pe.get_word_from_data(data[offset:offset+2], 0)
                offset += 2
                if ustr_length == 0:
                    continue
                ustr = pe.get_string_u_at_rva(data_rva+offset, max_length = ustr_length)
                offset += ustr_length*2
                resStrings.append(ustr)
                print '[+]', resStrings
    except ValueError as exception:
        print "[!] No Strings found in Resources Section"
    except AttributeError as exception:
        print "[!] The PE file has no Resource Section"

# this function dumps strings found in the pe file
def strngs(filename, min=4):
    with open(filename, "rb") as f:
        result = ""
        for c in f.read():
            if c in string.ascii_letters:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:
            yield result

main()
