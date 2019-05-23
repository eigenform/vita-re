#!/usr/bin/python3
""" wa2recovr.py
Example usage:
```
    #!/usr/bin/python3
    from wa2recovr import *

    # Read an executable
    elf = binary(argv[1])

    # Extract entries
    entries = elf.walk_entries()

    for entry in entries:
        # Do something useful
        # ...
```
"""

from sys import argv
from struct import pack, unpack
from hexdump import hexdump
from zlib import decompress
from math import ceil
import hashlib

from vntools.psvself import *

def hdprint(desc, data):
    """ Wrapper around hexdump output """
    print("{}".format(desc))
    for line in hexdump(data, result='generator'):
        print("    {}".format(line))


""" ---------------------------------------------------------------------------
Containers for objects
"""

class binary(object):
    """ Simple container/parser for the binary. Takes some filename of a SELF,
    and 'table_off', an offset to some array of entries in the binary. """
    def __init__(self, filename, table_off):
        self.filename = filename

        self.table_base_off = table_off
        self.entries = []

        # Read an ELF file into memory
        with open(filename, "rb") as f: 
            self.data = f.read()

        # Parse ELF header
        self.elf = ELF(self.data)
        self.t_addr   = self.elf.phdr[0].p_vaddr
        self.t_len    = self.elf.phdr[0].p_filesz
        self.t_off    = self.elf.phdr[0].p_off
        self.d_addr   = self.elf.phdr[1].p_vaddr
        self.d_len    = self.elf.phdr[1].p_filesz
        self.d_off    = self.elf.phdr[1].p_off

        m = hashlib.sha256()
        m.update(self.data)
        self.sha256 = m.hexdigest()

    def _v_to_off(self, vaddr):
        """ Translate a virtual address into a file offset """
        if ((vaddr >= self.t_addr) and (vaddr < (self.t_addr + self.t_len))):
            return (self.t_off + (vaddr - self.t_addr))
        if ((vaddr >= (self.t_addr + self.t_len)) and (vaddr < self.d_addr)):
            raise Exception("There's no mapping for this virtual address")
        if ((vaddr >= self.d_addr) and (vaddr < (self.d_addr + self.d_len))):
            return ((vaddr - self.t_addr) - 0x500)
        if (vaddr >= (self.d_addr + self.d_len)):
            raise Exception("There's no mapping for this virtual address")

    def _off_to_v(self, offset): 
        """ Translate a file offset into a virtual address """
        if (offset < self.t_off):
            raise Exception("There's no virtual address for this offset")
        if ((offset >= self.t_off) and (offset < self.d_off)):
            return ((self.t_addr + offset) - self.t_off) 
        if ((offset >= self.d_off) and (offset < 0x0044d090)):
            return ((self.t_addr + offset) + 0x500) 
        if (offset >= (self.d_off + self.d_len)):
            raise Exception("There's no virtual address for this offset")

    def _recover_string(self, vaddr):
        """ Given some virtual address, recover a string """
        cur = self._v_to_off(vaddr)
        name = bytearray()
        while True:
            char = unpack("<1s", self.data[cur:cur+1])[0]
            if (char == b'\x00'):
                break
            name += char
            cur += 1
        return name.decode('utf8')

    def _recover_file(self, size, lzsize, vaddr, filename):
        """ Inflate the data at the given virtual address """
        cur = self._v_to_off(vaddr)
        blk_data = bytearray()
        while True:

            # Terminate when we've reached the target file size
            if ((len(blk_data) >= size)):
                break

            # Read the header for this block
            blk_size, blk_lzsize = unpack("<II", self.data[cur:cur+0x08])

            # Decompress this block of data
            blk_data += decompress(self.data[cur+0x10:cur+0x10+blk_lzsize])

            # Move to the next block
            blk_lzsize_aligned = (ceil(blk_lzsize / 0x10) * 0x10) + 0x10
            cur += blk_lzsize_aligned

        return blk_data

    def walk_entries(self):
        """ Given an offset, extract and return an array of all files """
        cur = self.table_base_off
        while True:

            # The array of entries terminates with a null entry
            saddr, daddr, size, lzsize = unpack("<4I", self.data[cur:cur+0x10])
            if ((saddr == 0) and (daddr == 0) and (size == 0) and (lzsize == 0)):
                break

            # Recover the filename for this entry
            filename = self._recover_string(saddr)
            filename = filename.replace("_", ".")

            # Decompress the data for this entry
            entry_data = self._recover_file(size, lzsize, daddr, filename)

            # Append the entry to our list, then move to the next entry
            entry = file_entry(filename, entry_data, saddr, daddr, size, lzsize)
            self.entries.append(entry)
            cur += 0x10

        return self.entries


class file_entry(object):
    """ Simple container for uncompressed file entries """
    def __init__(self, filename, data, saddr, daddr, size, lzsize):
        self.filename = filename
        self.data = data
        self.saddr = saddr
        self.daddr = daddr
        self.size = size
        self.lzsize = lzsize

        m = hashlib.sha256()
        m.update(self.data)
        self.sha256 = m.hexdigest()

    def write(self, path):
        """ Write the file to some folder """
        with open("{}/{}".format(path, self.filename), "wb") as f:
            f.write(self.data)

    def print_info(self):
        print("Filename: {}".format(self.filename))
        print("  String address:   {:08x}".format(self.saddr))
        print("  Data address:     {:08x}".format(self.daddr))
        print("  File size:        {:08x}".format(self.size))
        print("  Compressed size:  {:08x}".format(self.lzsize))

