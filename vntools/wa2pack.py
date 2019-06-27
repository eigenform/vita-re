#!/usr/bin/python3
""" wa2pack.py
"""

from .psvself import *

from sys import argv
from struct import pack, unpack
from hexdump import hexdump
from zlib import decompress, compress
from math import ceil


class binary(object):
    """ 
    Container for a binary [executable].
    """
    def __init__(self, filename, table_off):
        """ Constructor for this object - reads the provided file into memory
        and does some initial book-keeping. Takes 'table_off', a file offset
        to the base of the array of compressed file entries. """
        self.filename = filename
        self.entry_table_offset = table_off

        # Read an ELF file into memory
        with open(filename, "rb") as f: 
            self.data = bytearray(f.read())

        self.elf    = ELF(self.data)

        #assert self.v2off(0x81000000) == 0x000000c0
        #assert self.v2off(0x81079000) == 0x00078b00
        #assert self.v2off(0x00000000) == 0x0044d090
        #assert self.off2v(0x000000c0) == 0x81000000
        #assert self.off2v(0x00078b00) == 0x81079000
        #assert self.off2v(0x0044d090) == 0x00000000
        #exit()

        print("[*] Read {} ({}) bytes".format(filename, hex(len(self.data))))

        # Read the entry table in the binary. This will create our initial
        # representation of all compressed data, decompressed data, etc.
        self._read_entry_table()


    # -------------------------------------------------------------------------
    # Helper functions

    def v2off(self, vaddr):
        """ Map a virtual address into an offset """
        for phdr in self.elf.phdr:
            base = phdr.p_vaddr
            tail = phdr.p_vaddr + phdr.p_filesz
            if ((vaddr >= base) and (vaddr <= tail)):
                return phdr.p_off + (vaddr - phdr.p_vaddr)
        raise Exception("Couldn't map vaddr {:08x}".format(vaddr))

    def off2v(self, offset):
        """ Map an offset into a virtual address """
        for phdr in self.elf.phdr:
            base = phdr.p_off
            tail = phdr.p_off + phdr.p_filesz
            if ((offset >= base) and (offset <= tail)):
                return phdr.p_vaddr + (offset - phdr.p_off)
        raise Exception("Couldn't map offset {:08x}".format(offset))

    def _recover_string(self, vaddr):
        """ Given some virtual address, recover a string from the binary """
        cur = self.v2off(vaddr)
        name = bytearray()
        while True:
            char = unpack("<1s", self.data[cur:cur+1])[0]
            if (char == b'\x00'):
                break
            name += char
            cur += 1
        return name.decode('utf8')

    # -------------------------------------------------------------------------
    # Entry table operations

    def _read_entry_table(self, decompress=False):
        """ Read the binary and update and return our own representation of 
        the current entry table (an array of entry() objects). 

        A particular entry table is always related to a particulr block of 
        compressed data in the binary (and therefore, always related to the
        decompressed output). If there are any errors downstream in obtaining
        compressed data or decompressed data, consider this entry invalid.
        """
        cur = self.entry_table_offset
        self.entry_table = []
        while True:
            # Read an entry from the binary
            header_vaddr = self.off2v(cur)
            header_data = self.data[cur:cur+0x10]
            saddr, daddr, size, lzsize = unpack("<4I", header_data)

            # The array terminates on a null entry
            if ((saddr == 0) and (daddr == 0)): break

            # Get the filename associated with this entry
            filename = self._recover_string(saddr)
            filename = filename.replace("_", ".")

            # Get the compressed data associated with this entry
            lzdata = self._read_lzdata(daddr, lzsize)
            assert len(lzdata) == lzsize

            # Get the decompressed data associated with this entry
            raw_data = self._decompress_lzdata(lzdata, lzsize, size)
            assert len(raw_data) == size

            # Create the entry, then go to the next one in the array
            e = entry(header_data, header_vaddr, saddr, daddr, size, lzsize, 
                        filename, lzdata, raw_data)
            self.entry_table.append(e)
            cur += 0x10

        return self.entry_table

    def recompress_entry_table(self):
        """ Iterate through all raw files in the entry table and re-build the
        compressed data for each file. If an entry is marked as dirty, rewrite
        the compressed data and compressed length fields in the object """
        for e in self.entry_table:
            assert e.size == len(e.raw_data)

            # Setup some state for the compressor
            remaining = len(e.raw_data)
            num_blocks = len(e.raw_data) // 0x10000
            if (len(e.raw_data) > (num_blocks * 0x10000)):
                num_blocks += 1
            cur = 0

            # Build the new compressed data block-by-block
            new_lz_data = bytearray()
            for i in range(0, num_blocks):
                if (remaining >= 0x10000):
                    size = 0x10000
                    raw_blkdata = e.raw_data[cur:cur+size]
                    lz_blkdata = compress(raw_blkdata)
                    cur = cur + size
                    remaining = remaining - size
                else:
                    size = remaining
                    raw_blkdata = e.raw_data[cur:cur+remaining]
                    lz_blkdata = compress(raw_blkdata)
                    cur = cur + remaining
                    remaining = remaining - remaining

                # Build a new header for this block
                header_data = pack("<LL", size, len(lz_blkdata))
                header_data += b'\x00' * 0x08
                assert len(header_data) == 0x10

                # Prepend a new header to the block
                lz_blkdata = header_data + lz_blkdata

                # Pad this block to 0x10-byte boundaries
                blk_lzsize_aligned = (ceil(len(lz_blkdata) / 0x10) * 0x10)
                lz_blkdata += b'\x00' * (blk_lzsize_aligned - len(lz_blkdata))
                assert len(lz_blkdata) == blk_lzsize_aligned

                # Append this block to the new compressed data
                new_lz_data += lz_blkdata

            assert cur == len(e.raw_data)
            assert remaining == 0

            # If this entry isn't marked dirty, just do nothing?
            if (e.dirty == False):
                assert new_lz_data == e.lz_data

            # If the entry is marked as dirty, update some of the fields
            else:
                assert new_lz_data != e.lz_data
                print("Rebuilt entry for '{}'".format(e.filename))
                print("old_lzsize={:08x}, new_lzsize={:08x}".format(e.lzsize,
                    len(new_lz_data)))

                e.lz_data = new_lz_data
                e.lzsize = len(new_lz_data)
       
    def rebuild_entry_table(self, dirty_base_vaddr):
        """ Iterate over all entries and potentially re-compute the 'daddr'. 
        For clean entries, make no changes to the entry. Use virtual address
        'base_vaddr' as the start of a new region of contiguous compressed
        data (the destination for all dirty entries). I assume that we can
        leave the saddr fields untouched for all entries. """ 

        new_daddr = dirty_base_vaddr
        for e in self.entry_table:
            # Make no changes for unmodified entries
            if (e.dirty == False):
                continue
            else:
                print("Fixing daddr for '{}' [{:08x} -> {:08x}]".format(
                    e.filename, e.daddr, new_daddr))
                e.daddr = new_daddr
                new_daddr += e.lzsize

    def write_entry_metadata(self):
        """ Write all entry fields back to the underlying data """
        cur = self.entry_table_offset
        for e in self.entry_table:
            header_data = pack("<4I", e.saddr, e.daddr, e.size, e.lzsize)
            self.data[cur+0x00:cur+0x10] = header_data
            cur += 0x10

    def rebuild_elf_headers(self):
        data = bytearray()
        data += self.elf.elf_header.magic
        data += self.elf.elf_header.type

        data += pack("<HH", self.elf.elf_header.e_type, 
                self.elf.elf_header.e_machine)
        data += pack("<LL", self.elf.elf_header.e_version, 
                self.elf.elf_header.e_entry)
        data += pack("<LL", self.elf.elf_header.e_phoff, 
                self.elf.elf_header.e_shoff)

        data += pack("<L", self.elf.elf_header.e_flags)

        data += pack("<HH", self.elf.elf_header.e_ehsize, 
                self.elf.elf_header.e_phentsize)
        data += pack("<HH", self.elf.elf_header.e_phnum, 
                self.elf.elf_header.e_shentsize)
        data += pack("<HH", self.elf.elf_header.e_shnum, 
                self.elf.elf_header.e_shstrndx)

        for phdr in self.elf.phdr:
            data += pack("<LL", phdr.p_type, phdr.p_off)
            data += pack("<LL", phdr.p_vaddr, phdr.p_paddr)
            data += pack("<LL", phdr.p_filesz, phdr.p_memsz)
            data += pack("<LL", phdr.p_flags, phdr.p_align)

        data += b'\x00' * (self.elf.phdr[0].p_off - len(data))
        assert len(data) == self.elf.phdr[0].p_off
        self.data[0x00:self.elf.phdr[0].p_off] = data



    # -------------------------------------------------------------------------
    # Compressed data (note everything is aligned to 0x10-byte boundaries)

    def _read_lzdata(self, daddr, lzsize):
        """ Given a base address and size, read a compressed file and return
        a bytearray() containing all of the compressed data """
        cur = self.v2off(daddr)
        lzdata = bytearray()
        while True:
            if (len(lzdata) >= lzsize): break
            blk_size, blk_lzsize = unpack("<II", self.data[cur:cur+0x08])
            blk_lzsize_aligned = (ceil(blk_lzsize / 0x10) * 0x10) + 0x10
            lzdata += self.data[cur:cur+blk_lzsize_aligned]
            cur += blk_lzsize_aligned
        assert len(lzdata) == lzsize
        return lzdata

    def _decompress_lzdata(self, lzdata, lzsize, size):
        """ Given some lzdata, the size of the compressed data, and the size 
        of the raw file, decompress the lzdata, yielding the raw file data """
        assert len(lzdata) == lzsize
        cur = 0x0
        data = bytearray()
        while True:
            if (len(data) >= size): break
            blk_size, blk_lzsize = unpack("<II", lzdata[cur:cur+0x08])
            blk_lzsize_aligned = (ceil(blk_lzsize / 0x10) * 0x10) + 0x10
            blk_lzdata = lzdata[cur+0x10:cur+0x10+blk_lzsize]
            assert len(blk_lzdata) == blk_lzsize 

            blk_data = decompress(blk_lzdata)
            data += blk_data
            cur += blk_lzsize_aligned
        assert len(data) == size
        return data


# -----------------------------------------------------------------------------
class dstring(object):
    """ Container for an individual string """
    def __init__(self, data):
        self.data = data
        self.string = self.data.decode("shift_jis_2004")

    def read(self):
        """ Use the current bytearray() to update the str() representation """
        self.string = self.data.decode("shift_jis_2004")
        return self.string

    def write(self, new_string):
        """ Given a new string, encode it into a new bytearray(), refresh our
        decoded representation, then return the updated string """
        self.data = new_string.encode("shift_jis_2004")
        return self.read()


# -----------------------------------------------------------------------------
class entry(object):
    """ Container for a file entry. These may be modified by the user, so we
    need some way of (a) telling if they're dirty, and (b) rebuilding the
    entire set of associated objects when they're changed """
    def __init__(self, header_data, header_vaddr, saddr, daddr, size, lzsize, 
            filename, lz_data, raw_data):
        assert len(lz_data) == lzsize
        assert len(raw_data) == size

        self.header_data = header_data
        self.header_vaddr = header_vaddr

        self.saddr = saddr
        self.daddr = daddr
        self.size = size
        self.lzsize = lzsize

        self.filename = filename
        self.lz_data = lz_data
        self.raw_data = raw_data

        self.dirty = False
        self.next = None

        self.read_strings()

    def read_strings(self):
        """ Use the raw_data bytearray() contents to update and return some
        array of all dstring() objects. As far as I can tell, some individual 
        string terminates on \x2c bytes (these are independent of the newline 
        characters within a string) """
        self.dstrings = []
        if ("txt" not in self.filename): return self.dstrings
        base = 0
        cur = 0
        while True:
            if ((cur >= len(self.raw_data)) or (base >= len(self.raw_data))):
                break
            while True:
                if (cur >= len(self.raw_data)): break
                if (self.raw_data[cur:cur+1] == b'\x2c'):
                    cur += 1
                    break
                cur += 1
            s = dstring(self.raw_data[base:cur])
            self.dstrings.append(s)
            base = cur
        return self.dstrings

    def write_strings(self, dstrings):
        """ Given an array of dstring() objects 'dstrings': rewrite the binary
        contents of the file, update our internal dstring() representation,
        then return the latest array of dstring() objects. """
        if ("txt" not in self.filename): return None

        # Build the new binary data
        old_data = self.raw_data
        self.raw_data = bytearray()
        for string in dstrings:
            self.raw_data += string.data

        # Recompute the size of the raw file and mark the entry as dirty
        if (self.raw_data != old_data):
            self.size = len(self.raw_data)
            self.dirty = True

        return self.read_strings()

