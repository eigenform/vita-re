#!/usr/bin/python3
""" wa2pack.py
"""

from vntools.psvself import *

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
            self.data = f.read()

        print("[*] Read {} ({}) bytes".format(filename, hex(len(self.data))))

        # First, parse the ELF headers 
        self._parse_headers()

        # Read the entry table in the binary. This will create our initial
        # representation of all compressed data, decompressed data, etc.
        self._read_entry_table()


    # -------------------------------------------------------------------------
    # Helper functions

    def _parse_headers(self):
        """ Update our representation of the ELF headers """ 
        self.elf    = ELF(self.data)

        self.t_addr = self.elf.phdr[0].p_vaddr
        self.t_len  = self.elf.phdr[0].p_filesz
        self.t_off  = self.elf.phdr[0].p_off
        self.d_addr = self.elf.phdr[1].p_vaddr
        self.d_len  = self.elf.phdr[1].p_filesz
        self.d_off  = self.elf.phdr[1].p_off

    def _v_to_off(self, vaddr):
        """ Translate a virtual address into a file offset.
        Fix these later to actually use underlying phdr data. """
        if ((vaddr >= self.t_addr) and (vaddr < (self.t_addr + self.t_len))):
            return (self.t_off + (vaddr - self.t_addr))
        if ((vaddr >= (self.t_addr + self.t_len)) and (vaddr < self.d_addr)):
            raise Exception("There's no mapping for this virtual address")
        if ((vaddr >= self.d_addr) and (vaddr < (self.d_addr + self.d_len))):
            return ((vaddr - self.t_addr) - 0x500)
        if (vaddr >= (self.d_addr + self.d_len)):
            raise Exception("There's no mapping for this virtual address")

    def _off_to_v(self, offset): 
        """ Translate a file offset into a virtual address.
        Fix these later to actually use underlying phdr data. """
        if (offset < self.t_off):
            raise Exception("There's no virtual address for this offset")
        if ((offset >= self.t_off) and (offset < self.d_off)):
            return ((self.t_addr + offset) - self.t_off) 
        if ((offset >= self.d_off) and (offset < 0x0044d090)):
            return ((self.t_addr + offset) + 0x500) 
        if (offset >= (self.d_off + self.d_len)):
            raise Exception("There's no virtual address for this offset")

    def _recover_string(self, vaddr):
        """ Given some virtual address, recover a string from the binary """
        cur = self._v_to_off(vaddr)
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

    def _read_entry_table(self):
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
            header_vaddr = self._off_to_v(cur)
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

    def rebuild_entry_table(self):
        """ Iterate through entries and check if they're dirty. If so, rebuild
        the compressed data and fix the sizes associated with this entry. """
        for e in self.entry_table:
            assert e.size == len(e.raw_data)

            print("Rebuilding entry for '{}'".format(e.filename))

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

            # If this block isn't dirty, just do nothing?
            if (e.dirty == False):
                assert new_lz_data == e.lz_data

            # Otherwise, fix up the entry fields that we know about
            else:
                if (new_lz_data != e.lz_data):
                    print("Compressed data changed!")
                    e.lz_data = new_lz_data
                    e.lzsize = len(new_lz_data)
                    e.daddr = None
           


    def write_entry_table(self, entry_table):
        """ Given an array of entry() objects, write them back to underlying
        binary data. After writing, re-update our internal representation and 
        return the new array of entry() objects. """
        assert len(entry_table) == len(self.entry_table)
        cur = self.entry_table_offset
        for e in entry_table:
            header_data = pack("<4I", e.saddr, e.daddr, e.size, e.lzsize)
            self.data[cur+0x00:cur+0x10] = header_data
        return self._read_entry_table()

    # -------------------------------------------------------------------------
    # Compressed data (note everything is aligned to 0x10-byte boundaries)

    def _read_lzdata(self, daddr, lzsize):
        """ Given a base address and size, read a compressed file and return
        a bytearray() containing all of the compressed data """
        cur = self._v_to_off(daddr)
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
    def __init__(self, header_data, header_vaddr, saddr, daddr, size, lzsize, filename, lz_data, raw_data):
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
            if ((cur >= len(self.raw_data)) or (base >= len(self.raw_data))): break
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

        if (self.raw_data != old_data):
            # Recompute the size of the raw file
            self.size = len(self.raw_data)

            # Mark the entry as dirty (we need to re-create compressed data)
            #self.lz_data = bytearray()
            #self.daddr = None
            self.dirty = True

        return self.read_strings()

