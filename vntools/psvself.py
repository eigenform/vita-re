#!/usr/bin/python3
from hexdump import hexdump
from struct import pack, unpack

# Various {S}ELF structure sizes
SELF_HEADER_SIZE    = 0x78
ELF_HEADER_SIZE     = 0x34
APPINFO_SIZE        = 0x18

ELF_PH_SIZE         = 0x20

ELF_SH_SIZE         = 0x40
SELF_SEG_SIZE       = 0x20
SCEVERSION_SIZE     = 0x10
CONTROLINFO_SIZE    = 0x10

class SELF(object):
    """ Container for a SELF """
    def __init__(self, data):
        # Parse SELF header
        self.self_header = self_header(data[0x00:SELF_HEADER_SIZE])

        # Parse AppInfo struct
        appinfo_head = self.self_header.appinfo_off
        self.appinfo = appinfo(data[appinfo_head:appinfo_head+APPINFO_SIZE])

        # Parse ELF header
        elf_head = self.self_header.elf_off
        self.elf_header = elf_header(data[elf_head:elf_head + ELF_HEADER_SIZE])

        self.phdr = []
        phdr_head = self.self_header.phdr_off
        for i in range(0, self.elf_header.e_phnum):
            p = phdr(data[phdr_head:phdr_head+ELF_PH_SIZE])
            self.phdr.append(p)
            phdr_head += ELF_PH_SIZE

class ELF(object):
    """ Container for an ELF """
    def __init__(self, data):

        # Parse ELF header
        self.elf_header = elf_header(data[0x00:ELF_HEADER_SIZE])

        self.phdr = []
        phdr_head = self.elf_header.e_phoff
        for i in range(0, self.elf_header.e_phnum):
            p = phdr(data[phdr_head:phdr_head+ELF_PH_SIZE])
            self.phdr.append(p)
            phdr_head += ELF_PH_SIZE


class self_header(object):
    """ Representation of a SELF header """
    def __init__(self, data):
        self.magic = data[0x00:0x04]
        assert self.magic == b'SCE\x00'
        self.ver, self.sdk_type, self.hdr_type = unpack("<LHH", data[0x04:0x0C])
        self.metadata_off, self.header_len = unpack("<LQ", data[0x0c:0x18])
        self.elf_size, self.self_size = unpack("<QQ", data[0x18:0x28])
        self.self_off, self.appinfo_off = unpack("<QQ", data[0x30:0x40])
        self.elf_off, self.phdr_off = unpack("<QQ", data[0x40:0x50])
        self.shdr_off, self.section_info_off = unpack("<QQ", data[0x50:0x60])
        self.scever_off, self.ctrlinfo_off = unpack("<QQ", data[0x60:0x70])
        self.ctrlinfo_size = unpack("<Q", data[0x70:0x78])

class elf_header(object):
    """ Representation of an ELF header """
    def __init__(self, data):
        self.magic = data[0x00:0x04]
        self.e_type, self.e_machine = unpack("<HH", data[0x10:0x14])
        self.e_version, self.e_entry = unpack("<LL", data[0x14:0x1c])
        self.e_phoff, self.e_shoff = unpack("<LL", data[0x1c:0x24])
        self.e_flags = unpack("<L", data[0x24:0x28])
        self.e_ehsize, self.e_phentsize = unpack("<HH", data[0x28:0x2c])
        self.e_phnum, e_shentsize = unpack("<HH", data[0x2c:0x30])
        self.e_shnum, self.e_shstrndx = unpack("<HH", data[0x30:0x34])

class appinfo(object):
    """ Representation of the AppInfo struct """
    def __init__(self, data):
        self.auth_id, self.ven_id = unpack("<QL", data[0x00:0x0c])
        self.self_type, self.ver = unpack("<LQ", data[0x0c:0x18])

class phdr(object):
    def __init__(self, data):
        self.p_type, self.p_off = unpack("<LL", data[0x00:0x08])
        self.p_vaddr, self.p_paddr = unpack("<LL", data[0x08:0x10])
        self.p_filesz, self.p_memsz = unpack("<LL", data[0x10:0x18])
        self.p_flags, self.p_align = unpack("<LL", data[0x18:0x20])

