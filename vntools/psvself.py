#!/usr/bin/python3
from hexdump import hexdump
from struct import pack, unpack
from zlib import decompress

# Various {S}ELF structure sizes
SELF_HEADER_SIZE    = 0x78
ELF_HEADER_SIZE     = 0x34
APPINFO_SIZE        = 0x18

ELF_PH_SIZE         = 0x20
ELF_SH_SIZE         = 0x40
SELF_SEG_SIZE       = 0x20
SCEVERSION_SIZE     = 0x10
CONTROLINFO_SIZE    = 0x10
SECTION_INFO_SIZE   = 0x20

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
        print(hex(elf_head))

        self.phdr = []
        phdr_head = self.self_header.phdr_off
        for i in range(0, self.elf_header.e_phnum):
            p = phdr(data[phdr_head:phdr_head+ELF_PH_SIZE])
            self.phdr.append(p)
            phdr_head += ELF_PH_SIZE

        self.section_info = []
        for i in range(0, self.elf_header.e_phnum):
            base = self.self_header.section_info_off + (i * SECTION_INFO_SIZE)
            tail = base + SECTION_INFO_SIZE
            section_data = data[base:tail]
            s = section_info(section_data)
            self.section_info.append(s)

    def get_info(self):
        print("---------- SELF Header")
        self.self_header.get_info()
        print("---------- ELF Header")
        self.elf_header.get_info()
        for i, phdr in enumerate(self.phdr):
            print("---------- PHDR {}".format(i))
            phdr.get_info()
        for i, section in enumerate(self.section_info):
            print("---------- Section {}".format(i))
            section.get_info()

class ELF(object):
    """ Container for an ELF """
    def __init__(self, data):
        # Parse ELF header
        self.elf_header = elf_header(data[0x00:ELF_HEADER_SIZE])

        # Keep self.orig_phdr around for reference when necessary.
        # You need to create two seperate objects for this.

        self.orig_phdr = []
        self.phdr = []

        phdr_head = self.elf_header.e_phoff
        for i in range(0, self.elf_header.e_phnum):
            mutable_p = phdr(data[phdr_head:phdr_head+ELF_PH_SIZE])
            saved_p = phdr(data[phdr_head:phdr_head+ELF_PH_SIZE])
            self.phdr.append(mutable_p)
            self.orig_phdr.append(saved_p)
            phdr_head += ELF_PH_SIZE

        # Save a copy of the original phdrs

    def read(self):
        """ Read the bytearray() representation of the ELF headers at some instant"""
        header_data = self.elf_header.read()
        phdr_data = bytearray()
        for phdr in self.phdr:
            phdr_data += phdr.read()
        return header_data + phdr_data

class elf_header(object):
    """ Representation of an ELF header """
    def __init__(self, data):
        self.data = data
        self.magic = data[0x00:0x04]
        self.type = data[0x04:0x10]
        self.e_type, self.e_machine = unpack("<HH", data[0x10:0x14])
        self.e_version, self.e_entry = unpack("<LL", data[0x14:0x1c])
        self.e_phoff, self.e_shoff = unpack("<LL", data[0x1c:0x24])
        self.e_flags = unpack("<L", data[0x24:0x28])[0]
        self.e_ehsize, self.e_phentsize = unpack("<HH", data[0x28:0x2c])
        self.e_phnum, self.e_shentsize = unpack("<HH", data[0x2c:0x30])
        self.e_shnum, self.e_shstrndx = unpack("<HH", data[0x30:0x34])

    def read(self):
        data = bytearray()
        data += self.magic
        data += self.type
        data += pack("<HH", self.e_type, self.e_machine)
        data += pack("<LL", self.e_version, self.e_entry)
        data += pack("<LL", self.e_phoff, self.e_shoff)
        data += pack("<L", self.e_flags)
        data += pack("<HH", self.e_ehsize, self.e_phentsize)
        data += pack("<HH", self.e_phnum, self.e_shentsize)
        data += pack("<HH", self.e_shnum, self.e_shstrndx)
        assert len(data) == 0x34
        return data

    def get_info(self):
        print("Entrypoint: {:08x}".format(self.e_entry))
        print("PHDR off: {:08x}".format(self.e_phoff))
        print("SHDR off: {:08x}".format(self.e_shoff))
        print("PHDR num: {:08x}".format(self.e_phnum))
        print("SHDR num: {:08x}".format(self.e_shnum))

class phdr(object):
    def __init__(self, data):
        self.p_type, self.p_off = unpack("<LL", data[0x00:0x08])
        self.p_vaddr, self.p_paddr = unpack("<LL", data[0x08:0x10])
        self.p_filesz, self.p_memsz = unpack("<LL", data[0x10:0x18])
        self.p_flags, self.p_align = unpack("<LL", data[0x18:0x20])

    def read(self, data):
        """ Write back to the bytearray() representation """
        data = bytearray()
        data += pack("<LL", self.p_type, self.p_off)
        data += pack("<LL", self.p_vaddr, self.p_paddr)
        data += pack("<LL", self.p_filesz, self.p_memsz)
        data += pack("<LL", self.p_flags, self.p_align)
        assert len(data) == 0x20
        return data

    def get_info(self):
        print("Offset: {:08x}".format(self.p_off))
        print("vaddr: {:08x}".format(self.p_vaddr))
        print("filesz: {:08x}".format(self.p_filesz))
        print("memsz: {:08x}".format(self.p_memsz))


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
        self.ctrlinfo_size = unpack("<Q", data[0x70:0x78])[0]

    def get_info(self):
        print("Metadata offset: {:08x}".format(self.metadata_off))
        print("ELF offset: {:08x}".format(self.elf_off))
        print("ELF size: {:08x}".format(self.elf_size))
        print("SELF size: {:08x}".format(self.self_size))
        print("PHDR offset: {:08x}".format(self.phdr_off))
        print("AppInfo offset: {:08x}".format(self.appinfo_off))
        print("SectionInfo offset: {:08x}".format(self.section_info_off))
        print("ControlInfo offset: {:08x}".format(self.ctrlinfo_off))
        print("ControlInfo size: {:08x}".format(self.ctrlinfo_size))

class appinfo(object):
    """ Representation of the AppInfo struct """
    def __init__(self, data):
        self.auth_id, self.ven_id = unpack("<QL", data[0x00:0x0c])
        self.self_type, self.ver = unpack("<LQ", data[0x0c:0x18])

class section_info(object):
    """ Section info structure """
    def __init__(self, data):
        self.data = data
        self.off = unpack("<Q", data[0x00:0x08])[0]
        self.len = unpack("<Q", data[0x08:0x10])[0]

        # 1=uncompressed, 2=compressed
        self.compressed = unpack("<Q", data[0x10:0x18])[0] 

        # 1=encrypted, 2=plaintext
        self.encrypted = unpack("<Q", data[0x18:0x20])[0]  

    def get_info(self):
        print("Offset: {:08x}".format(self.off))
        print("Size: {:08x}".format(self.len))
        print("compressed: {:08x}".format(self.compressed))
        print("encrypted: {:08x}".format(self.encrypted))
