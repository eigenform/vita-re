#pragma once

#include "common.h"

// some info taken from the wiki, see http://vitadevwiki.com/index.php?title=SELF_File_Format

typedef struct __attribute__((packed)) 
{
	u32 magic;                 /* 53434500 = SCE\0 */
	u32 version;               /* header version 3*/
	u16 sdk_type;              /* */
	u16 header_type;           /* 1 self, 2 unknown, 3 pkg */
	u32 metadata_offset;       /* metadata offset */
	u64 header_len;            /* self header length */
	u64 elf_filesize;          /* ELF file length */
	u64 self_filesize;         /* SELF file length */
	u64 unknown;               /* UNKNOWN */
	u64 self_offset;           /* SELF offset */
	u64 appinfo_offset;        /* app info offset */
	u64 elf_offset;            /* ELF #1 offset */
	u64 phdr_offset;           /* program header offset */
	u64 shdr_offset;           /* section header offset */
	u64 section_info_offset;   /* section info offset */
	u64 sceversion_offset;     /* version offset */
	u64 controlinfo_offset;    /* control info offset */
	u64 controlinfo_size;      /* control info size */
	u64 padding;
} sce_header;

typedef struct __attribute__((packed))
{
	u64 authid;                /* auth id */
	u32 vendor_id;             /* vendor id */
	u32 self_type;             /* app type */
	u64 version;               /* app version */
	u64 padding;               /* UNKNOWN */
} sce_appinfo;

typedef struct __attribute__((packed))
{
	u32 unk1;
	u32 unk2;
	u32 unk3;
	u32 unk4;
} sce_version;

typedef struct __attribute__((packed))
{
	// 4==PSVita ELF digest info; 
	// 5==PSVita NPDRM info; 
	// 6==PSVita boot param info;
	// 7==PSVita shared secret info
	u32 type; 

	u32 size;
	u64 next; // 1 if another structure follows (otherwise, 0)

	union 
	{
		// type 4, 0x50 bytes
		struct  
		{
			// 0x40 bytes of data
			u8 constant[0x14]; 
			u8 elf_digest[0x20]; // SHA-256 of source ELF file
			u8 padding[8];
			u32 min_required_fw; // ex: 0x363 for 3.63
		} elf_digest_info;

		// type 5, 0x110 bytes
		struct
		{ 
			// 0x80 bytes of data
			u32 magic;               // 7F 44 52 4D (".DRM")
			u32 finalized_flag;      // ex: 80 00 00 01
			u32 drm_type;            // license_type ex: 2 local, 0XD free with license
			u32 padding;
			u8 content_id[0x30];
			u8 digest[0x10];         // ?sha-1 hash of debug self/sprx created using make_fself_npdrm?
			u8 padding_78[0x78];
			u8 hash_signature[0x38]; // unknown hash/signature
		} npdrm_info;


		// type 6, 0x110 bytes
		struct
		{ 
			// 0x100 bytes of data
			u32 is_used; // 0=false, 1=true
			u8 boot_param[0x9C]; // ex: starting with 02 00 00 00
		} boot_param_info;

		// type 7, 0x50 bytes
		struct
		{ 
			// 0x40 bytes of data
			u8 shared_secret_0[0x10];
			u8 shared_secret_1[0x10];
			u8 shared_secret_2[0x10];
			u8 shared_secret_3[0x10];
		} shared_secret_info;
	};
} control_info;

typedef struct __attribute__((packed))
{
	u64 offset;
	u64 length;
	u64 compression; // 1 = uncompressed, 2 = compressed
	u64 encryption;  // 1 = encrypted, 2 = plain
} segment_info;

