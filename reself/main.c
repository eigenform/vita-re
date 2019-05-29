/* reself - "pack ELF back into SELF"
 *
 * Derived heavily from `vita-inject-elf`, see here:
 *
 *	https://github.com/CelesteBlue-dev/PSVita-RE-tools/
 */


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <zlib.h>

#include "common.h"
#include "self.h"
#include "elf.h"
#include "sha256.h"

#define LZ_BUF_LEN		0x02000000	// Buffer geometry for zlib
#define SHA256_DIGEST_LEN	0x20		// Size of a SHA256 hash
#define METADATA_PAD_LEN	0x30		// Padding before metadata
#define MAX_SEGMENTS		0x20		// Only support N segments

u8 elf_digest[SHA256_DIGEST_LEN];		// SHA256 digest buffer
u8 *lzdata_buf;					// zlib compression buffer
u8 *self_file, *elf_file;			// User input buffers
size_t self_len, elf_len;			// Size of user input
u8 *seg_lzdata[MAX_SEGMENTS] = { NULL };	// Compressed segment buffers


// Get the size of some file
size_t get_filesize(const char *filename)
{
	FILE *fp = fopen(filename, "rb");
	fseek(fp, 0, SEEK_SET);
	fseek(fp, 0, SEEK_END);
	size_t sz = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	fclose(fp);
	return sz;
}

// Read 'len' bytes from a file into memory, returning a pointer to the data
u8 *read_file(const char *filename, size_t len)
{
	FILE *fp = fopen(filename, "rb");
	u8 *buf = calloc(1, len);
	fread(buf, len, 1, fp);
	fclose(fp);
	return buf;
}

// Given 'dst', 'src', and some size 'src_len', compress the provided data and
// return the size of resulting compressed data in 'dst'
size_t compress_segment(void *dst, void *src, size_t src_len)
{
	int res;
	size_t dst_len = LZ_BUF_LEN;
	memset(lzdata_buf, 0, LZ_BUF_LEN);
	res = compress(dst, &dst_len, src, src_len);
	if (res != Z_OK)
	{
		fprintf(stderr, "zlib compress() returned %d for phdr\n", res);
		exit(-1);
	}
	return dst_len;
}

// Given some buffer 'src' and a size 'len, write a SHA256 digest to 'dst'
void sha256_digest(void *dst, size_t len, void *src)
{
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, src, len);
	sha256_final(&ctx, dst);
}



int main(int argc, const char **argv)
{
	if (argc != 4) 
	{
		fprintf(stdout, "usage: %s ", argv[0]);
		fprintf(stdout, "<input SELF> <input ELF> <output SELF>\n");
		exit(0);
	}

	lzdata_buf		= (u8*)calloc(1, LZ_BUF_LEN);

	self_len		= get_filesize(argv[1]);
	elf_len			= get_filesize(argv[2]);
	self_file		= read_file(argv[1], self_len);
	elf_file		= read_file(argv[2], elf_len);

	sce_header *shdr	= (sce_header*)(self_file);
	Elf32_Ehdr *ehdr	= (Elf32_Ehdr*)(elf_file);
	Elf32_Ehdr *self_ehdr	= (Elf32_Ehdr*)(self_file + shdr->elf_offset);
	Elf32_Phdr *elf_phdrs	= (Elf32_Phdr*)(elf_file + ehdr->e_phoff);
	segment_info *snfo	= (segment_info*)(self_file + shdr->section_info_offset);
	control_info *cnfo	= (control_info *)(self_file + shdr->controlinfo_offset);

	/* Validate some aspects of the SELF/ELF headers on our user input:
	 *	- Die if we can't validate magic bytes on either header
	 *	- Refuse to support cases where we remove/add ELF segments
	 */

	if (memcmp(self_file, "\x53\x43\x45\x00", 4) != 0)
	{
		fprintf(stderr, "%s is not a valid SELF file\n", argv[1]);
		exit(-1);
	}
	if (memcmp(elf_file, "\x7f\x45\x4c\x46\x01\x01\x01", 7) != 0)
	{
		fprintf(stderr, "%s is not a valid ELF file\n", argv[1]);
		exit(-1);
	}
	if (ehdr->e_phnum != self_ehdr->e_phnum) 
	{
		fprintf(stderr, "The number of segments doesn't match\n");
		fprintf(stderr, "(No support for adding/removing segments)\n");
		exit(-1);
	}
	if (ehdr->e_phnum > MAX_SEGMENTS)
	{
		fprintf(stderr, "No support for files with more than %d segments (found %d)\n",
				MAX_SEGMENTS, ehdr->e_phnum);
		exit(-1);

	}

	fprintf(stdout, "Read SELF file %s (%08x bytes)\n", argv[1], self_len);
	fprintf(stdout, "Read ELF file %s (%08x bytes)\n", argv[2], elf_len);

	/* Re-compress all of the segments in the ELF file, and also write the 
	 * new size of the segments into the corresponding section_info entry 
	 * on the SELF header.
	 */

	// Embed the new ELF header into the SELF header
	memcpy(self_file + shdr->elf_offset, elf_file, sizeof(Elf32_Ehdr));
	memcpy(self_file + shdr->phdr_offset, (elf_file + ehdr->e_phoff), 
			(ehdr->e_phentsize * ehdr->e_phnum));

	// Compress all of the segments
	for (int i = 0; i < ehdr->e_phnum; i++) 
	{
		fprintf(stdout, "Got ELF segment %i\t[length=%08x, off=%08x]\n",
			i, (u32)elf_phdrs[i].p_filesz, 
			(u32)elf_phdrs[i].p_offset);

		fprintf(stdout, "Original SELF segment %i\t[length=%08x]\n", 
				i, (u32)snfo[i].length);

		size_t lz_len = compress_segment(
			lzdata_buf, 
			(elf_file + elf_phdrs[i].p_offset), 
			elf_phdrs[i].p_filesz
		);

		seg_lzdata[i] = (u8*)calloc(1, lz_len + 0x10);
		memcpy(seg_lzdata[i], lzdata_buf, lz_len);

		snfo[i].length = lz_len;
		fprintf(stdout, "New SELF segment %i\t[length=%08x]\n", i, 
				(u32)snfo[i].length);
	}

	/* The control_info struct in the SELF contains a SHA256 digest of the
	 * embedded ELF file. Re-compute SHA256 digest for the contents of the 
	 * new ELF to-be-embedded in the SELF file output
	 */

	fprintf(stdout, "Old SHA256 digest: ");
	for (int i = 0; i < SHA256_DIGEST_LEN; i++)
		fprintf(stdout, "%02x", cnfo->elf_digest_info.elf_digest[i]);
	fprintf(stdout, "\n");

	sha256_digest(elf_digest, elf_len, elf_file);

	fprintf(stdout, "New SHA256 digest: ");
	for (int i = 0; i < SHA256_DIGEST_LEN; i++)
		fprintf(stdout, "%02x", elf_digest[i]);
	fprintf(stdout, "\n");
	
	while(cnfo->next) {
		switch(cnfo->type) {
		case 4:
			memcpy(cnfo->elf_digest_info.elf_digest, &elf_digest, 
					sizeof(elf_digest));
			break;
		case 5:
			memset(&cnfo->npdrm_info, 0, sizeof(cnfo->npdrm_info));
			break;
		}
		cnfo = (control_info*)((char*)cnfo + cnfo->size);
	}


	/* Flush the new SELF file to disk step-by-step, then fix up some of
	 * the fields in the new SELF header afterwards. */
	
	FILE *fout = fopen(argv[3], "wb");

	fwrite(self_file, sizeof(sce_header), 1, fout);
	fwrite(self_file + shdr->appinfo_offset, sizeof(sce_appinfo), 1, fout);

	fwrite(self_file + shdr->elf_offset, sizeof(Elf32_Ehdr), 1, fout);
	u8 ehdr_pad[0xc] = { 0 };
	fwrite(&ehdr_pad, 0xc, 1, fout);
	fwrite(self_file + shdr->phdr_offset, ehdr->e_phentsize, 
			ehdr->e_phnum, fout);

	fwrite(self_file + shdr->section_info_offset, sizeof(segment_info), 
			ehdr->e_phnum, fout);
	fwrite(self_file + shdr->sceversion_offset, sizeof(sce_version), 1, 
			fout);
	fwrite(self_file + shdr->controlinfo_offset, shdr->controlinfo_size, 1, 
			fout);

	int cm_pad_len = shdr->metadata_offset - 
		(shdr->controlinfo_offset + shdr->controlinfo_size);
	u8 *cm_padding = calloc(1, cm_pad_len);
	fwrite(cm_padding, cm_pad_len, 1, fout);
	free(cm_padding);

	u8 metadata_pad[METADATA_PAD_LEN] = { 0 };
	fwrite(&metadata_pad, METADATA_PAD_LEN, 1, fout);

	int metadata_len = shdr->header_len - 
		shdr->metadata_offset - METADATA_PAD_LEN;
	fwrite(self_file + shdr->metadata_offset + METADATA_PAD_LEN, 
			metadata_len, 1, fout);

	// `vita-inject-elf` writes the plaintext header here
	fwrite(elf_file, elf_phdrs[0].p_offset, 1, fout);

	// Compressed segment data is aligned to 0x10-byte boundaries
	u64 current_pos, aligned_pos;
	for (int i = 0; i < ehdr->e_phnum; i++) 
	{
		current_pos = ftell(fout);
		aligned_pos = ((current_pos + 0x10 - 1) / 0x10) * 0x10;
		fseek(fout, aligned_pos, SEEK_SET);
		snfo[i].offset = aligned_pos;
		fwrite(seg_lzdata[i], snfo[i].length, 1, fout);
	}

	// Correct the segment_info entry offsets in the SELF header
	fseek(fout, shdr->section_info_offset, SEEK_SET);
	fwrite(self_file + shdr->section_info_offset, sizeof(segment_info), 
			ehdr->e_phnum, fout);

	// Correct the total filesize in the SELF header
	fseek(fout, 0, SEEK_END);
	u64 self_filesize  = ftell(fout);
	fseek(fout, 0x20, SEEK_SET);
	fwrite(&self_filesize, sizeof(self_filesize), 1, fout);
	fseek(fout, 0, SEEK_END);

	fclose(fout);
	fprintf(stdout, "Wrote new file to %s (%08x bytes)\n", argv[3], 
			self_filesize);
	free(self_file);
	free(elf_file);
	free(lzdata_buf);
	for (int i = 0; i < MAX_SEGMENTS; i++)
	{
		if (seg_lzdata[i] != NULL) 
			free(seg_lzdata[i]);
	}
	return 0;
}
