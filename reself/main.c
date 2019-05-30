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
#define EHDR_PAD_LEN		0x0c		// ELF header padding length

u8 elf_digest[SHA256_DIGEST_LEN];		// SHA256 digest buffer
u8 *lzdata_buf;					// zlib compression buffer
u8 *s_buf, *e_buf;			// User input buffers
size_t self_len, elf_len;			// Size of user input
u8 *seg_lzdata[MAX_SEGMENTS] = { NULL };	// Compressed segment buffers

u8 metadata_pad[METADATA_PAD_LEN] = { 0 };	// A bunch of padding zeros
u8 ehdr_pad[0xc] = { 0 };			// ...


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
		printf("zlib compress() returned %d for phdr\n", res);
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
		printf("usage: %s ", argv[0]);
		printf("<input SELF> <input ELF> <output SELF>\n");
		exit(0);
	}

	lzdata_buf		= (u8*)calloc(1, LZ_BUF_LEN);

	self_len		= get_filesize(argv[1]);
	elf_len			= get_filesize(argv[2]);
	s_buf			= read_file(argv[1], self_len);
	e_buf			= read_file(argv[2], elf_len);

	sce_header *shdr	= (sce_header*)(s_buf);
	Elf32_Ehdr *ehdr	= (Elf32_Ehdr*)(e_buf);
	Elf32_Ehdr *self_ehdr	= (Elf32_Ehdr*)(s_buf + shdr->elf_off);
	Elf32_Phdr *elf_phdrs	= (Elf32_Phdr*)(e_buf + ehdr->e_phoff);

	seginfo *snfo	= (seginfo*)(s_buf + shdr->seginfo_off);
	ctrlinfo *cnfo	= (ctrlinfo *)(s_buf + shdr->ctrlinfo_off);


	// Validate some user input before proceeding
	if (memcmp(s_buf, "\x53\x43\x45\x00", 4) != 0)
	{
		printf("%s is not a valid SELF file\n", argv[1]); exit(-1);
	}
	if (memcmp(e_buf, "\x7f\x45\x4c\x46\x01\x01\x01", 7) != 0)
	{
		printf("%s is not a valid ELF file\n", argv[1]); exit(-1);
	}
	if (ehdr->e_phnum != self_ehdr->e_phnum) 
	{
		printf("The number of segments doesn't match\n"); exit(-1);
	}
	if (ehdr->e_phnum > MAX_SEGMENTS)
	{
		printf("No support for >%d segments\n",MAX_SEGMENTS); exit(-1);
	}

	printf("Got input %s (%08x bytes)\n", argv[1], self_len);
	printf("Got input %s (%08x bytes)\n", argv[2], elf_len);

	// Embed the new ELF header (from user input)
	memcpy(s_buf + shdr->elf_off, e_buf, sizeof(Elf32_Ehdr));
	memcpy(s_buf + shdr->phdr_off, (e_buf + ehdr->e_phoff), 
			(ehdr->e_phentsize * ehdr->e_phnum));

	// Re-compress all of the ELF segments
	for (int i = 0; i < ehdr->e_phnum; i++) 
	{
		printf("Got segment %i\t[length=%08x, off=%08x]\n", i, 
				(u32)elf_phdrs[i].p_filesz, 
				(u32)elf_phdrs[i].p_offset);

		printf("Original segment %i\t[length=%08x]\n", i, 
				(u32)snfo[i].size);

		u8 *src = e_buf + elf_phdrs[i].p_offset;
		size_t lz_len = compress_segment(lzdata_buf, src,
			elf_phdrs[i].p_filesz);

		seg_lzdata[i] = (u8*)calloc(1, lz_len + 0x10);
		memcpy(seg_lzdata[i], lzdata_buf, lz_len);

		snfo[i].size = lz_len;

		printf("New segment %i\t[length=%08x]\n", i, (u32)snfo[i].size);
	}

	// Recompute SHA256 digest over contents of the new ELF to-be-embedded
	sha256_digest(elf_digest, elf_len, e_buf);
	while(cnfo->next) 
	{
		switch(cnfo->type) {
		case 4:
			memcpy(cnfo->elf_digest_info.elf_digest, &elf_digest, 
					sizeof(elf_digest));
			break;
		case 5:
			memset(&cnfo->npdrm_info, 0, sizeof(cnfo->npdrm_info));
			break;
		}
		cnfo = (ctrlinfo*)((char*)cnfo + cnfo->size);
	}


	
	FILE *fout = fopen(argv[3], "wb");

	u8 *src = s_buf;
	fwrite(src, sizeof(sce_header), 1, fout);
	src = s_buf + shdr->appinfo_off;
	fwrite(src, sizeof(sce_appinfo), 1, fout);

	src = s_buf + shdr->elf_off;
	fwrite(src, sizeof(Elf32_Ehdr), 1, fout);
	fwrite(&ehdr_pad, 0xc, 1, fout);
	src = s_buf + shdr->phdr_off;
	fwrite(src, ehdr->e_phentsize, ehdr->e_phnum, fout);
	
	src = s_buf + shdr->seginfo_off;
	fwrite(src, sizeof(seginfo), ehdr->e_phnum, fout);
	src = s_buf + shdr->sceversion_off;
	fwrite(src, sizeof(sce_version), 1, fout);
	src = s_buf + shdr->ctrlinfo_off;
	fwrite(src, shdr->ctrlinfo_size, 1, fout);

	int ctrlinfo_tail = shdr->ctrlinfo_off + shdr->ctrlinfo_size;
	int cm_pad_len = shdr->metadata_off - ctrlinfo_tail;
	u8 *cm_padding = calloc(1, cm_pad_len);
	fwrite(cm_padding, cm_pad_len, 1, fout);
	free(cm_padding);

	fwrite(&metadata_pad, METADATA_PAD_LEN, 1, fout);

	int metadata_len = shdr->header_len - shdr->metadata_off - 
		METADATA_PAD_LEN;
	src = s_buf + shdr->metadata_off + METADATA_PAD_LEN;
	fwrite(src, metadata_len, 1, fout);

	// Just write the plaintext header (?)
	fwrite(e_buf, elf_phdrs[0].p_offset, 1, fout);

	// Compressed segment data is aligned to 0x10-byte boundaries
	u64 current_pos, aligned_pos;
	for (int i = 0; i < ehdr->e_phnum; i++) 
	{
		current_pos = ftell(fout);
		aligned_pos = ((current_pos + 0x10 - 1) / 0x10) * 0x10;
		fseek(fout, aligned_pos, SEEK_SET);
		snfo[i].off = aligned_pos;
		fwrite(seg_lzdata[i], snfo[i].size, 1, fout);
	}

	// Correct the seginfo entry offsets in the SELF header
	fseek(fout, shdr->seginfo_off, SEEK_SET);
	fwrite(s_buf + shdr->seginfo_off, sizeof(seginfo), 
			ehdr->e_phnum, fout);

	// Correct the total SELF filesize in the SELF header
	fseek(fout, 0, SEEK_END);
	u64 self_filesize  = ftell(fout);
	fseek(fout, 0x20, SEEK_SET);
	fwrite(&self_filesize, sizeof(self_filesize), 1, fout);


	// Correct the total ELF filesize in the SELF header
	fseek(fout, 0x18, SEEK_SET);
	u64 elf_filesize = elf_len;
	fwrite(&elf_filesize, sizeof(elf_filesize), 1, fout);


	fseek(fout, 0, SEEK_END);
	fclose(fout);
	printf("Wrote new file to %s (%08x bytes)\n", argv[3], 
			self_filesize);
	free(s_buf);
	free(e_buf);
	free(lzdata_buf);
	for (int i = 0; i < MAX_SEGMENTS; i++)
	{
		if (seg_lzdata[i] != NULL) 
			free(seg_lzdata[i]);
	}
	return 0;
}
