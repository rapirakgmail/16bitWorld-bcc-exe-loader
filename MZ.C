#include <stdio.h>
#include <stdlib.h>
#include <mem.h>
#include <string.h>
#include <dos.h>


// MZ Header
typedef struct _IMAGE_DOS_HEADER {
	unsigned short e_magic;      // Magic number 'MZ' = 0x5A4D
	unsigned short e_cblp;       // Bytes on last page of file
	unsigned short e_cp;         // number Pages in file (จำนวน หน้า (pages) ในไฟล์ Exe
	unsigned short e_crlc;       // Relocations
	unsigned short e_cparhdr;    // Size of header in paragraphs (1 paragraph = 16 bytes)
	unsigned short e_minalloc;   // Minimum extra paragraphs needed
	unsigned short e_maxalloc;   // Maximum extra paragraphs needed
	unsigned short e_ss;         // Initial (relative) SS value
	unsigned short e_sp;         // Initial SP value
	unsigned short e_csum;       // Checksum
	unsigned short e_ip;         // Initial IP value
	unsigned short e_cs;         // Initial (relative) CS value
	unsigned short e_lfarlc;     // File address of relocation table
	unsigned short e_ovno;       // Overlay number
	unsigned short e_res[4];     // Reserved words
	unsigned short e_oemid;      // OEM identifier (for e_oeminfo)
	unsigned short e_oeminfo;    // OEM information; e_oemid specific
	unsigned short e_res2[10];   // Reserved  unsigned short
	unsigned long  e_lfanew;     // Offset to PE header (if a PE file)
} IMAGE_DOS_HEADER;


// Relocation Entry
struct RelocEntry {
	unsigned short offset;
	unsigned short segment;
};
void showMzInfo(char *filename) {

	FILE *f;
	IMAGE_DOS_HEADER hdr;
	struct RelocEntry reloc;
	int i;
	int estimated_size;

	f = fopen(filename, "rb");
	if (!f) {
	printf("Cannot open file.\n");
	return;
	}

	fread(&hdr, sizeof( IMAGE_DOS_HEADER ), 1, f);

	if (hdr.e_magic != 0x5A4D) {
	printf("Not a valid MZ EXE.\n");
	fclose(f);
	return;
	}

	printf("\n== MZ Header ==\n");
	printf("Magic:            0x%04X\n", hdr.e_magic);
	printf("Bytes last page:  %u\n", hdr.e_cblp);
	printf("Pages in file:    %u\n", hdr.e_cp);
	printf("Relocations:      %u\n", hdr.e_crlc);
	printf("Header size:      %u paragraphs (%lu bytes)\n", hdr.e_cparhdr, (unsigned long)(hdr.e_cparhdr * 16));
	printf("Min alloc:        %u paragraphs\n", hdr.e_minalloc);
	printf("Max alloc:        %u paragraphs\n", hdr.e_maxalloc);
	printf("Initial SS:       0x%04X\n", hdr.e_ss);
	printf("Initial SP:       0x%04X\n", hdr.e_sp);
	printf("Checksum:         0x%04X\n", hdr.e_csum);
	printf("Initial IP:       0x%04X\n", hdr.e_ip);
	printf("Initial CS:       0x%04X\n", hdr.e_cs);
	printf("Reloc table at:   0x%04X\n", hdr.e_lfarlc);
	printf("Overlay number:   %u\n", hdr.e_ovno);
	printf("OEM ID:           %u\n", hdr.e_oemid);
	printf("OEM Info:         %u\n", hdr.e_oeminfo);
	printf("PE header offset: 0x%08lX\n", hdr.e_lfanew);

	estimated_size = (unsigned long)(hdr.e_cp * 512);
	if (hdr.e_cblp != 0)
	estimated_size -= (512 - hdr.e_cblp);

	printf("\nEstimated EXE size: %lu bytes\n", estimated_size);


	printf("\n== MZ Header ==\n");
	printf("\nRelocation Count : %u", hdr.e_crlc);
	printf("\nReloc Table Off  : 0x%04X", hdr.e_lfarlc);

	//e_crlc	Number of relocation entries.
	if (hdr.e_crlc > 0) {
	fseek(f, hdr.e_lfarlc, SEEK_SET);
	printf("\n== Relocation Table ==\n");
	for (i = 0; i < hdr.e_crlc; i++) {
		fread(&reloc, sizeof(struct RelocEntry), 1, f);
		printf("#%02d: Segment = 0x%04X, Offset = 0x%04X, Linear = 0x%05lX\n",
		   i,
		   reloc.segment,
		   reloc.offset,
		   (unsigned long)((reloc.segment << 4) + reloc.offset));
	}
	} else {
	printf("No relocation entries.\n");
	}
	fclose(f);
}

int main(int argc,char *argv[])
{
	char fname[256];
	FILE *fp;
	strcpy(fname,"C:\\MZ\\H.EXE");
	if( argv[1] != NULL ) {
	  strcpy( fname,argv[1] );
	}

	showMzInfo( fname );

}