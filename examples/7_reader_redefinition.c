// The program reads its own memory instead of a file and parses its section headers.
// It redefines reader so that it reads directly from memory.

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>

typedef struct {
	char *base;
	size_t index;
} Reader;

char reader_get(Reader *r) {
	return r->base[r->index++];
}

void reader_seek(Reader *r, size_t s) {
	r->index = s;
}

size_t reader_tell(Reader *r) {
	return r->index;
}

void reader_get_block(Reader *r, size_t s, void *buf) {
	for (size_t i = 0; i < s; i++) {
		*r->base++ = reader_get(r);
	}
}

#define EPEP_READER Reader
#define EPEP_READER_GET(r) reader_get(r)
#define EPEP_READER_SEEK(reader, offset) reader_seek(reader, offset)
#define EPEP_READER_TELL(reader) reader_tell(reader)
#define EPEP_READER_GET_BLOCK(reader, size, buf) reader_get_block(reader, size, buf)
#define EPEP_INST
#include "../epep.h"



#define ERROR(epep) (printf("Error #%u from EPEP at " __FILE__ ": %u", epep.error_code, __LINE__), 1)

int main(int argc, char **argv) {
	Reader r = { .base = GetModuleHandle(NULL), .index = 0 };
	Epep epep = { 0 };
	if (!epep_init(&epep, r)) {
		printf("Not PE");
		return 1;
	}

	// Get string table useful to show long names of sections (not mondatory actually)
	size_t string_table_size = 1;
	if (epep.kind == EPEP_OBJECT && !epep_get_string_table_size(&epep, &string_table_size)) {
		return ERROR(epep);
	}
	char *string_table = malloc(string_table_size);
	if (epep.kind == EPEP_OBJECT && !epep_get_string_table(&epep, string_table)) {
		return ERROR(epep);
	}

	printf("Section Table:\n");
	for (size_t i = 0; i < epep.coffFileHeader.NumberOfSections; i++) {
		EpepSectionHeader sh = { 0 };
		if (!epep_get_section_header_by_index(&epep, &sh, i)) {
			return ERROR(epep);
		}
		printf("  Section #%u\n", i);
		// Object filrs may contain sections with long names
		// In that case names are stored in COFF String Table and index of name in the table is stored after '/' in Name
		if (epep.kind == EPEP_OBJECT && sh.Name[0] == '/') {
			printf("    Name:                 %s\n", &string_table[atoi(sh.Name + 1)]);
		} else {
			printf("    Name:                 %.*s\n", 8, sh.Name);
		}
		printf("    VirtualSize:          %08x\n", sh.VirtualSize);
		printf("    VirtualAddress:       %08x\n", sh.VirtualAddress);
		printf("    SizeOfRawData:        %08x\n", sh.SizeOfRawData);
		printf("    PointerToRawData:     %08x\n", sh.PointerToRawData);
		printf("    PointerToRelocations: %08x\n", sh.PointerToRelocations);
		printf("    PointerToLinenumbers: %08x\n", sh.PointerToLinenumbers);
		printf("    NumberOfRelocations:  %08x\n", sh.NumberOfRelocations);
		printf("    NumberOfLinenumbers:  %08x\n", sh.NumberOfLinenumbers);
		printf("    Characteristics:      %08x\n", sh.Characteristics);
	}
	return 0;
}
