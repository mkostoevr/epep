#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define EPEP_INST
#include "epep.h"

#define ERROR(epep) (printf("Error #%u from EPEP at " __FILE__ ": %u", epep.error_code, __LINE__), 1)

int main(int argc, char **argv) {
	if (argc < 2) {
		printf("Usage:\n%s <filename>\n", argv[0]);
		return 0;
	}
	Epep epep = { 0 };
	FILE *fp = fopen(argv[1], "rb");
	if (!fp) {
		printf("File not found: %s\n", argv[1]);
		return 1;
	}
	if (!epep_init(&epep, fp)) {
		printf("Not PE");
		return 1;
	}
	// Get string table useful to show long names of sections
	size_t string_table_size = 1;
	if (epep.kind == EPEP_OBJECT && !epep_get_string_table_size(&epep, &string_table_size)) {
		return ERROR(epep);
	}
	char *string_table = malloc(string_table_size);
	if (epep.kind == EPEP_OBJECT && !epep_get_string_table(&epep, string_table)) {
		return ERROR(epep);
	}
	if (epep.kind == EPEP_OBJECT) {
		for (size_t i = 0; i < epep.coffFileHeader.NumberOfSections; i++) {
		EpepSectionHeader sh = { 0 };
		if (!epep_get_section_header_by_index(&epep, &sh, i)) {
			return ERROR(epep);
		}
		printf("  Relocations for section #%u", i);
		if (epep.kind == EPEP_OBJECT && sh.Name[0] == '/') {
			printf(" (%s)\n", &string_table[atoi(sh.Name + 1)]);
		} else {
			printf(" (%.*s)\n", 8, sh.Name);
		}
		for (size_t i = 0; i < sh.NumberOfRelocations; i++) {
			EpepCoffRelocation rel = { 0 };
			if (!epep_get_section_relocation_by_index(&epep, &sh, &rel, i)) {
				return ERROR(epep);
			}
			printf("    COFF Relocation #%u\n", i);
			printf("      VirtualAddress: %08x\n", rel.VirtualAddress);
			printf("      SymbolTableIndex: %08x\n", rel.SymbolTableIndex);
			printf("      Type: %04x\n", rel.Type);
		}
	}
	}
	return 0;
}
