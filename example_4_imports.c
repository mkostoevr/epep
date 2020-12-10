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
	if (epep.kind == EPEP_IMAGE && epep_has_import_table(&epep)) {
		printf("Import Directory Table:\n");
		for (size_t i = 0; i < 1024; i++) {
			EpepImportDirectory import_directory = { 0 };
			if (!epep_get_import_directory_by_index(&epep, &import_directory, i)) {
				return ERROR(epep);
			}
			if (import_directory.NameRva == 0) {
				break;
			}
			size_t name_max = 1024;
			char name[name_max];
			if (!epep_get_import_directory_name_s(&epep, &import_directory, name, name_max)) {
				return ERROR(epep);
			}
			printf("  Import Directory #%lu:\n", i);
			printf("    Name:                  %s\n", name);
			printf("    ImportLookupTableRva:  %08x\n", import_directory.ImportLookupTableRva);
			printf("    TimeDateStamp:         %08x\n", import_directory.TimeDateStamp);
			printf("    ForwarderChain:        %08x\n", import_directory.ForwarderChain);
			printf("    ImportAddressTableRva: %08x\n", import_directory.ImportAddressTableRva);
			for (size_t j = 0; j < 1024 * 1024; j++) {
				size_t lookup = 0;
				if (!epep_get_import_directory_lookup_by_index(&epep, &import_directory, &lookup, j)) {
					return ERROR(epep);
				}
				if (lookup == 0) {
					break;
				}
				size_t name_max = 1024;
				char name[name_max];
				if (!epep_get_lookup_name_s(&epep, lookup, name, name_max)) {
					return ERROR(epep);
				}
				printf("      Lookup:              %016x (%s)\n", lookup, name);
			}
		}
		printf("\n");
	} else if (epep.error_code) {
		return ERROR(epep);
	}
	return 0;
}
