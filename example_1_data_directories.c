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
	if (epep.coffFileHeader.SizeOfOptionalHeader != 0) {
		printf("Data directories:\n");
		for (size_t i = 0; i < epep.optionalHeader.NumberOfRvaAndSizes; i++) {
			char *dds[] = {
				"Export Table",
				"Import Table",
				"Resource Table",
				"Exception Table",
				"Certificate Table",
				"Base Relocation Table",
				"Debug",
				"Architecture",
				"Global Ptr",
				"TLS Table",
				"Load Config Table",
				"Bound Import",
				"Import Address Table",
				"Delay Import Descriptor",
				"CLR Runtime Header",
				"Reserved, must be zero"
			};
			EpepImageDataDirectory idd = { 0 };
			if (!epep_get_data_directory_by_index(&epep, &idd, i)) {
				return ERROR(epep);
			}
			printf("  Data directory #%u:\n", i);
			printf("    Type:           %s\n", dds[i % 16]);
			printf("    VirtualAddress: %016x\n", idd.VirtualAddress);
			printf("    Size:           %016x\n", idd.Size);
			// Certificate table (4'th) data directory's VirtualAddress isn't a real RVA, it's a file offset
			// so it's actually outside of any section, so let's skip section name printing for it
			if (idd.VirtualAddress && i != 4) {
				EpepSectionHeader sh = { 0 };
				if (!epep_get_section_header_by_rva(&epep, &sh, idd.VirtualAddress)) {
					return ERROR(epep);
				}
				printf("    Section:        %s\n", sh.Name);
			}
		}
	}
	return 0;
}
