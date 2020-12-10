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
	if (epep_has_base_relocation_table(&epep)) {
		printf("Base Relocations:\n");
		EpepBaseRelocationBlock brb = { 0 };
		if (!epep_get_first_base_relocation_block(&epep, &brb)) {
			return ERROR(epep);
		}
		for (size_t i = 0; brb.offset; i++) {
			printf("  Base Relocation Block #%u:\n", i);
			printf("    PageRva:   %08x\n", brb.PageRva);
			printf("    BlockSize: %08x\n", brb.BlockSize);
			printf("    Relocations:\n");
			for (size_t j = 0; j < ((brb.BlockSize - 8) / 2); j++) {
				char *strs[] = {
					"IMAGE_REL_BASED_ABSOLUTE",
					"IMAGE_REL_BASED_HIGH",
					"IMAGE_REL_BASED_LOW",
					"IMAGE_REL_BASED_HIGHLOW",
					"IMAGE_REL_BASED_HIGHADJ",
					"IMAGE_REL_BASED_MIPS_JMPADDR | IMAGE_REL_BASED_ARM_MOV32 | IMAGE_REL_BASED_RISCV_HIGH20",
					"reserved, must be zero",
					"IMAGE_REL_BASED_THUMB_MOV32 | IMAGE_REL_BASED_RISCV_LOW12I",
					"IMAGE_REL_BASED_RISCV_LOW12S",
					"IMAGE_REL_BASED_MIPS_JMPADDR16",
					"IMAGE_REL_BASED_DIR64",
				};
				printf("      Relocation #%u:\n", j);
				EpepBaseRelocation br = { 0 };
				if (!epep_get_base_relocation_block_base_relocation_by_index(&epep, &brb, &br, j)) {
					return ERROR(epep);
				}
				printf("        Type:   %01x (%s)\n", br.Type, strs[br.Type % (sizeof(strs) / sizeof(*strs))]);
				printf("        Offset: %03x (%u)\n", br.Offset, br.Offset);
			}
			if (!epep_get_next_base_relocation_block(&epep, &brb)) {
				return ERROR(epep);
			}
		}
		printf("\n");
	} else if (epep.error_code) {
		return ERROR(epep);
	}
	return 0;
}
