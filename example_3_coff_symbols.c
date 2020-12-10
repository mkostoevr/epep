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
	size_t string_table_size = 1;
	if (epep.kind == EPEP_OBJECT && !epep_get_string_table_size(&epep, &string_table_size)) {
		return ERROR(epep);
	}
	char *string_table = malloc(string_table_size);
	if (epep.kind == EPEP_OBJECT && !epep_get_string_table(&epep, string_table)) {
		return ERROR(epep);
	}

	if (epep.kind == EPEP_OBJECT && epep.coffFileHeader.NumberOfSymbols != 0) {
		printf("Symbols:\n");
		for (size_t i = 0; i < epep.coffFileHeader.NumberOfSymbols; i++) {
			EpepCoffSymbol sym = { 0 };
			if (!epep_get_symbol_by_index(&epep, &sym, i)) {
				return ERROR(epep);
			}
			printf("  Symbol #%u\n", i);
			if (sym.symbol.Zeroes == 0) {
				printf("    Name:               %s\n", &string_table[sym.symbol.Offset]);
			} else {
				printf("    Name:               %.*s\n", 8, sym.symbol.ShortName);
			}
			printf("    Value:              %08x\n", sym.symbol.Value);
			printf("    SectionNumber:      %04x\n", sym.symbol.SectionNumber);
			printf("    Type:               %04x\n", sym.symbol.Type);
			printf("    StorageClass:       %02x\n", sym.symbol.StorageClass);
			printf("    NumberOfAuxSymbols: %02x\n", sym.symbol.NumberOfAuxSymbols);
			for (size_t j = 0; j < sym.symbol.NumberOfAuxSymbols; j++) {
				i++;
			}
		}
		printf("\n");
	}
	return 0;
}
