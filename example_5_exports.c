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
	if (epep.kind == EPEP_IMAGE && epep_has_export_table(&epep)) {
		if (!epep_read_export_directory(&epep)) {
			return ERROR(epep);
		}
		size_t name_max = 256;
		char name[name_max];
		strcpy(name, "undefined");
		if (!epep_get_dll_name_s(&epep, name, name_max)) {
			return ERROR(epep);
		}
		printf("Export Directory:\n");
		printf("  ExportFlags:           %08x\n", epep.export_directory.ExportFlags);
		printf("  TimeDateStamp:         %08x\n", epep.export_directory.TimeDateStamp);
		printf("  MajorVersion:          %04x\n", epep.export_directory.MajorVersion);
		printf("  MinorVersion:          %04x\n", epep.export_directory.MinorVersion);
		printf("  NameRva:               %08x (%s)\n", epep.export_directory.NameRva, name);
		printf("  OrdinalBase:           %08x\n", epep.export_directory.OrdinalBase);
		printf("  AddressTableEntries:   %08x\n", epep.export_directory.AddressTableEntries);
		printf("  NumberOfNamePointers:  %08x\n", epep.export_directory.NumberOfNamePointers);
		printf("  ExportAddressTableRva: %08x\n", epep.export_directory.ExportAddressTableRva);
		printf("  NamePointerRva:        %08x\n", epep.export_directory.NamePointerRva);
		printf("  OrdinalTableRva:       %08x\n", epep.export_directory.OrdinalTableRva);
		printf("  Exports:\n");
		for (size_t i = 0; i < epep.export_directory.AddressTableEntries; i++) {
			printf("    Export #%u:\n", i);
			size_t name_max = 1024;
			char name[name_max];
			printf("      Ordinal:      %u\n", epep.export_directory.OrdinalBase + i);
			if (epep_get_export_name_s_by_index(&epep, name, name_max, i)) {
				printf("      Name:         %s\n", name);
			}
			EpepExportAddress ea = { 0 };
			if (!epep_get_export_address_by_index(&epep, &ea, i)) {
				return ERROR(epep);
			}
			if (epep_export_address_is_forwarder(&epep, &ea)) {
				size_t forwarder_max = 1024;
				char forwarder[forwarder_max];
				if (!epep_get_export_address_forwarder_s(&epep, &ea, forwarder, forwarder_max)) {
					return ERROR(epep);
				}
				printf("      ForwarderRva: %08x (%s)\n", ea.ForwarderRva, forwarder);
			} else {
				printf("      ExportRva:    %08x\n", ea.ExportRva);
			}
		}
		printf("\n");
	} else if (epep.error_code) {
		return ERROR(epep);
	}
	return 0;
}
