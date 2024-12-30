#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define EPEP_INST
#include "../epep.h"

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
	printf("COFF File Header:\n");
	printf("  Machine:              %04x\n", epep.coffFileHeader.Machine);
	printf("  NumberOfSections:     %04x\n", epep.coffFileHeader.NumberOfSections);
	printf("  TimeDateStamp:        %08x\n", epep.coffFileHeader.TimeDateStamp);
	printf("  PointerToSymbolTable: %08x\n", epep.coffFileHeader.PointerToSymbolTable);
	printf("  NumberOfSymbols:      %08x\n", epep.coffFileHeader.NumberOfSymbols);
	printf("  SizeOfOptionalHeader: %04x\n", epep.coffFileHeader.SizeOfOptionalHeader);
	printf("  Characteristics:      %04x\n", epep.coffFileHeader.Characteristics);
	printf("\n");
	if (epep.coffFileHeader.SizeOfOptionalHeader != 0) {
		printf("Optional Header:\n");
		printf("  Magic:                       %04x\n", epep.optionalHeader.Magic);
		printf("  MajorLinkerVersion:          %02x\n", epep.optionalHeader.MajorLinkerVersion);
		printf("  MinorLinkerVersion:          %02x\n", epep.optionalHeader.MinorLinkerVersion);
		printf("  SizeOfCode:                  %08x\n", epep.optionalHeader.SizeOfCode);
		printf("  SizeOfInitializedData:       %08x\n", epep.optionalHeader.SizeOfInitializedData);
		printf("  SizeOfUninitializedData:     %08x\n", epep.optionalHeader.SizeOfUninitializedData);
		printf("  AddressOfEntryPoint:         %08x\n", epep.optionalHeader.AddressOfEntryPoint);
		printf("  BaseOfCode:                  %08x\n", epep.optionalHeader.BaseOfCode);
		printf("  BaseOfData:                  %08x\n", epep.optionalHeader.BaseOfData);
		printf("  ImageBase:                   %016x\n", epep.optionalHeader.ImageBase);
		printf("  SectionAlignment:            %08x\n", epep.optionalHeader.SectionAlignment);
		printf("  FileAlignment:               %08x\n", epep.optionalHeader.FileAlignment);
		printf("  MajorOperatingSystemVersion: %04x\n", epep.optionalHeader.MajorOperatingSystemVersion);
		printf("  MinorOperatingSystemVersion: %04x\n", epep.optionalHeader.MinorOperatingSystemVersion);
		printf("  MajorImageVersion:           %04x\n", epep.optionalHeader.MajorImageVersion);
		printf("  MinorImageVersion:           %04x\n", epep.optionalHeader.MinorImageVersion);
		printf("  MajorSubsystemVersion:       %04x\n", epep.optionalHeader.MajorSubsystemVersion);
		printf("  MinorSubsystemVersion:       %04x\n", epep.optionalHeader.MinorSubsystemVersion);
		printf("  Win32VersionValue:           %08x\n", epep.optionalHeader.Win32VersionValue);
		printf("  SizeOfImage:                 %08x\n", epep.optionalHeader.SizeOfImage);
		printf("  SizeOfHeaders:               %08x\n", epep.optionalHeader.SizeOfHeaders);
		printf("  CheckSum:                    %08x\n", epep.optionalHeader.CheckSum);
		printf("  Subsystem:                   %04x\n", epep.optionalHeader.Subsystem);
		printf("  DllCharacteristics:          %04x\n", epep.optionalHeader.DllCharacteristics);
		printf("  SizeOfStackReserve:          %016x\n", epep.optionalHeader.SizeOfStackReserve);
		printf("  SizeOfStackCommit:           %016x\n", epep.optionalHeader.SizeOfStackCommit);
		printf("  SizeOfHeapReserve:           %016x\n", epep.optionalHeader.SizeOfHeapReserve);
		printf("  SizeOfHeapCommit:            %016x\n", epep.optionalHeader.SizeOfHeapCommit);
		printf("  LoaderFlags:                 %08x\n", epep.optionalHeader.LoaderFlags);
		printf("  NumberOfRvaAndSizes:         %08x\n", epep.optionalHeader.NumberOfRvaAndSizes);
		printf("\n");
	}
	return 0;
}
