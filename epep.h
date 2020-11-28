#ifndef EPEP_READER
#include <stdio.h>
#define EPEP_READER FILE *
#define EPEP_READER_GET(reader) getc(reader)
#define EPEP_READER_SEEK(reader, offset) fseek(reader, offset, SEEK_SET)
#endif

typedef struct {
	uint32_t VirtualAddress;
	uint32_t Size;
} EpepImageDataDirectory;

typedef struct {
	EPEP_READER reader;
	size_t signature_offset_offset;
	size_t signature_offset;
	struct CoffFileHeader {
		uint16_t Machine;
		uint16_t NumberOfSections;
		uint32_t TimeDateStamp;
		uint32_t PointerToSymbolTable;
		uint32_t NumberOfSymbols;
		uint16_t SizeOfOptionalHeader;
		uint16_t Characteristics;
	} coffFileHEader;
	struct OptionalHeader {
		// Standard fields
		uint16_t Magic;
		uint8_t MajorLinkerVersion;
		uint8_t MinorLinkerVersion;
		uint32_t SizeOfCode;
		uint32_t SizeOfInitializedData;
		uint32_t SizeOfUninitializedData;
		uint32_t AddressOfEntryPoint;
		uint32_t BaseOfCode;
		uint32_t BaseOfData; // PE32-only
		// Windows-specific fields
		uint64_t ImageBase;
		uint32_t SectionAlignment;
		uint32_t FileAlignment;
		uint16_t MajorOperatingSystemVersion;
		uint16_t MinorOperatingSystemVersion;
		uint16_t MajorImageVersion;
		uint16_t MinorImageVersion;
		uint16_t MajorSubsystemVersion;
		uint16_t MinorSubsystemVersion;
		uint32_t Win32VersionValue;
		uint32_t SizeOfImage;
		uint32_t SizeOfHeaders;
		uint32_t CheckSum;
		uint16_t Subsystem;
		uint16_t DllCharacteristics;
		uint64_t SizeOfStackReserve;
		uint64_t SizeOfStackCommit;
		uint64_t SizeOfHeapReserve;
		uint64_t SizeOfHeapCommit;
		uint32_t LoaderFlags;
		uint32_t NumberOfRvaAndSizes;
	} optionalHeader;
} Epep;

static int epep_read_u16(Epep *epep) {
	unsigned l = EPEP_READER_GET(epep->reader);
	unsigned h = EPEP_READER_GET(epep->reader);
	return l | (h << 8);
}

static int epep_read_u32(Epep *epep) {
	unsigned b0 = EPEP_READER_GET(epep->reader);
	unsigned b1 = EPEP_READER_GET(epep->reader);
	unsigned b2 = EPEP_READER_GET(epep->reader);
	unsigned b3 = EPEP_READER_GET(epep->reader);
	return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
}

static int epep_read_u64(Epep *epep) {
	uint64_t res = 0;
	for (unsigned i = 0; i < 64; i += 8) {
		res |= EPEP_READER_GET(epep->reader) << i;
	}
	return res;
}

static int epep_read_ptr(Epep *epep) {
	return epep->optionalHeader.Magic == 0x10b
		? epep_read_u32(epep)
		: epep_read_u64(epep);
}

int epep_init(Epep *epep, EPEP_READER reader) {
	memset(epep, 0, sizeof(epep));
	epep->reader = reader;
	epep->signature_offset_offset = 0x3c;
	EPEP_READER_SEEK(epep->reader, epep->signature_offset_offset);
	epep->signature_offset = 0;
	epep->signature_offset |= EPEP_READER_GET(epep->reader);
	epep->signature_offset |= EPEP_READER_GET(epep->reader) << 8;
	epep->signature_offset |= EPEP_READER_GET(epep->reader) << 16;
	epep->signature_offset |= EPEP_READER_GET(epep->reader) << 24;
	EPEP_READER_SEEK(epep->reader, epep->signature_offset);
	if (EPEP_READER_GET(epep->reader) != 'P' ||
		EPEP_READER_GET(epep->reader) != 'E' ||
		EPEP_READER_GET(epep->reader) != '\0' ||
		EPEP_READER_GET(epep->reader) != '\0') {
		return 0;
	}
	epep->coffFileHEader.Machine = epep_read_u16(epep);
	epep->coffFileHEader.NumberOfSymbols = epep_read_u16(epep);
	epep->coffFileHEader.TimeDateStamp = epep_read_u32(epep);
	epep->coffFileHEader.PointerToSymbolTable = epep_read_u32(epep);
	epep->coffFileHEader.NumberOfSymbols = epep_read_u32(epep);
	epep->coffFileHEader.SizeOfOptionalHeader = epep_read_u16(epep);
	epep->coffFileHEader.Characteristics = epep_read_u16(epep);
	if (epep->coffFileHEader.SizeOfOptionalHeader != 0) {
		// Standard fields
		epep->optionalHeader.Magic = epep_read_u16(epep);
		epep->optionalHeader.MajorLinkerVersion = EPEP_READER_GET(epep->reader);
		epep->optionalHeader.MinorLinkerVersion = EPEP_READER_GET(epep->reader);
		epep->optionalHeader.SizeOfCode = epep_read_u32(epep);
		epep->optionalHeader.SizeOfInitializedData = epep_read_u32(epep);
		epep->optionalHeader.SizeOfUninitializedData = epep_read_u32(epep);
		epep->optionalHeader.AddressOfEntryPoint = epep_read_u32(epep);
		epep->optionalHeader.BaseOfCode = epep_read_u32(epep);
		if (epep->optionalHeader.Magic == 0x10b) {
			epep->optionalHeader.BaseOfData = epep_read_u32(epep);
		}
		// Windows-specific fields
		epep->optionalHeader.ImageBase = epep_read_ptr(epep);
		epep->optionalHeader.SectionAlignment = epep_read_u32(epep);
		epep->optionalHeader.FileAlignment = epep_read_u32(epep);
		epep->optionalHeader.MajorOperatingSystemVersion = epep_read_u16(epep);
		epep->optionalHeader.MinorOperatingSystemVersion = epep_read_u16(epep);
		epep->optionalHeader.MajorImageVersion = epep_read_u16(epep);
		epep->optionalHeader.MinorImageVersion = epep_read_u16(epep);
		epep->optionalHeader.MajorSubsystemVersion = epep_read_u16(epep);
		epep->optionalHeader.Win32VersionValue = epep_read_u32(epep);
		epep->optionalHeader.MinorSubsystemVersion = epep_read_u16(epep);
		epep->optionalHeader.SizeOfImage = epep_read_u32(epep);
		epep->optionalHeader.SizeOfHeaders = epep_read_u32(epep);
		epep->optionalHeader.CheckSum = epep_read_u32(epep);
		epep->optionalHeader.Subsystem = epep_read_u16(epep);
		epep->optionalHeader.DllCharacteristics = epep_read_u16(epep);
		epep->optionalHeader.SizeOfStackReserve = epep_read_ptr(epep);
		epep->optionalHeader.SizeOfStackCommit = epep_read_ptr(epep);
		epep->optionalHeader.SizeOfHeapReserve = epep_read_ptr(epep);
		epep->optionalHeader.SizeOfHeapCommit = epep_read_ptr(epep);
		epep->optionalHeader.LoaderFlags = epep_read_u32(epep);
		epep->optionalHeader.NumberOfRvaAndSizes = epep_read_u32(epep);
	}
	return 1;
}

void epep_get_image_data_directory(Epep *epep, EpepImageDataDirectory *idd) {
	
}
