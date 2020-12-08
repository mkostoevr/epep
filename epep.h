// Dependencies:
// <stdint.h> or any another source of uint64_t, uint32_t, uint16_t, uint8_t, size_t

#ifndef EPEP_READER
#include <stdio.h>
#define EPEP_READER FILE *
#define EPEP_READER_GET(reader) getc(reader)
#define EPEP_READER_SEEK(reader, offset) fseek(reader, offset, SEEK_SET)
#define EPEP_READER_TELL(reader) ftell(reader)
#define EPEP_READER_GET_BLOCK(reader, size, buf) fread(buf, 1, size, reader);
#endif

//
// Public declarations
//

typedef enum {
	EPEP_INVALID,
	EPEP_IMAGE,
	EPEP_OBJECT,
} EpepKind;

typedef enum {
	EPEP_ERR_SUCCESS,
	EPEP_ERR_DATA_DIRECTORY_INDEX_IS_INVALID,
	EPEP_ERR_SECTION_HEADER_INDEX_IS_INVALID,
	EPEP_ERR_SYMBOL_INDEX_IS_INVALID,
	EPEP_ERR_NOT_AN_OBJECT,
	EPEP_ERR_ADDRESS_IS_OUT_OF_SECTION_RAW_DATA,
	EPEP_ERR_OUTPUT_CAPACITY_IS_ZERO,
	EPEP_ERR_OUTPUT_IS_NULL,
	EPEP_ERR_ADDRESS_IS_OUT_OF_ANY_SECTION,
} EpepError;

typedef struct {
	uint32_t ExportRva;
	uint32_t ForwarderRva;
} EpepExportAddress;

typedef struct {
	uint32_t ImportLookupTableRva;
	uint32_t TimeDateStamp;
	uint32_t ForwarderChain;
	uint32_t NameRva;
	uint32_t ImportAddressTableRva;
} EpepImportDirectory;

typedef struct {
	uint32_t VirtualAddress;
	uint32_t Size;
} EpepImageDataDirectory;

typedef struct {
	char Name[8];
	uint32_t VirtualSize;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData;
	uint32_t PointerToRawData;
	uint32_t PointerToRelocations;
	uint32_t PointerToLinenumbers;
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers;
	uint32_t Characteristics;
} EpepSectionHeader;

typedef union {
	struct {
		union {
			char ShortName[8];
			struct {
				uint32_t Zeroes;
				uint32_t Offset;
			};
		};
		uint32_t Value;
		uint16_t SectionNumber;
		uint16_t Type;
		uint8_t StorageClass;
		uint8_t NumberOfAuxSymbols;
	} symbol;
	struct {
		uint32_t TagIndex;
		uint32_t TotalSize;
		uint32_t PointerToLinenumber;
		uint32_t PointerToNextFunction;
		uint16_t Unused;
	} auxFunctionDefinition;
	struct {
		uint8_t Unused0[4];
		uint16_t Linenumber;
		uint8_t Unused1[6];
		uint32_t PointerToNextFunction;
		uint8_t Unused2[2];
	} auxBfOrEfSymbol;
	struct {
		uint32_t TagIndex;
		uint32_t Characteristics;
		uint8_t Unused[10];
	} auxWeakExternal;
	struct {
		char FileName[18];
	} auxFile;
	struct {
		uint32_t Length;
		uint16_t NumberOfRelocations;
		uint16_t NumberOfLinenumbers;
		uint32_t CheckSum;
		uint16_t Number;
		uint8_t  Selection;
		uint8_t Unused[3];
	} auxSectionDefinition;
} EpepCoffSymbol;

typedef struct {
	EPEP_READER reader;
	EpepKind kind;
	EpepError error_code;
	size_t signature_offset_offset;
	size_t signature_offset;
	size_t first_data_directory_offset;
	size_t first_section_header_offset;
	size_t export_table_offset;
	size_t import_table_offset;
	struct {
		uint16_t Machine;
		uint16_t NumberOfSections;
		uint32_t TimeDateStamp;
		uint32_t PointerToSymbolTable;
		uint32_t NumberOfSymbols;
		uint16_t SizeOfOptionalHeader;
		uint16_t Characteristics;
	} coffFileHeader;
	struct {
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
	struct {
		uint32_t ExportFlags;
		uint32_t TimeDateStamp;
		uint16_t MajorVersion;
		uint16_t MinorVersion;
		uint32_t NameRva;
		uint32_t OrdinalBase;
		uint32_t AddressTableEntries;
		uint32_t NumberOfNamePointers;
		uint32_t ExportAddressTableRva;
		uint32_t NamePointerRva;
		uint32_t OrdinalTableRva;
	} export_directory;
} Epep;

//
// Public functions
//

/// Constructor of the general information container
int epep_init(Epep *epep, EPEP_READER reader);

/// Gives Data Directiry by its index
int epep_get_data_directory_by_index(Epep *epep, EpepImageDataDirectory *idd, size_t index);

/// Gives Section Header by its index
int epep_get_section_header_by_index(Epep *epep, EpepSectionHeader *sh, size_t index);

/// Gives COFF Symbol by its index
int epep_get_symbol_by_index(Epep *epep, EpepCoffSymbol *sym, size_t index);

/// Gives COFF string table size
int epep_get_string_table_size(Epep *epep, size_t *size);

/// Gives COFF string table
int epep_get_string_table(Epep *epep, char *string_table);

/// Gives section contents by Section Header
int epep_get_section_contents(Epep *epep, EpepSectionHeader *sh, void *buf);

/// Gives section header by RVA
int epep_get_section_header_by_rva(Epep *epep, EpepSectionHeader *sh, size_t addr);

/// Gives file offset corresponding to RVA is any, returns 0 othervice
int epep_get_file_offset_by_rva(Epep *epep, size_t *offset, size_t addr);

/// Returns non-zero if import table exists in the file
int epep_has_import_table(Epep *epep);

/// Places offset of import table into epep structure
int epep_read_import_table_offset(Epep *epep);

/// Gives Import Directory by index
int epep_get_import_directory_by_index(Epep *epep, EpepImportDirectory *import_directory, size_t index);

/// Gives name of Import Directory (library)
int epep_get_import_directory_name_s(Epep *epep, EpepImportDirectory *import_directory, char *name, size_t name_max);

/// Gives Import Lookup by import directory and index
int epep_get_import_directory_lookup_by_index(Epep *epep, EpepImportDirectory *import_directory, size_t *lookup, size_t index);

/// Gives name of Import Directory Lookup (imported symbol) or nothing if imported by ordinal
int epep_get_lookup_name_s(Epep *epep, size_t lookup, char *name, size_t name_max);

/// Returns non-zero if export table exists in the file
int epep_has_export_table(Epep *epep);

/// Palces offset of export table into epep structrue
int epep_read_export_table_offset(Epep *epep);

/// Palces export table into epep structrue
int epep_read_export_directory(Epep *epep);

/// Gives name of the DLL
int epep_get_dll_name_s(Epep *epep, char *name, size_t name_max);

//
// The code
//

#ifdef EPEP_INST

static int is_pe32(Epep *epep) {
	return epep->optionalHeader.Magic == 0x10b;
}

static int is_pe32p(Epep *epep) {
	return epep->optionalHeader.Magic == 0x20b;
}

static uint8_t epep_read_u8(Epep *epep) {
	return EPEP_READER_GET(epep->reader);
}

static uint16_t epep_read_u16(Epep *epep) {
	unsigned l = epep_read_u8(epep);
	unsigned h = epep_read_u8(epep);
	return l | (h << 8);
}

static uint32_t epep_read_u32(Epep *epep) {
	unsigned b0 = epep_read_u8(epep);
	unsigned b1 = epep_read_u8(epep);
	unsigned b2 = epep_read_u8(epep);
	unsigned b3 = epep_read_u8(epep);
	return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
}

static uint64_t epep_read_u64(Epep *epep) {
	uint64_t res = 0;
	for (unsigned i = 0; i < 64; i += 8) {
		res |= epep_read_u8(epep) << i;
	}
	return res;
}

static uint64_t epep_read_ptr(Epep *epep) {
	return is_pe32(epep) ? epep_read_u32(epep) : epep_read_u64(epep);
}

int epep_init(Epep *epep, EPEP_READER reader) {
	*epep = (Epep){ 0 };
	epep->kind = EPEP_IMAGE;
	epep->reader = reader;
	epep->error_code = EPEP_ERR_SUCCESS;
	epep->signature_offset_offset = 0x3c;
	EPEP_READER_SEEK(epep->reader, epep->signature_offset_offset);
	epep->signature_offset = 0;
	epep->signature_offset |= epep_read_u8(epep);
	epep->signature_offset |= epep_read_u8(epep) << 8;
	epep->signature_offset |= epep_read_u8(epep) << 16;
	epep->signature_offset |= epep_read_u8(epep) << 24;
	EPEP_READER_SEEK(epep->reader, epep->signature_offset);
	char signature_buf[4];
	signature_buf[0] = epep_read_u8(epep);
	signature_buf[1] = epep_read_u8(epep);
	signature_buf[2] = epep_read_u8(epep);
	signature_buf[3] = epep_read_u8(epep);
	if (signature_buf[0] != 'P' || signature_buf[1] != 'E' ||
		signature_buf[2] != '\0' || signature_buf[3] != '\0') {
		epep->kind = EPEP_OBJECT;
		EPEP_READER_SEEK(epep->reader, 0);
	}
	epep->coffFileHeader.Machine = epep_read_u16(epep);
	epep->coffFileHeader.NumberOfSections = epep_read_u16(epep);
	epep->coffFileHeader.TimeDateStamp = epep_read_u32(epep);
	epep->coffFileHeader.PointerToSymbolTable = epep_read_u32(epep);
	epep->coffFileHeader.NumberOfSymbols = epep_read_u32(epep);
	epep->coffFileHeader.SizeOfOptionalHeader = epep_read_u16(epep);
	epep->coffFileHeader.Characteristics = epep_read_u16(epep);
	if (epep->coffFileHeader.SizeOfOptionalHeader != 0) {
		// Standard fields
		epep->optionalHeader.Magic = epep_read_u16(epep);
		epep->optionalHeader.MajorLinkerVersion = epep_read_u8(epep);
		epep->optionalHeader.MinorLinkerVersion = epep_read_u8(epep);
		epep->optionalHeader.SizeOfCode = epep_read_u32(epep);
		epep->optionalHeader.SizeOfInitializedData = epep_read_u32(epep);
		epep->optionalHeader.SizeOfUninitializedData = epep_read_u32(epep);
		epep->optionalHeader.AddressOfEntryPoint = epep_read_u32(epep);
		epep->optionalHeader.BaseOfCode = epep_read_u32(epep);
		if (is_pe32(epep)) {
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
		epep->first_data_directory_offset = EPEP_READER_TELL(epep->reader);
	}
	epep->first_section_header_offset = EPEP_READER_TELL(epep->reader);
	if (epep->coffFileHeader.SizeOfOptionalHeader != 0) {
		epep->first_section_header_offset += epep->optionalHeader.NumberOfRvaAndSizes * sizeof(EpepImageDataDirectory);
	}
	return 1;
}

int epep_get_data_directory_by_index(Epep *epep, EpepImageDataDirectory *idd, size_t index) {
	if (index >= epep->optionalHeader.NumberOfRvaAndSizes) {
		epep->error_code = EPEP_ERR_DATA_DIRECTORY_INDEX_IS_INVALID;
		return 0;
	}
	EPEP_READER_SEEK(epep->reader, epep->first_data_directory_offset + sizeof(EpepImageDataDirectory) * index);
	idd->VirtualAddress = epep_read_u32(epep);
	idd->Size = epep_read_u32(epep);
	return 1;
}

int epep_get_section_header_by_index(Epep *epep, EpepSectionHeader *sh, size_t index) {
	if (index >= epep->coffFileHeader.NumberOfSections) {
		epep->error_code = EPEP_ERR_SECTION_HEADER_INDEX_IS_INVALID;
		return 0;
	}
	EPEP_READER_SEEK(epep->reader, epep->first_section_header_offset + sizeof(EpepSectionHeader) * index);
	for (int i = 0; i < 8; i++) {
		sh->Name[i] = epep_read_u8(epep);
	}
	sh->VirtualSize = epep_read_u32(epep);
	sh->VirtualAddress = epep_read_u32(epep);
	sh->SizeOfRawData = epep_read_u32(epep);
	sh->PointerToRawData = epep_read_u32(epep);
	sh->PointerToRelocations = epep_read_u32(epep);
	sh->PointerToLinenumbers = epep_read_u32(epep);
	sh->NumberOfRelocations = epep_read_u16(epep);
	sh->NumberOfLinenumbers = epep_read_u16(epep);
	sh->Characteristics = epep_read_u32(epep);
	return 1;
}

int epep_get_symbol_by_index(Epep *epep, EpepCoffSymbol *sym, size_t index) {
	if (epep->kind != EPEP_OBJECT) {
		epep->error_code = EPEP_ERR_NOT_AN_OBJECT;
		return 0;
	}
	if (index >= epep->coffFileHeader.NumberOfSymbols) {
		epep->error_code = EPEP_ERR_SYMBOL_INDEX_IS_INVALID;
		return 0;
	}
	EPEP_READER_SEEK(epep->reader, epep->coffFileHeader.PointerToSymbolTable + 18 * index);
	for (size_t i = 0; i < 18; i++) {
		sym->auxFile.FileName[i] = epep_read_u8(epep);
	}
	return 1;
}

int epep_get_string_table_size(Epep *epep, size_t *size) {
	EPEP_READER_SEEK(epep->reader, epep->coffFileHeader.PointerToSymbolTable + 18 * epep->coffFileHeader.NumberOfSymbols);
	*size = epep_read_u32(epep);
	return 1;
}

int epep_get_string_table(Epep *epep, char *string_table) {
	size_t size = 0;
	if (!epep_get_string_table_size(epep, &size)) {
		return 0;
	}
	// A COFF strings table starts with its size
	*string_table++ = (size & 0x000000ff) >> 0;
	*string_table++ = (size & 0x0000ff00) >> 8;
	*string_table++ = (size & 0x00ff0000) >> 16;
	*string_table++ = (size & 0xff000000) >> 24;
	EPEP_READER_GET_BLOCK(epep->reader, size - 4, string_table);
	return 1;
}

int epep_get_section_contents(Epep *epep, EpepSectionHeader *sh, void *buf) {
	size_t size_of_raw_data = sh->SizeOfRawData;
	EPEP_READER_SEEK(epep->reader, sh->PointerToRawData);
	EPEP_READER_GET_BLOCK(epep->reader, size_of_raw_data, buf);
	return 1;
}

int epep_get_section_header_by_rva(Epep *epep, EpepSectionHeader *sh, size_t addr) {
	EpepSectionHeader sh0 = { 0 };
	for (size_t i = 0; i < epep->coffFileHeader.NumberOfSections; i++) {
		epep_get_section_header_by_index(epep, &sh0, i);
		if (addr >= sh0.VirtualAddress && addr < (sh0.VirtualAddress + sh0.VirtualSize)) {
			*sh = sh0;
			return 1;
		}
	}
	epep->error_code = EPEP_ERR_ADDRESS_IS_OUT_OF_ANY_SECTION;
	return 0;
}

int epep_get_file_offset_by_rva(Epep *epep, size_t *offset, size_t addr) {
	EpepSectionHeader sh = { 0 };
	if (!epep_get_section_header_by_rva(epep, &sh, addr)) {
		return 0;
	}
	size_t diff = addr - sh.VirtualAddress;
	if (diff >= sh.SizeOfRawData) {
		epep->error_code = EPEP_ERR_ADDRESS_IS_OUT_OF_SECTION_RAW_DATA;
		return 0;
	}
	*offset = sh.PointerToRawData + diff;
	return 1;
}

int epep_has_import_table(Epep *epep) {
	EpepImageDataDirectory idd = { 0 };
	if (!epep_get_data_directory_by_index(epep, &idd, 1)) {
		return 0;
	}
	return idd.VirtualAddress;
}

int epep_read_import_table_offset(Epep *epep) {
	EpepImageDataDirectory import_table_dd = { 0 };
	if (!epep_get_data_directory_by_index(epep, &import_table_dd, 1)) {
		return 0;
	}
	if (!epep_get_file_offset_by_rva(epep, &epep->import_table_offset, import_table_dd.VirtualAddress)) {
		return 0;
	}
	return 1;
}

int epep_get_import_directory_by_index(Epep *epep, EpepImportDirectory *import_directory, size_t index) {
	if (epep->import_table_offset == 0) {
		if (!epep_read_import_table_offset(epep)) {
			return 0;
		}
	}
	EPEP_READER_SEEK(epep->reader, epep->import_table_offset + index * sizeof(*import_directory));
	EPEP_READER_GET_BLOCK(epep->reader, sizeof(*import_directory), import_directory);
	return 1;
}

int epep_get_import_directory_name_s(Epep *epep, EpepImportDirectory *import_directory, char *name, size_t name_max) {
	size_t name_rva = import_directory->NameRva;
	size_t name_offset = 0;
	if (!epep_get_file_offset_by_rva(epep, &name_offset, name_rva)) {
		return 0;
	}
	EPEP_READER_SEEK(epep->reader, name_offset);
	EPEP_READER_GET_BLOCK(epep->reader, name_max, name);
	return 1;
}

int epep_get_import_directory_lookup_by_index(Epep *epep, EpepImportDirectory *import_directory, size_t *lookup, size_t index) {
	size_t first_lookup_offset = 0;
	if (!epep_get_file_offset_by_rva(epep, &first_lookup_offset, import_directory->ImportLookupTableRva)) {
		return 0;
	}
	size_t size_of_lookup = is_pe32(epep) ? 4 : 8;
	size_t lookup_offset = first_lookup_offset + size_of_lookup * index;
	EPEP_READER_SEEK(epep->reader, lookup_offset);
	EPEP_READER_GET_BLOCK(epep->reader, size_of_lookup, lookup);
	return 1;
}

int epep_get_lookup_name_s(Epep *epep, size_t lookup, char *name, size_t name_max) {
	if (name_max == 0) {
		epep->error_code = EPEP_ERR_OUTPUT_CAPACITY_IS_ZERO;
		return 0;
	}
	if (name == NULL) {
		epep->error_code = EPEP_ERR_OUTPUT_IS_NULL;
		return 0;
	}
	uint64_t mask = is_pe32(epep) ? 0x80000000 : 0x8000000000000000;
	if (lookup & mask) {
		name[0] = '\0';
		return 1;
	}
	size_t name_rva = lookup;
	size_t name_offset = 0;
	if (!epep_get_file_offset_by_rva(epep, &name_offset, name_rva)) {
		return 0;
	}
	// skip 2 bytes (Name Table :: Hint)
	name_offset += 2;
	EPEP_READER_SEEK(epep->reader, name_offset);
	EPEP_READER_GET_BLOCK(epep->reader, name_max, name);
	return 1;
}

int epep_has_export_table(Epep *epep) {
	EpepImageDataDirectory idd = { 0 };
	if (!epep_get_data_directory_by_index(epep, &idd, 0)) {
		return 0;
	}
	return idd.VirtualAddress;
}

int epep_read_export_table_offset(Epep *epep) {
	EpepImageDataDirectory export_table_dd = { 0 };
	if (!epep_get_data_directory_by_index(epep, &export_table_dd, 0)) {
		return 0;
	}
	if (!epep_get_file_offset_by_rva(epep, &epep->export_table_offset, export_table_dd.VirtualAddress)) {
		return 0;
	}
	return 1;
}

int epep_read_export_directory(Epep *epep) {
	if (epep->export_table_offset == 0) {
		if (!epep_read_export_table_offset(epep)) {
			return 0;
		}
	}
	EPEP_READER_SEEK(epep->reader, epep->export_table_offset);
	EPEP_READER_GET_BLOCK(epep->reader, sizeof(epep->export_directory), &epep->export_directory);
	return 1;
}

int epep_get_dll_name_s(Epep *epep, char *name, size_t name_max) {
	size_t offset = 0;
	if (!epep_get_file_offset_by_rva(epep, &offset, epep->export_directory.NameRva)) {
		return 0;
	}
	EPEP_READER_SEEK(epep->reader, offset);
	EPEP_READER_GET_BLOCK(epep->reader, name_max, name);
	return 1;
}

#endif // EPEP_INST
