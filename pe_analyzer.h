/* Include guard to prevent the header from being included multiple times */
#ifndef PE_ANALYZER_H
#define PE_ANALYZER_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <stdbool.h>

#define DOS_HEADER_PADDING 58
#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550
#define PE32 0x010B
#define PE32_PLUS 0x020B
#define IMAGE_SIZEOF_SHORT_NAME 8
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000ULL

#define IMAGE_DIRECTORY_ENTRY_EXPORT    0
#define IMAGE_DIRECTORY_ENTRY_IMPORT    1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE  2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#define IMAGE_DIRECTORY_ENTRY_SECURITY  4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_DEBUG     6
#define IMAGE_DIRECTORY_ENTRY_TLS       7
#define IMAGE_DIRECTORY_ENTRY_IAT       12
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_WRITE 0x80000000

// 1. Define the enum first, so the functions below can use it
typedef enum {
    PE_SUCCESS, 
    PE_ERROR_FILE_OPEN, 
    PE_ERROR_STAT, 
    PE_ERROR_MMAP, 
    PE_ERROR_FILE_TOO_SMALL, 
    PE_ERROR_INVALID_DOS_SIGNATURE, 
    PE_ERROR_INVALID_NT_OFFSET, 
    PE_ERROR_INVALID_PE_SIGNATURE,
    PE_ERROR_INVALID_HEADER_OFFSET,
    PE_ERROR_INVALID_SECTION_HEADER,
    PE_ERROR_INVALID_IMPORT_TABLE,
    PE_ERROR_PARSE_IMPORT_THUNKS,
    PE_ERROR_PARSE_EXPORT_DIRECTORY,
    PE_ERROR_PARSE_SECTION_HEADER
} pe_status_t;

// 2. Definition of the PE structures
typedef struct image_dos_header {
    uint16_t e_magic;
    uint8_t padding[DOS_HEADER_PADDING];
    uint32_t e_lfanew;
} __attribute__((packed)) image_dos_header;

typedef struct image_file_header {
    uint16_t machine;
    uint16_t numberOfSections;
    uint32_t timeDateStamp;
    uint32_t pointerToSymbolTable;
    uint32_t numberOfSymbols;
    uint16_t sizeOfOptionalHeader;
    uint16_t characteristics;
} __attribute__((packed)) image_file_header;


typedef struct image_data_directory {
    uint32_t virtualAddress;
    uint32_t size;

}  __attribute__((packed)) image_data_directory;

typedef struct image_import_descriptor {
    uint32_t originalFirstThunk;
    uint32_t timeDateStamp;
    uint32_t forwarderChain;
    uint32_t name;
    uint32_t firstThunk;
}  __attribute__((packed)) image_import_descriptor;

typedef struct image_import_by_name {
    uint16_t hint;
    uint8_t name[1];
}  __attribute__((packed)) image_import_by_name;

typedef struct image_optional_header_64 {
    uint16_t magic;
    uint8_t majorLinkerVersion;
    uint8_t minorLinkerVersion;
    uint32_t sizeOfCode;
    uint32_t sizeOfInitializedData;
    uint32_t sizeOfUninitializedData;
    uint32_t addressOfEntryPoint;
    uint32_t baseOfCode;
    uint64_t imageBase;
    uint32_t sectionAlignment;
    uint32_t fileAlignment;
    uint16_t majorOperatingSystemVersion;
    uint16_t minorOperatingSystemVersion;
    uint16_t majorImageVersion;
    uint16_t minorImageVersion;
    uint16_t majorSubsystemVersion;
    uint16_t minorSubsystemVersion;
    uint32_t win32VersionValue;
    uint32_t sizeOfImage;
    uint32_t sizeOfHeaders;
    uint32_t checkSum;
    uint16_t subsystem;
    uint16_t dllCharacteristics;
    uint64_t sizeOfStackReserve;
    uint64_t sizeOfStackCommit;
    uint64_t sizeOfHeapReserve;
    uint64_t sizeOfHeapCommit;
    uint32_t loaderFlags;
    uint32_t numberOfRvaAndSizes;
    image_data_directory dataDirectory[16];
} __attribute__((packed)) image_optional_header_64;

typedef struct image_section_header {
    uint8_t name[IMAGE_SIZEOF_SHORT_NAME];
    uint32_t virtualSize;
    uint32_t virtualAddress;
    uint32_t sizeOfRawData;
    uint32_t pointerToRawData;
    uint32_t pointerToRelocations;
    uint32_t pointerToLinenumbers;
    uint16_t numberOfRelocations;
    uint16_t numberOfLinenumbers;
    uint32_t characteristics;
} __attribute__((packed)) image_section_header;


typedef struct image_export_directory {
    uint32_t characteristics;        
    uint32_t timeDateStamp;         
    uint16_t majorVersion;
    uint16_t minorVersion;
    uint32_t name;                   
    uint32_t base;                  
    uint32_t numberOfFunctions;      
    uint32_t numberOfNames;          
    uint32_t addressOfFunctions;     
    uint32_t addressOfNames;         
    uint32_t addressOfNameOrdinals;  
} __attribute__((packed)) image_export_directory;

// 3. Definition of the Analyzer itself (which now recognizes the headers defined above)
typedef struct pe_analyzer {
    const uint8_t *fileData;
    const image_dos_header *dosHeader;
    const uint8_t *ntHeader;
    const image_file_header *fileHeader;
    const image_optional_header_64 *optHeader64;
    const image_section_header *sectionHeaders;
    size_t fileSize;
    int fd;
    const uint8_t *optHeader;
} pe_analyzer;



// 4. Finally - Declaration of public functions only!
pe_status_t peLoad(pe_analyzer *ctx, const char *filepath);
void freeResources(pe_analyzer *ctx);

#endif