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

#define DOS_HEADER_PADDING 58
#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550
#define PE32 0x010B
#define PE32_PLUS 0x020B

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
    PE_ERROR_INVALID_HEADER_OFFSET
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

// 3. Definition of the Analyzer itself (which now recognizes the headers defined above)
typedef struct pe_analyzer {
    const uint8_t *fileData;
    const image_dos_header *dosHeader;
    const uint8_t *ntHeader;
    const image_file_header *fileHeader;
    size_t fileSize;
    int fd;
    const uint8_t *optHeader;
} pe_analyzer;

// 4. Finally - Declaration of public functions only!
pe_status_t peLoad(pe_analyzer *ctx, const char *filepath);
void freeResources(pe_analyzer *ctx);

#endif