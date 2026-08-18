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

typedef enum {PE_SUCCESS, PE_ERROR_FILE_OPEN, PE_ERROR_STAT, PE_ERROR_MMAP, PE_ERROR_FILE_TOO_SMALL, PE_ERROR_INVALID_DOS_SIGNATURE, PE_ERROR_INVALID_NT_OFFSET, PE_ERROR_INVALID_PE_SIGNATURE}pe_status_t;

typedef struct pe_analyzer
{
    const uint8_t *fileData;
    const image_dos_header *dosHeader;
    const uint8_t *ntHeader;

    size_t fileSize;
    int fd;
}pe_analyzer;

typedef struct image_dos_header
{
    uint16_t e_magic;
    uint8_t padding[DOS_HEADER_PADDING];
    uint32_t e_lfanew;
}__attribute__((packed)) image_dos_header;;

pe_status_t peLoad (pe_analyzer *ctx, const char *filepath);
static pe_status_t IOLayout (pe_analyzer *ctx, const char *filepath);
static pe_status_t parsingLayout(pe_analyzer *ctx);
void freeResources (pe_analyzer *ctx);

#endif