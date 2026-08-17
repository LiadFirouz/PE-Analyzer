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


typedef enum {PE_SUCCESS, PE_ERROR_FILE_OPEN, PE_ERROR_STAT, PE_ERROR_MMAP, PE_ERROR_FILE_TOO_SMALL, PE_ERROR_INVALID_DOS_SIGNATURE}pe_status_t;

typedef struct pe_analyzer
{
    const uint8_t *fileData;
    const uint8_t *dosHeader;
    const uint8_t *ntHeader;

    size_t fileSize;
    int fd;
}pe_analyzer;

pe_status_t peLoad (pe_analyzer *ctx, const char *filepath);
void freeResources (pe_analyzer *ctx);

#endif