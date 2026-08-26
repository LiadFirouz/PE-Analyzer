#include "pe_analyzer.h"
#include <unistd.h>
#include <errno.h>

// Forward Declarations for internal use
static pe_status_t IOLayout(pe_analyzer *ctx, const char *filepath);
static pe_status_t parsingLayout(pe_analyzer *ctx);
uint32_t RvaToOffset(uint32_t rva, const pe_analyzer *ctx);

// Main entry function to load and parse a PE (Portable Executable) file
pe_status_t peLoad(pe_analyzer *ctx, const char *filepath)
{
    // Perform file I/O and map the file into memory
    pe_status_t status = IOLayout(ctx, filepath);
    if (status != PE_SUCCESS)
        return status;

    // Parse and validate the PE layout and headers
    return parsingLayout(ctx);
}

// Handles opening the file, verifying its status, and mapping it to memory
static pe_status_t IOLayout(pe_analyzer *ctx, const char *filepath)
{
    // Basic pointer safety checks to ensure valid input
    if (ctx == NULL || filepath == NULL)
    {
        return PE_ERROR_FILE_OPEN;
    }

    // Open the target file in read-only mode
    int fd = open(filepath, O_RDONLY);

    // Check if the file descriptor is valid
    if (fd == -1)
    {
        // Print which type of error the code have
        perror("Failed to open file");
        return PE_ERROR_FILE_OPEN;
    }

    // Get the file size using fstat
    struct stat fileSize;

    // Call fstat passing the file descriptor and structure address
    if (fstat(fd, &fileSize) == -1)
    {
        perror("Error retrieving file status\n");
        close(fd);
        return PE_ERROR_STAT;
    }

    // Ensure the file is at least large enough to contain a standard DOS header (64 bytes)
    if (fileSize.st_size < (long)64)
    {
        fprintf(stderr, "File is too small (less than 64 bytes)\n");
        close(fd);
        return PE_ERROR_FILE_TOO_SMALL;
    }

    // Map the file into virtual memory for read-only access
    void *mappedMemory = mmap(NULL, fileSize.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mappedMemory == MAP_FAILED)
    {
        close(fd);
        return PE_ERROR_MMAP;
    }

    // Assign the mapped memory pointer to the context
    ctx->fileData = (const uint8_t *)mappedMemory;

    // Update our context struct on success with the file descriptor and size
    ctx->fd = fd;
    ctx->fileSize = fileSize.st_size;

    return PE_SUCCESS;
}

// Parses the mapped memory to locate and validate PE headers
static pe_status_t parsingLayout(pe_analyzer *ctx)
{
    // Point the DOS header to the beginning of the mapped file
    ctx->dosHeader = (const image_dos_header *)ctx->fileData;

    // Validate the DOS signature (typically 'MZ')
    if (ctx->dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("e_magic %04X, ctx->fileData[0] %c, ctx->fileData[1] %c\n", ctx->dosHeader->e_magic, ctx->fileData[0], ctx->fileData[1]);
        freeResources(ctx);
        return PE_ERROR_INVALID_DOS_SIGNATURE;
    }

    // Check if the offset to the NT headers exceeds the file boundary
    if ((ctx->dosHeader->e_lfanew > ctx->fileSize - 24))
    {
        freeResources(ctx);
        return PE_ERROR_INVALID_NT_OFFSET;
    }

    // Locate the NT headers using the offset from the DOS header
    ctx->ntHeader = ctx->fileData + ctx->dosHeader->e_lfanew;

    // Validate the PE signature (typically 'PE\0\0')
    if (*(const uint32_t *)(ctx->ntHeader) != IMAGE_NT_SIGNATURE)
    {
        freeResources(ctx);
        return PE_ERROR_INVALID_PE_SIGNATURE;
    }

    ctx->fileHeader = (const image_file_header *)(ctx->ntHeader + 4);
    printf("Machine: %04X\n", ctx->fileHeader->machine);

    ctx->optHeader = (const uint8_t *)(ctx->fileHeader + 1);

    if (ctx->fileSize + ctx->fileData < ctx->fileHeader->sizeOfOptionalHeader + ctx->optHeader)
    {
        printf("There was an overflow in the header\n");
        freeResources(ctx);
        return PE_ERROR_INVALID_HEADER_OFFSET;
    }

    uint16_t magic = *((uint16_t *)(ctx->optHeader));
    printf("magic = %04X\n", magic);
    ctx->optHeader64 = (const image_optional_header_64 *)ctx->optHeader;
    printf("ImageBase = %016llX, AddressOfEntryPoint = %08X\n", ctx->optHeader64->imageBase, ctx->optHeader64->addressOfEntryPoint);

    ctx->sectionHeaders = (const image_section_header *)(ctx->optHeader + ctx->fileHeader->sizeOfOptionalHeader);

    if ((const uint8_t *)(ctx->sectionHeaders + ctx->fileHeader->numberOfSections) > (ctx->fileData + ctx->fileSize))
    {
        printf("There was an overflow in the header section\n");
        freeResources(ctx);
        return PE_ERROR_INVALID_SECTION_HEADER;
    }

    return PE_SUCCESS;
}

uint32_t RvaToOffset(uint32_t rva, const pe_analyzer *ctx)
{
    if (ctx == NULL || ctx->fileHeader == NULL || ctx->sectionHeaders == NULL)
    {
        return 0;
    }

    for (int i = 0; i < ctx->fileHeader->numberOfSections; i++)
    {
        const image_section_header *sec = &ctx->sectionHeaders[i];

        // Check if RVA falls within the virtual bounds of the section
        if (rva >= sec->virtualAddress && rva < sec->virtualAddress + sec->virtualSize)
        {
            uint32_t delta = rva - sec->virtualAddress;

            // Defensive check: Ensure the RVA is backed by physical file data
            // (handles cases where VirtualSize > SizeOfRawData due to BSS/zero-fill)
            if (delta >= sec->sizeOfRawData)
            {
                return 0;
            }

            // Translate virtual delta to physical disk offset
            return sec->pointerToRawData + delta;
        }
    }

    // RVA does not belong to any mapped section
    return 0;
}

// Cleans up allocated resources, unmaps memory, and closes file descriptors
void freeResources(pe_analyzer *ctx)
{
    // Safety check to ensure the context is not null
    if (ctx == NULL)
        return;

    // Unmap the file from memory if it was successfully mapped
    if (ctx->fileData != NULL)
        munmap((void *)ctx->fileData, ctx->fileSize);

    // Close the file descriptor if it is currently open
    if (ctx->fd >= 0)
        close(ctx->fd);

    // Reset fields to their default state to prevent dangling pointers or double frees
    ctx->fileData = NULL;
    ctx->dosHeader = NULL;
    ctx->fd = -1;
}