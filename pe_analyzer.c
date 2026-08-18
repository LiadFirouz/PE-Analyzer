#include "pe_analyzer.h"
#include <unistd.h>
#include <errno.h>

pe_status_t peLoad(pe_analyzer *ctx, const char *filepath)
{
    // Basic pointer safety checks
    if (ctx == NULL || filepath == NULL)
    {
        return PE_ERROR_FILE_OPEN;
    }

    int fd = open(filepath, O_RDONLY);

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
        perror("Error retrieving file status");
        close(fd);
        return PE_ERROR_STAT;
    }

    if (fileSize.st_size < (long)64)
    {
        fprintf(stderr, "File is too small (less than 64 bytes)\n");
        close(fd);
        return PE_ERROR_FILE_TOO_SMALL;
    }

    void *mappedMemory = mmap(NULL, fileSize.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mappedMemory == MAP_FAILED)
    {
        close(fd);
        return PE_ERROR_MMAP;
    }
    ctx->fileData = (const uint8_t *)mappedMemory;

    // Update our context struct on success
    ctx->fd = fd;
    ctx->fileSize = fileSize.st_size;

    ctx->dosHeader = ctx->fileData;

    return PE_SUCCESS;
}

void freeResources(pe_analyzer *ctx)
{
    if (ctx->fileData != NULL)
        munmap((void *)ctx->fileData, ctx->fileSize);
    if (ctx->fd >= 0)
        close(ctx->fd);
}