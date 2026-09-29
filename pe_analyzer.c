#include "pe_analyzer.h"
#include <unistd.h>
#include <errno.h>

// Forward Declarations for internal use
static pe_status_t IOLayout(pe_analyzer *ctx, const char *filepath);
static pe_status_t parsingLayout(pe_analyzer *ctx);
uint32_t RvaToOffset(uint32_t rva, const pe_analyzer *ctx);
static pe_status_t parseImportDirectory(const pe_analyzer *ctx);
static pe_status_t parseImportThunks(const pe_analyzer *ctx, const image_import_descriptor *importDesc);
pe_status_t parseExportDirectory(const pe_analyzer *ctx);
pe_status_t parseSectionHeaders(const pe_analyzer *ctx);

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

    parseImportDirectory(ctx);
    parseExportDirectory(ctx);
    parseSectionHeaders(ctx);
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

static pe_status_t parseImportThunks(const pe_analyzer *ctx, const image_import_descriptor *importDesc)
{
    uint32_t thunkRva = 0;
    if (importDesc->originalFirstThunk != 0)
        thunkRva = importDesc->originalFirstThunk;
    else if (importDesc->firstThunk != 0)
        thunkRva = importDesc->firstThunk;
    else
        return PE_SUCCESS;

    const uint32_t offset = RvaToOffset(thunkRva, ctx);
    if (offset == 0)
        return PE_ERROR_PARSE_IMPORT_THUNKS;

    const uint64_t *thunk = (const uint64_t *)(ctx->fileData + offset);
    uint32_t nameOffset;
    while (1)
    {
        if ((const uint8_t *)(thunk + 1) > ctx->fileData + ctx->fileSize)
            return PE_ERROR_PARSE_IMPORT_THUNKS;

        if (*thunk == 0)
            break;

        if (*thunk & IMAGE_ORDINAL_FLAG64)
            printf("    [Ordinal] %u\n", (uint32_t)(*thunk & 0xFFFF));
        else
        {
            nameOffset = RvaToOffset((uint32_t)(*thunk), ctx);
            if (nameOffset == 0)
                return PE_ERROR_PARSE_IMPORT_THUNKS;
            if (nameOffset + sizeof(uint16_t) + 1 > ctx->fileSize)
                return PE_ERROR_PARSE_IMPORT_THUNKS;
            const uint16_t *hint = (const uint16_t *)(ctx->fileData + nameOffset);
            const char *funcNamePtr = (const char *)(hint + 1);
            if (memchr(funcNamePtr, '\0', ctx->fileSize - (nameOffset + 2)) == NULL)
                return PE_ERROR_PARSE_IMPORT_THUNKS;
            printf("    [FuncName] %s (Hint: %u)\n", funcNamePtr, *hint);
        }
        thunk++;
    }
    return PE_SUCCESS;
}

static pe_status_t parseImportDirectory(const pe_analyzer *ctx)
{
    if (ctx->optHeader64->dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].virtualAddress == 0 || ctx->optHeader64->dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].size == 0)
        return PE_SUCCESS;

    uint32_t rawOffset = RvaToOffset(ctx->optHeader64->dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].virtualAddress, ctx);
    if (rawOffset == 0)
        return PE_ERROR_INVALID_IMPORT_TABLE;

    const image_import_descriptor *importDesc = (const image_import_descriptor *)(ctx->fileData + rawOffset);

    while (1)
    {
        if ((const uint8_t *)(importDesc + 1) > ctx->fileData + ctx->fileSize)
            return PE_ERROR_INVALID_IMPORT_TABLE;
        if (importDesc->name == 0 && importDesc->firstThunk == 0)
            break;

        uint32_t dllName = RvaToOffset(importDesc->name, ctx);
        if (dllName == 0)
            return PE_ERROR_INVALID_IMPORT_TABLE;

        const char *dllNameStr = (const char *)(ctx->fileData + dllName);
        int maxLen = ctx->fileSize - dllName;
        if (memchr(dllNameStr, '\0', maxLen) == NULL)
            return PE_ERROR_INVALID_IMPORT_TABLE;

        printf("%s\n", dllNameStr);
        parseImportThunks(ctx, importDesc);
        importDesc++;
    }
    return PE_SUCCESS;
}

pe_status_t parseExportDirectory(const pe_analyzer *ctx)
{
    const image_data_directory *dataDirectory = &ctx->optHeader64->dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dataDirectory->virtualAddress == 0 || dataDirectory->size == 0)
        return PE_SUCCESS;

    const uint32_t offsetDataDirectory = RvaToOffset(dataDirectory->virtualAddress, ctx);
    if (offsetDataDirectory == 0)
        return PE_ERROR_PARSE_EXPORT_DIRECTORY;

    if (offsetDataDirectory + sizeof(image_export_directory) > ctx->fileSize)
        return PE_ERROR_PARSE_EXPORT_DIRECTORY;

    const image_export_directory *exportDir = (const image_export_directory *)(ctx->fileData + offsetDataDirectory);

    uint32_t nameRva = exportDir->name;
    const uint32_t offsetName = RvaToOffset(nameRva, ctx);
    if (offsetName == 0)
        return PE_ERROR_PARSE_EXPORT_DIRECTORY;

    const char *moduleName = (const char *)(ctx->fileData + offsetName);
    if (memchr(moduleName, '\0', ctx->fileSize - offsetName) == NULL)
        return PE_ERROR_PARSE_EXPORT_DIRECTORY;

    printf("\n--- Export Directory: %s ---\n", moduleName);
    printf("Base Ordinal: %u | Functions: %u | Names: %u\n\n",
           exportDir->base, exportDir->numberOfFunctions, exportDir->numberOfNames);

    if (exportDir->numberOfFunctions == 0 || exportDir->addressOfFunctions == 0)
        return PE_SUCCESS;

    uint32_t offsetFunctions = RvaToOffset(exportDir->addressOfFunctions, ctx);
    if (offsetFunctions == 0)
        return PE_ERROR_PARSE_EXPORT_DIRECTORY;

    if ((uint64_t)offsetFunctions + ((uint64_t)exportDir->numberOfFunctions * sizeof(uint32_t)) > ctx->fileSize)
        return PE_ERROR_PARSE_EXPORT_DIRECTORY;

    const uint32_t *functions = (const uint32_t *)(ctx->fileData + offsetFunctions);

    if (exportDir->numberOfNames > 0)
    {
        if (exportDir->addressOfNames == 0 || exportDir->addressOfNameOrdinals == 0)
            return PE_ERROR_PARSE_EXPORT_DIRECTORY;

        uint32_t offsetNames = RvaToOffset(exportDir->addressOfNames, ctx);
        uint32_t offsetOrdinals = RvaToOffset(exportDir->addressOfNameOrdinals, ctx);

        if (offsetNames == 0 || offsetOrdinals == 0)
            return PE_ERROR_PARSE_EXPORT_DIRECTORY;

        if ((uint64_t)offsetNames + ((uint64_t)exportDir->numberOfNames * sizeof(uint32_t)) > ctx->fileSize ||
            (uint64_t)offsetOrdinals + ((uint64_t)exportDir->numberOfNames * sizeof(uint16_t)) > ctx->fileSize)
            return PE_ERROR_PARSE_EXPORT_DIRECTORY;

        const uint32_t *names = (const uint32_t *)(ctx->fileData + offsetNames);
        const uint16_t *ordinals = (const uint16_t *)(ctx->fileData + offsetOrdinals);

        for (uint32_t i = 0; i < exportDir->numberOfNames; i++)
        {
            uint32_t funcNameRva = names[i];
            uint32_t offsetNameRva = RvaToOffset(funcNameRva, ctx);
            if (offsetNameRva == 0)
                return PE_ERROR_PARSE_EXPORT_DIRECTORY;

            const char *funcName = (const char *)(ctx->fileData + offsetNameRva);
            if (memchr(funcName, '\0', ctx->fileSize - offsetNameRva) == NULL)
                return PE_ERROR_PARSE_EXPORT_DIRECTORY;

            uint16_t functionIndex = ordinals[i];
            if (functionIndex >= exportDir->numberOfFunctions)
                return PE_ERROR_PARSE_EXPORT_DIRECTORY;

            uint32_t funcRva = functions[functionIndex];
            uint32_t actualOrdinal = exportDir->base + functionIndex;

            if (funcRva >= dataDirectory->virtualAddress &&
                funcRva < (dataDirectory->virtualAddress + dataDirectory->size))
            {
                uint32_t offsetFuncRva = RvaToOffset(funcRva, ctx);
                if (offsetFuncRva == 0)
                    return PE_ERROR_PARSE_EXPORT_DIRECTORY;

                const char *forwardStr = (const char *)(ctx->fileData + offsetFuncRva);
                if (memchr(forwardStr, '\0', ctx->fileSize - offsetFuncRva) == NULL)
                    return PE_ERROR_PARSE_EXPORT_DIRECTORY;

                printf("    [Forwarded] Ordinal: %-5u | Name: %-35s -> %s\n",
                       actualOrdinal, funcName, forwardStr);
            }
            else
            {
                printf("    [Export]    Ordinal: %-5u | RVA: 0x%08X | Name: %s\n",
                       actualOrdinal, funcRva, funcName);
            }
        }
    }

    return PE_SUCCESS;
}

pe_status_t parseSectionHeaders(const pe_analyzer *ctx)
{
    uint32_t offsetSectionTable = ctx->dosHeader->e_lfanew + sizeof(uint32_t) + sizeof(image_file_header) + ctx->fileHeader->sizeOfOptionalHeader;
    if (ctx->fileHeader->numberOfSections == 0)
        return PE_ERROR_PARSE_SECTION_HEADER;

    if ((uint64_t)offsetSectionTable + ((uint64_t)ctx->fileHeader->numberOfSections * sizeof(image_section_header)) > ctx->fileSize)
        return PE_ERROR_PARSE_SECTION_HEADER;
    const image_section_header *sections = (const image_section_header *)(ctx->fileData + offsetSectionTable);

    for (uint32_t i = 0; i < ctx->fileHeader->numberOfSections; i++)
    {
        char safeName[9];
        memcpy(safeName, sections[i].name, 8);
        safeName[8] = '\0';
        if (sections[i].sizeOfRawData > 0)
        {
            uint64_t headersEnd = offsetSectionTable + ctx->fileHeader->numberOfSections * sizeof(image_section_header);
            if ((uint64_t)sections[i].pointerToRawData < headersEnd ||
                (uint64_t)sections[i].pointerToRawData + sections[i].sizeOfRawData > ctx->fileSize)
            {
                return PE_ERROR_INVALID_SECTION_HEADER;
            }
        }
        bool isExec = (sections[i].characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool isRead = (sections[i].characteristics & IMAGE_SCN_MEM_READ) != 0;
        bool isWrite = (sections[i].characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        char perms[4] = "---";

        if (isRead)
            perms[0] = 'R';
        if (isWrite)
            perms[1] = 'W';
        if (isExec)
            perms[2] = 'X';

        if (isWrite && isExec)
            printf("[!] WARNING: W^X Violation detected in section %s!\n", safeName);
        printf("  [%-8s] VA: 0x%08X | VSize: 0x%08X | RawOffset: 0x%08X | RawSize: 0x%08X | Perms: [%s]\n",
               safeName,
               sections[i].virtualAddress,
               sections[i].virtualSize,
               sections[i].pointerToRawData,
               sections[i].sizeOfRawData,
               perms);
    }

    return PE_SUCCESS;
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