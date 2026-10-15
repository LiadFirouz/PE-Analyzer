/**
 * @file pe_analyzer.c
 * @brief Static Portable Executable (PE) File Analyzer Core Engine.
 *
 * This module implements low-level parsing, structural analysis, heuristic threat
 * detection, entropy calculation, and security mitigation checks for 32-bit and 64-bit
 * Windows PE binaries (PE32 / PE32+).
 */

#include "pe_analyzer.h"
#include <unistd.h>
#include <errno.h>

// Forward Declarations for internal implementation scope
static pe_status_t IOLayout(pe_analyzer *ctx, const char *filepath);
static pe_status_t parsingLayout(pe_analyzer *ctx, const char *filepath);
uint32_t RvaToOffset(uint32_t rva, const pe_analyzer *ctx);
static pe_status_t parseImportDirectory(const pe_analyzer *ctx, string_vector_t *imports);
static pe_status_t parseImportThunks(const pe_analyzer *ctx, const image_import_descriptor *importDesc, string_vector_t *imports);
pe_status_t parseExportDirectory(const pe_analyzer *ctx);
pe_status_t parseSectionHeaders(const pe_analyzer *ctx);
const char *threatTypeToString(pe_threat_type_t type);
pe_status_t initItems(string_vector_t *itemsVector);
pe_status_t pushItem(string_vector_t *itemsVector, const char *name);
void freeItems(string_vector_t *itemsVector);
void analyzeImportsHeuristics(const string_vector_t *imports, const heuristic_rule_t *rules, size_t ruleCount);
void analyzeSectionAnomalies(const pe_analyzer *ctx);
double calculateEntropy(const uint8_t *data, size_t size);
pe_status_t analyzeSecurityMitigations(const pe_analyzer *ctx, pe_report_t *report);
pe_status_t generateReport(const pe_analyzer *ctx, pe_report_t *report, const char *filepath);
const char *verdictToStr(pe_verdict_type_t r);

/**
 * @brief Primary entry point to load, map, and analyze a PE file.
 *
 * @param ctx Pointer to the primary analyzer context structure.
 * @param filepath Path to the target PE file on disk.
 * @return pe_status_t Execution status code (PE_SUCCESS on successful parsing).
 */
pe_status_t peLoad(pe_analyzer *ctx, const char *filepath)
{
    // Perform file I/O and map the file into memory
    pe_status_t status = IOLayout(ctx, filepath);
    if (status != PE_SUCCESS)
        return status;

    // Parse and validate the PE layout and headers
    return parsingLayout(ctx, filepath);
}

/**
 * @brief Handles file opening, boundary checks, and virtual memory mapping.
 *
 * Uses POSIX mmap() to map the raw binary directly into the process's address space
 * for efficient zero-copy pointer arithmetic during static binary analysis.
 *
 * @param ctx Pointer to the analyzer context.
 * @param filepath Disk path of the binary file.
 * @return pe_status_t PE_SUCCESS if successfully mapped, or appropriate error code.
 */
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

/**
 * @brief Parses mapped binary headers, validates signatures, and drives execution stages.
 *
 * Validates IMAGE_DOS_SIGNATURE ("MZ") and IMAGE_NT_SIGNATURE ("PE\0\0"), maps section
 * headers, and sequentially triggers import/export parsing, heuristic checks, section
 * anomaly detection, OS mitigation analysis, and final report generation.
 *
 * @param ctx Pointer to the analyzer context.
 * @param filepath Path string of the file being analyzed.
 * @return pe_status_t Status code representing validation/parsing state.
 */
static pe_status_t parsingLayout(pe_analyzer *ctx, const char *filepath)
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
    string_vector_t imports;
    initItems(&imports);
    parseImportDirectory(ctx, &imports);
    parseExportDirectory(ctx);
    analyzeImportsHeuristics(&imports, HEURISTIC_RULES, RULE_COUNT);
    parseSectionHeaders(ctx);
    analyzeSectionAnomalies(ctx);
    pe_report_t report = {0};
    analyzeSecurityMitigations(ctx, &report);
    generateReport(ctx, &report, filepath);
    freeItems(&imports);

    return PE_SUCCESS;
}

/**
 * @brief Translates a Relative Virtual Address (RVA) to a raw file offset on disk.
 *
 * Iterates through section headers to identify which section encapsulates the RVA
 * based on VirtualAddress and VirtualSize, then applies section delta math:
 * FileOffset = PointerToRawData + (RVA - VirtualAddress).
 *
 * @param rva Relative Virtual Address to translate.
 * @param ctx Pointer to the active PE analyzer context.
 * @return uint32_t Raw file offset, or 0 if RVA is unmapped or out of physical bounds.
 */
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

/**
 * @brief Parses thunk arrays (ILT/IAT) for a given imported DLL descriptor.
 *
 * Traverses thunk tables to extract function hints and names, or ordinal import flags,
 * pushing resolved API strings into the provided string vector.
 *
 * @param ctx Pointer to the active PE analyzer context.
 * @param importDesc Pointer to the current IMAGE_IMPORT_DESCRIPTOR.
 * @param imports Vector to store extracted import API names.
 * @return pe_status_t PE_SUCCESS on success, error code on corrupted bounds.
 */
static pe_status_t parseImportThunks(const pe_analyzer *ctx, const image_import_descriptor *importDesc, string_vector_t *imports)
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
            pushItem(imports, funcNamePtr);
        }
        thunk++;
    }
    return PE_SUCCESS;
}

/**
 * @brief Parses the Import Directory Data Directory (IMAGE_DIRECTORY_ENTRY_IMPORT).
 *
 * Iterates over the null-terminated array of IMAGE_IMPORT_DESCRIPTOR structs to discover
 * imported dynamic link libraries (DLLs) and their referenced functions.
 *
 * @param ctx Pointer to the active PE analyzer context.
 * @param imports Vector to store extracted import API names across all modules.
 * @return pe_status_t PE_SUCCESS on success, error code on parsing failure.
 */
static pe_status_t parseImportDirectory(const pe_analyzer *ctx, string_vector_t *imports)
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
        if (dllName >= ctx->fileSize)
            return PE_ERROR_INVALID_IMPORT_TABLE;
        size_t maxLen = ctx->fileSize - dllName;
        if (memchr(dllNameStr, '\0', maxLen) == NULL)
            return PE_ERROR_INVALID_IMPORT_TABLE;

        printf("%s\n", dllNameStr);
        parseImportThunks(ctx, importDesc, imports);
        importDesc++;
    }
    return PE_SUCCESS;
}

/**
 * @brief Parses the Export Directory Data Directory (IMAGE_DIRECTORY_ENTRY_EXPORT).
 *
 * Extracts exported functions, ordinals, exported API names, and handles detection of
 * forwarded exports (symbols pointing to external DLL functions).
 *
 * @param ctx Pointer to the active PE analyzer context.
 * @return pe_status_t PE_SUCCESS on successful export directory analysis.
 */
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

/**
 * @brief Parses section headers, prints memory permissions, and checks for W^X violations.
 *
 * Iterates through the IMAGE_SECTION_HEADER array, decodes section flags (Execute, Read, Write),
 * and flags W^X violations (sections marked as both Write and Execute).
 *
 * @param ctx Pointer to the active PE analyzer context.
 * @return pe_status_t PE_SUCCESS on successful section header parsing.
 */
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

/**
 * @brief Initializes a dynamic string vector structure.
 *
 * @param itemsVector Pointer to the string_vector_t structure to initialize.
 * @return pe_status_t PE_SUCCESS on valid initialization, PE_ERROR_NULL_POINTER if NULL.
 */
pe_status_t initItems(string_vector_t *itemsVector)
{
    if (itemsVector == NULL)
    {
        return PE_ERROR_NULL_POINTER;
    }

    itemsVector->items = NULL;
    itemsVector->capacity = 0;
    itemsVector->size = 0;
    return PE_SUCCESS;
}

/**
 * @brief Appends a string item into the dynamic string vector with dynamic growth factor.
 *
 * @param itemsVector Pointer to the string vector.
 * @param name Pointer to the string to store.
 * @return pe_status_t PE_SUCCESS on success, PE_ERROR_OUT_OF_MEMORY on realloc failure.
 */
pe_status_t pushItem(string_vector_t *itemsVector, const char *name)
{
    if (itemsVector == NULL || name == 0)
        return PE_ERROR_NULL_POINTER;

    if (itemsVector->size >= itemsVector->capacity)
    {
        uint32_t newCap = (itemsVector->capacity == 0) ? 64 : itemsVector->capacity * 2;
        size_t bytes = newCap * sizeof(const char *);
        const char **newItems = realloc(itemsVector->items, bytes);

        if (newItems == NULL)
            return PE_ERROR_OUT_OF_MEMORY;

        itemsVector->items = newItems;
        itemsVector->capacity = newCap;
    }
    itemsVector->items[itemsVector->size] = name;
    itemsVector->size++;
    return PE_SUCCESS;
}

/**
 * @brief Frees dynamically allocated memory in the string vector and resets state fields.
 *
 * @param itemsVector Pointer to the string vector to release.
 */
void freeItems(string_vector_t *itemsVector)
{
    if (itemsVector == NULL)
        return;

    free(itemsVector->items);
    itemsVector->capacity = 0;
    itemsVector->size = 0;
    itemsVector->items = NULL;
}

/**
 * @brief Matches imported API names against pre-defined heuristic threat rules.
 *
 * Evaluates import patterns (e.g., Process Injection, C2 networking, Keylogging)
 * and flags potential threat categories when threshold criteria are satisfied.
 *
 * @param imports Vector containing all imported API names.
 * @param rules Array of heuristic threat rules.
 * @param ruleCount Number of rules in the array.
 */
void analyzeImportsHeuristics(const string_vector_t *imports, const heuristic_rule_t *rules, size_t ruleCount)
{
    if (imports == NULL || rules == NULL || ruleCount == 0)
        return;
    for (size_t r = 0; r < ruleCount; r++)
    {
        size_t matchCount = 0;
        for (size_t i = 0; i < rules[r].apiCount; i++)
        {
            for (size_t j = 0; j < imports->size; j++)
            {
                if (strcmp(rules[r].apis[i], imports->items[j]) == 0)
                {
                    matchCount++;
                    break;
                }
            }
        }
        if (matchCount >= rules[r].threshold)
            printf("Threat: %s | Category: %s\n", rules[r].description, threatTypeToString(rules[r].threatCategory));
    }
}

/**
 * @brief Translates threat type enum to human-readable string descriptions.
 *
 * @param type Category enum value.
 * @return const char* String representation of the threat category.
 */
const char *threatTypeToString(pe_threat_type_t type)
{
    switch (type)
    {
    case INJECTION:
        return "Process Injection";
    case NETWORK_C2:
        return "Network / C2";
    case EVASION_PACKING:
        return "Evasion / Packing";
    case KEYLOGGING_SURVEILLANCE:
        return "Keylogging / Surveillance";
    default:
        return "Unknown Threat";
    }
}

/**
 * @brief Inspects PE sections for structural anomalies, size mismatches, and high entropy.
 *
 * Flags W^X permission violations, VirtualSize vs RawSize allocation mismatches (packer indicators),
 * and high Shannon entropy (H > 7.2) signaling encrypted/packed code or data payloads.
 *
 * @param ctx Pointer to the active PE analyzer context.
 */
void analyzeSectionAnomalies(const pe_analyzer *ctx)
{
    if (!(ctx != NULL && ctx->fileHeader != NULL && ctx->sectionHeaders != NULL))
        return;

    for (size_t i = 0; i < ctx->fileHeader->numberOfSections; i++)
    {
        printf("\n");
        const image_section_header *sec = &ctx->sectionHeaders[i];
        bool isWrite = (sec->characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        bool isExec = (sec->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        char safeName[9] = {0};
        memcpy(safeName, sec->name, 8);
        if (isWrite && isExec)
        {
            printf("[!] ANOMALY: W^X Violation in section [%s]\n", safeName);
        }
        if ((sec->sizeOfRawData > 0 && sec->virtualSize >= sec->sizeOfRawData * 3) ||
            (sec->sizeOfRawData == 0 && sec->virtualSize > 0))
        {
            printf("[!] ANOMALY: Size Mismatch [%s]\n", safeName);
        }
        double ent = 0.0;
        if (sec->sizeOfRawData > 0 && sec->pointerToRawData <= ctx->fileSize &&
            sec->sizeOfRawData <= ctx->fileSize - sec->pointerToRawData)
        {
            ent = calculateEntropy(ctx->fileData + sec->pointerToRawData, sec->sizeOfRawData);
        }
        if (ent > 7.2)
        {
            printf("[!] ANOMALY: High Entropy (%4.2f) in section [%s] -> Suspected Encrypted/Packed Data\n", ent, safeName);
        }
    }
}

/**
 * @brief Calculates Shannon Entropy over a raw binary buffer.
 *
 * Computes entropy using H = -sum(P(i) * log2(P(i))) across byte value distribution [0..255].
 * High entropy values (nearing 8.0) indicate compressed, packed, or encrypted data streams.
 *
 * @param data Pointer to the raw byte buffer.
 * @param size Buffer size in bytes.
 * @return double Calculated entropy score (0.0 to 8.0).
 */
double calculateEntropy(const uint8_t *data, size_t size)
{
    double entropy = 0;
    if (size == 0 || data == NULL)
        return 0;
    uint64_t frequencies[256] = {0};
    for (uint32_t i = 0; i < size; i++)
    {
        frequencies[data[i]]++;
    }

    for (uint32_t j = 0; j < 256; j++)
    {
        if (frequencies[j] != 0)
        {
            double p = (double)frequencies[j] / size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

/**
 * @brief Evaluates binary hardening features from Optional Header DllCharacteristics bitmasks.
 *
 * Inspects security mitigations including ASLR (DYNAMIC_BASE), DEP/NX (NX_COMPAT),
 * Control Flow Guard (GUARD_CF), SafeSEH (NO_SEH), and Terminal Server Awareness,
 * updating the analysis report state accordingly.
 *
 * @param ctx Pointer to the active PE analyzer context.
 * @param report Pointer to the destination report structure.
 * @return pe_status_t PE_SUCCESS on successful mitigation decoding.
 */
pe_status_t analyzeSecurityMitigations(const pe_analyzer *ctx, pe_report_t *report)
{
    if (ctx == NULL || ctx->optHeader64 == NULL)
        return PE_SECURITY_MITIGATIONS_FAILED;
    uint16_t dllC = ctx->optHeader64->dllCharacteristics;
    printf("\nEnabled Security Mitigations: \n");
    if (dllC & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA || dllC & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
    {
        report->has_aslr = true;
        printf("+ ASLR\n");
    }
    if (dllC & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
    {
        report->has_forceInteg = true;
        printf("+ Force Integrity\n");
    }
    if (dllC & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
    {
        report->has_DEPNX = true;
        printf("+ DEP/NX\n");
    }
    if (dllC & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)
    {
        report->has_noIsolation = true;
        printf("+ No Isolation\n");
    }
    if (dllC & IMAGE_DLLCHARACTERISTICS_NO_SEH)
    {
        report->has_safeSEH = true;
        printf("+ SafeSEH\n");
    }
    if (dllC & IMAGE_DLLCHARACTERISTICS_NO_BIND)
    {
        report->has_bind = true;
        printf("+ BIND\n");
    }
    if (dllC & IMAGE_DLLCHARACTERISTICS_APPCONTAINER)
    {
        report->has_appcontainer = true;
        printf("+ APPCONTAINER\n");
    }
    if (dllC & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER)
    {
        report->has_WDN = true;
        printf("+ WDM DRIVER\n");
    }
    if (dllC & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
    {
        report->has_CFG = true;
        printf("+ CFG\n");
    }
    if (dllC & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
    {
        report->has_teminalServerAware = true;
        printf("+ TERMINAL SERVER AWARE \n");
    }
    return PE_SUCCESS;
}

/**
 * @brief Converts verdict enum value into static string description.
 *
 * @param r Verdict enum (CLEAN, SUSPICIOUS, MALICIOUS).
 * @return const char* Human-readable verdict string.
 */
const char *verdictToStr(pe_verdict_type_t r)
{
    if (r == CLEAN)
    {
        return "Clean";
    }
    if (r == SUSPICIOUS)
    {
        return "Suspicious";
    }
    return "Malicious";
}

/**
 * @brief Aggregates findings, computes cumulative risk scores, and generates terminal summary report.
 *
 * Applies threat weighting rules for missing mitigations (ASLR: +20, DEP/NX: +20, CFG: +5, SafeSEH: +5),
 * maps cumulative score to verdict categories (0-40 Clean, 40-60 Suspicious, 60+ Malicious),
 * and formats an executive security summary.
 *
 * @param ctx Pointer to the active PE analyzer context.
 * @param report Pointer to the report structure.
 * @param filepath Path string of the analyzed executable.
 * @return pe_status_t PE_SUCCESS on successful report generation.
 */
pe_status_t generateReport(const pe_analyzer *ctx, pe_report_t *report, const char *filepath)
{
    if (ctx == NULL || ctx->fileHeader == NULL || report == NULL)
    {
        return PE_ERROR_NULL_POINTER;
    }
    report->risk_score = 0;

    if (!report->has_aslr)
    {
        report->risk_score += 20;
    }
    if (!report->has_DEPNX)
    {
        report->risk_score += 20;
    }

    if (!report->has_CFG)
    {
        report->risk_score += 5;
    }
    if (!report->has_safeSEH)
    {
        report->risk_score += 5;
    }

    if (report->risk_score < 40)
    {
        report->verdict = CLEAN;
    }
    else if (report->risk_score >= 40 && report->risk_score < 60)
    {
        report->verdict = SUSPICIOUS;
    }
    else
    {
        report->verdict = MALICIOUS;
    }

    const char *archStr = (ctx->fileHeader->machine == 0x8664) ? "x64 (PE32+)" : "x86 (PE32)";

    printf("==================================================\n"
           "                 PE ANALYSIS REPORT               \n"
           "==================================================\n");
    printf("Target File : [%s]\nArchitecture: [%s]\n--------------------------------------------------\n", filepath, archStr);
    printf("Risk Score : [%zu]\nVerdict: [%s]\n--------------------------------------------------\n", report->risk_score, verdictToStr(report->verdict));

    return PE_SUCCESS;
}

/**
 * @brief Unmaps virtual memory regions and closes open file descriptors.
 *
 * Performs clean resource teardown to prevent dangling file descriptors, memory leaks,
 * or invalid pointer accesses upon application shutdown or error exits.
 *
 * @param ctx Pointer to the PE analyzer context to clean up.
 */
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