/**
 * @file pe_analyzer.h
 * @brief Header file for the Portable Executable (PE) Static Analyzer.
 *
 * Contains macro definitions, Windows PE/COFF header structures, error status codes,
 * threat heuristics models, analysis report structures, and public API declarations.
 */

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
#include <math.h>

/** @brief Byte offset padding within the legacy DOS header up to e_lfanew. */
#define DOS_HEADER_PADDING 58

/** @brief Magic signature for valid MS-DOS headers ("MZ" -> 0x5A4D in Little-Endian). */
#define IMAGE_DOS_SIGNATURE 0x5A4D

/** @brief Magic signature for valid PE NT headers ("PE\0\0" -> 0x00004550 in Little-Endian). */
#define IMAGE_NT_SIGNATURE 0x00004550

/** @brief Magic number identifying 32-bit PE Optional Header (PE32). */
#define PE32 0x010B

/** @brief Magic number identifying 64-bit PE Optional Header (PE32+). */
#define PE32_PLUS 0x020B

/** @brief Fixed length of section names in the Section Header table (8 bytes, non-null terminated if 8 chars). */
#define IMAGE_SIZEOF_SHORT_NAME 8

/** @brief Mask to test if an Import Thunk entry imports a function by Ordinal (64-bit). */
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000ULL

/** @name Data Directory Table Indices
 *  Indices into the Optional Header's DataDirectory array.
 *  @{
 */
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0      /**< Export Directory */
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1      /**< Import Directory */
#define IMAGE_DIRECTORY_ENTRY_RESOURCE 2    /**< Resource Directory */
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3   /**< Exception Directory */
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4    /**< Security / Digital Signature Directory */
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5   /**< Base Relocation Directory */
#define IMAGE_DIRECTORY_ENTRY_DEBUG 6       /**< Debug Directory */
#define IMAGE_DIRECTORY_ENTRY_TLS 7         /**< Thread Local Storage (TLS) Directory */
#define IMAGE_DIRECTORY_ENTRY_IAT 12        /**< Import Address Table (IAT) */
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16 /**< Total Data Directory entries */
/** @} */

/** @name Section Permission Characteristics Bitmasks
 *  Flag masks indicating memory access permissions for PE sections.
 *  @{
 */
#define IMAGE_SCN_MEM_EXECUTE 0x20000000 /**< Section is executable in memory */
#define IMAGE_SCN_MEM_READ 0x40000000    /**< Section is readable in memory */
#define IMAGE_SCN_MEM_WRITE 0x80000000   /**< Section is writable in memory */
/** @} */

/** @name DllCharacteristics OS Security Mitigation Flags
 *  Bitmask values inside the Optional Header reflecting binary hardening settings.
 *  @{
 */
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA 0x0020       // ASLR: 64-bit entropy
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040          // ASLR: DLL can be relocated
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY 0x0080       // Code integrity checks enforced
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT 0x0100             // DEP: Data Execution Prevention
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 0x0200          // Isolation aware
#define IMAGE_DLLCHARACTERISTICS_NO_SEH 0x0400                // SafeSEH: No Structured Exception Handling
#define IMAGE_DLLCHARACTERISTICS_NO_BIND 0x0800               // Do not bind the image
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER 0x1000          // Image must run in an AppContainer
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER 0x2000            // WDM driver
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF 0x4000              // Control Flow Guard (CFG)
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 0x8000 // Terminal Server aware
/** @} */

/** @name Machine Architecture Types
 *  @{
 */
#define IMAGE_FILE_MACHINE_AMD64 0x8664 /**< x86-64 / x64 Architecture */
#define IMAGE_FILE_MACHINE_I386 0x014c  /**< Intel 386 / x86 Architecture */
/** @} */

/**
 * @brief Return status codes for analyzer operations and error handling.
 */
typedef enum
{
    PE_SUCCESS,                      /**< Operation completed successfully */
    PE_ERROR_FILE_OPEN,              /**< Failed to open file on disk */
    PE_ERROR_STAT,                   /**< Failed to query file status or size */
    PE_ERROR_MMAP,                   /**< Memory mapping (mmap) failed */
    PE_ERROR_FILE_TOO_SMALL,         /**< File size below minimum DOS header size (64 bytes) */
    PE_ERROR_INVALID_DOS_SIGNATURE,  /**< Missing 'MZ' DOS signature */
    PE_ERROR_INVALID_NT_OFFSET,      /**< Invalid e_lfanew offset pointing outside mapped bounds */
    PE_ERROR_INVALID_PE_SIGNATURE,   /**< Missing 'PE\0\0' NT signature */
    PE_ERROR_INVALID_HEADER_OFFSET,  /**< Header size overflow or invalid offset */
    PE_ERROR_INVALID_SECTION_HEADER, /**< Corrupted or out-of-bounds section header table */
    PE_ERROR_INVALID_IMPORT_TABLE,   /**< Corrupted or unmapped Import Directory */
    PE_ERROR_PARSE_IMPORT_THUNKS,    /**< Error reading Import Lookup/Address thunks */
    PE_ERROR_PARSE_EXPORT_DIRECTORY, /**< Error parsing Export Directory tables */
    PE_ERROR_PARSE_SECTION_HEADER,   /**< Error reading section table entry */
    PE_ERROR_NULL_POINTER,           /**< Null pointer argument passed to function */
    PE_ERROR_OUT_OF_MEMORY,          /**< Memory allocation failure */
    PE_SECURITY_MITIGATIONS_FAILED   /**< Failure during security mitigations analysis */
} pe_status_t;

/**
 * @brief Categories for heuristic threat detection.
 */
typedef enum
{
    NETWORK_C2,             /**< Command & Control / Remote Communication */
    INJECTION,              /**< Process Injection / Memory Manipulation */
    EVASION_PACKING,        /**< Evasion / Packer Detection */
    KEYLOGGING_SURVEILLANCE /**< Keylogging / System Surveillance */
} pe_threat_type_t;

/**
 * @brief Assessment verdicts for final threat report evaluation.
 */
typedef enum
{
    CLEAN,      /**< Low risk score (< 40): Benign or standard binary */
    SUSPICIOUS, /**< Medium risk score (40-59): Anomalies detected */
    MALICIOUS   /**< High risk score (60+): Severe threats or missing critical mitigations */
} pe_verdict_type_t;

/**
 * @brief MS-DOS Header (IMAGE_DOS_HEADER).
 * Sitting at the beginning of all PE binaries for backward compatibility.
 */
typedef struct image_dos_header
{
    uint16_t e_magic;                    /**< Magic number ('MZ') */
    uint8_t padding[DOS_HEADER_PADDING]; /**< Unused historical DOS fields */
    uint32_t e_lfanew;                   /**< File offset to the PE NT Header */
} __attribute__((packed)) image_dos_header;

/**
 * @brief COFF File Header (IMAGE_FILE_HEADER).
 * Contains general physical properties of the target architecture and layout.
 */
typedef struct image_file_header
{
    uint16_t machine;              /**< Target architecture CPU type */
    uint16_t numberOfSections;     /**< Count of section entries in Section Table */
    uint32_t timeDateStamp;        /**< Build timestamp (seconds since Unix Epoch) */
    uint32_t pointerToSymbolTable; /**< File offset to COFF symbol table (deprecated in PE) */
    uint32_t numberOfSymbols;      /**< Number of symbols in COFF table (deprecated) */
    uint16_t sizeOfOptionalHeader; /**< Size of following Optional Header struct */
    uint16_t characteristics;      /**< Binary characteristic flags (e.g., Executable, DLL) */
} __attribute__((packed)) image_file_header;

/**
 * @brief Data Directory entry specifying location and size of PE tables.
 */
typedef struct image_data_directory
{
    uint32_t virtualAddress; /**< Relative Virtual Address (RVA) of the directory table */
    uint32_t size;           /**< Size in bytes of the directory table */
} __attribute__((packed)) image_data_directory;

/**
 * @brief Import Descriptor structure (IMAGE_IMPORT_DESCRIPTOR).
 * Represents an imported dynamic library (DLL).
 */
typedef struct image_import_descriptor
{
    uint32_t originalFirstThunk; /**< RVA to Import Lookup Table (ILT) */
    uint32_t timeDateStamp;      /**< Timestamp or 0/1 depending on binding status */
    uint32_t forwarderChain;     /**< Index of first forwarder chain entry */
    uint32_t name;               /**< RVA to ASCII string containing DLL name */
    uint32_t firstThunk;         /**< RVA to Import Address Table (IAT) */
} __attribute__((packed)) image_import_descriptor;

/**
 * @brief Import By Name entry structure (IMAGE_IMPORT_BY_NAME).
 */
typedef struct image_import_by_name
{
    uint16_t hint;   /**< Export table name index hint */
    uint8_t name[1]; /**< Null-terminated ASCII function name (variable length) */
} __attribute__((packed)) image_import_by_name;

/**
 * @brief Optional Header structure for 64-bit binaries (IMAGE_OPTIONAL_HEADER64).
 * Holds logical layout data, entry point, image base, and the DataDirectory array.
 */
typedef struct image_optional_header_64
{
    uint16_t magic;                         /**< Magic identifier (0x020B for PE32+) */
    uint8_t majorLinkerVersion;             /**< Major version of linker */
    uint8_t minorLinkerVersion;             /**< Minor version of linker */
    uint32_t sizeOfCode;                    /**< Total size of code (.text) sections */
    uint32_t sizeOfInitializedData;         /**< Total size of initialized data sections */
    uint32_t sizeOfUninitializedData;       /**< Total size of BSS sections */
    uint32_t addressOfEntryPoint;           /**< Entry point RVA (starting execution offset) */
    uint32_t baseOfCode;                    /**< Base RVA of code section */
    uint64_t imageBase;                     /**< Preferred virtual load address in memory */
    uint32_t sectionAlignment;              /**< Memory alignment factor for sections */
    uint32_t fileAlignment;                 /**< Raw disk alignment factor for sections */
    uint16_t majorOperatingSystemVersion;   /**< OS major version required */
    uint16_t minorOperatingSystemVersion;   /**< OS minor version required */
    uint16_t majorImageVersion;             /**< Major binary version */
    uint16_t minorImageVersion;             /**< Minor binary version */
    uint16_t majorSubsystemVersion;         /**< Subsystem major version */
    uint16_t minorSubsystemVersion;         /**< Subsystem minor version */
    uint32_t win32VersionValue;             /**< Reserved field */
    uint32_t sizeOfImage;                   /**< Total virtual memory footprint of image */
    uint32_t sizeOfHeaders;                 /**< Combined size of all headers aligned to fileAlignment */
    uint32_t checkSum;                      /**< Image checksum */
    uint16_t subsystem;                     /**< Target subsystem (e.g., GUI, Console) */
    uint16_t dllCharacteristics;            /**< OS security mitigation and runtime flags */
    uint64_t sizeOfStackReserve;            /**< Stack size reserve */
    uint64_t sizeOfStackCommit;             /**< Stack initial commit size */
    uint64_t sizeOfHeapReserve;             /**< Local heap size reserve */
    uint64_t sizeOfHeapCommit;              /**< Local heap initial commit size */
    uint32_t loaderFlags;                   /**< Obsolete loader flags */
    uint32_t numberOfRvaAndSizes;           /**< Count of DataDirectory entries (typically 16) */
    image_data_directory dataDirectory[16]; /**< Array of Data Directory structures */
} __attribute__((packed)) image_optional_header_64;

/**
 * @brief Section Header structure (IMAGE_SECTION_HEADER).
 * Defines spatial bounds and permissions for an individual binary section.
 */
typedef struct image_section_header
{
    uint8_t name[IMAGE_SIZEOF_SHORT_NAME]; /**< UTF-8/ASCII section name (8 bytes max) */
    uint32_t virtualSize;                  /**< Total size of section when loaded into memory */
    uint32_t virtualAddress;               /**< RVA of section in memory */
    uint32_t sizeOfRawData;                /**< Size of section data on disk */
    uint32_t pointerToRawData;             /**< Raw file offset to section data on disk */
    uint32_t pointerToRelocations;         /**< File offset to COFF relocations */
    uint32_t pointerToLinenumbers;         /**< File offset to COFF line numbers */
    uint16_t numberOfRelocations;          /**< Count of relocations */
    uint16_t numberOfLinenumbers;          /**< Count of line numbers */
    uint32_t characteristics;              /**< Memory permission and section attribute flags */
} __attribute__((packed)) image_section_header;

/**
 * @brief Export Directory structure (IMAGE_EXPORT_DIRECTORY).
 * Contains symbol information for functions exported by DLLs or executables.
 */
typedef struct image_export_directory
{
    uint32_t characteristics;       /**< Reserved field */
    uint32_t timeDateStamp;         /**< Export creation timestamp */
    uint16_t majorVersion;          /**< Major version */
    uint16_t minorVersion;          /**< Minor version */
    uint32_t name;                  /**< RVA to ASCII string of DLL name */
    uint32_t base;                  /**< Starting ordinal number for exports */
    uint32_t numberOfFunctions;     /**< Total count of exported functions */
    uint32_t numberOfNames;         /**< Total count of exported function names */
    uint32_t addressOfFunctions;    /**< RVA to Export Address Table (EAT) */
    uint32_t addressOfNames;        /**< RVA to Export Name Pointer Table */
    uint32_t addressOfNameOrdinals; /**< RVA to Export Ordinal Table */
} __attribute__((packed)) image_export_directory;

/**
 * @brief Master Analysis Context structure.
 * Holds mapped binary memory pointers, file descriptors, and header references.
 */
typedef struct pe_analyzer
{
    const uint8_t *fileData;                     /**< Base pointer to mapped virtual memory */
    const image_dos_header *dosHeader;           /**< Pointer to DOS Header */
    const uint8_t *ntHeader;                     /**< Raw pointer to start of NT Header */
    const image_file_header *fileHeader;         /**< Pointer to COFF File Header */
    const image_optional_header_64 *optHeader64; /**< Pointer to 64-bit Optional Header */
    const image_section_header *sectionHeaders;  /**< Pointer to Section Header array */
    size_t fileSize;                             /**< Total file size in bytes */
    int fd;                                      /**< POSIX file descriptor */
    const uint8_t *optHeader;                    /**< Raw pointer to Optional Header */
} pe_analyzer;

/**
 * @brief Dynamic string vector for managing collections of strings.
 */
typedef struct string_vector_t
{
    const char **items; /**< Pointer to dynamic array of string pointers */
    size_t size;        /**< Current count of items stored */
    size_t capacity;    /**< Total allocated capacity */
} string_vector_t;

/**
 * @brief Rule structure for heuristic API threat detection.
 */
typedef struct heuristic_rule_t
{
    pe_threat_type_t threatCategory; /**< Associated threat category enum */
    const char *description;         /**< Rule description string */
    const char **apis;               /**< Array of API names to match against imports */
    size_t apiCount;                 /**< Count of target APIs in the array */
    size_t threshold;                /**< Minimum API match count to trigger threat rule */
} heuristic_rule_t;

/**
 * @brief Consolidated Security Report and Risk Scoring structure.
 */
typedef struct pe_report_t
{
    const char *filepath;        /**< Path to target binary */
    pe_verdict_type_t verdict;   /**< Final calculated assessment verdict */
    size_t risk_score;           /**< Cumulative numerical risk score */
    size_t anomaliesCounter;     /**< Total count of detected structural anomalies */
    string_vector_t findings;    /**< Vector of finding description strings */
    bool has_aslr;               /**< ASLR mitigation state */
    bool has_forceInteg;         /**< Force Integrity check state */
    bool has_DEPNX;              /**< DEP/NX mitigation state */
    bool has_noIsolation;        /**< No Isolation state */
    bool has_safeSEH;            /**< SafeSEH mitigation state */
    bool has_bind;               /**< Bind state */
    bool has_appcontainer;       /**< AppContainer requirement state */
    bool has_WDN;                /**< WDM Driver flag state */
    bool has_CFG;                /**< Control Flow Guard mitigation state */
    bool has_teminalServerAware; /**< Terminal Server Awareness state */
} pe_report_t;

/** @brief Sample APIs targeted for Process Injection detection. */
static const char *injection_apis[] = {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess"};

/** @brief Sample APIs targeted for Network / C2 detection. */
static const char *network_apis[] = {
    "InternetOpenA", "HttpSendRequestA", "WSAStartup", "URLDownloadToFileA"};

/** @brief Heuristic rules definition table. */
static const heuristic_rule_t HEURISTIC_RULES[] = {
    {INJECTION, "Process Injection Capability", injection_apis, 4, 2},
    {NETWORK_C2, "Network / C2 Communication Capability", network_apis, 4, 1}};

/** @brief Total count of defined heuristic rules. */
static const size_t RULE_COUNT = sizeof(HEURISTIC_RULES) / sizeof(HEURISTIC_RULES[0]);

// 4. Finally - Declaration of public functions only!

/**
 * @brief Loads a PE binary, maps it into memory, and executes full static analysis.
 *
 * @param ctx Pointer to initialized analyzer context structure.
 * @param filepath Path to the PE file on disk.
 * @return pe_status_t Status code (PE_SUCCESS on success).
 */
pe_status_t peLoad(pe_analyzer *ctx, const char *filepath);

/**
 * @brief Releases mapped memory regions and closes open file descriptors.
 *
 * @param ctx Pointer to the analyzer context.
 */
void freeResources(pe_analyzer *ctx);

#endif