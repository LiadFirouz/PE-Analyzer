# Static PE Analyzer

A low-level, static analysis engine written in C for parsing, validating, and inspecting Windows Portable Executable (PE32 / PE32+) binaries. This project implements strict defensive bounds checking, binary structure mapping, and virtual-to-physical address translation directly from disk images.

---

## 1. Architectural Overview: Disk vs. Memory Layout

The Windows OS Loader maps executable binaries into virtual memory using alignment boundaries that differ fundamentally from their on-disk representation:

* **File Alignment (Disk Layout):** Binaries are packed on disk in chunks aligned to `FileAlignment` (typically `0x200` / 512 bytes) to minimize physical storage. Positions in this state are designated as **File Offsets** (raw byte offsets from the start of the file).
* **Section Alignment (Memory Layout / RAM):** When loaded into memory, sections are mapped to virtual page boundaries matching `SectionAlignment` (typically `0x1000` / 4 KB). Positions in this state are designated as **Relative Virtual Addresses (RVA)** — offsets relative to the process base address (`ImageBase`).

====================== ON-DISK LAYOUT (Raw Offsets) ======================
[ DOS Header ] -> [ NT Headers ] -> [ Section Headers ] -> [ .text (Raw) ] -> [ .rdata (Raw) ]
(0x00 - 0x40)     (e_lfanew)                               (PointerToRawData)

====================== IN-MEMORY LAYOUT (Virtual Addresses) ==============
[ ImageBase + 0x0000 ] -> Headers
[ ImageBase + 0x1000 ] -> .text Section (VirtualAddress = 0x1000)
[ ImageBase + 0x2000 ] -> .rdata Section (VirtualAddress = 0x2000)


### RVA-to-File-Offset Translation (`RvaToOffset`)
Because a static analyzer inspects an unmapped disk image in memory via `mmap()`, all internal pointers formatted as RVAs must be translated into physical file offsets:

$$\text{File Offset} = (\text{RVA} - \text{Section.VirtualAddress}) + \text{Section.PointerToRawData}$$

#### Boundary Rules & Defensive Checks
1. **Section Containment:** A target RVA must satisfy $\text{Section.VirtualAddress} \le \text{RVA} < \text{Section.VirtualAddress} + \text{Section.VirtualSize}$.
2. **BSS / Zero-Fill Protection:** If $\text{VirtualSize} > \text{SizeOfRawData}$ (uninitialized data/BSS), any RVA where $(\text{RVA} - \text{Section.VirtualAddress}) \ge \text{SizeOfRawData}$ is unbacked by physical disk data and cannot be translated to a valid raw offset.

---

## 2. PE32+ (64-Bit) Binary Layout Specifications

### A. DOS Header (`IMAGE_DOS_HEADER` - 64 Bytes / `0x40`)
Preserved for backward compatibility with MS-DOS systems.

| Offset | Field | Type | Size | Description |
| :--- | :--- | :--- | :--- | :--- |
| `0x00` | `e_magic` | `uint16_t` | 2 Bytes | DOS Signature: `0x5A4D` (`"MZ"`). |
| `0x02` | *Padding/Reserved* | `uint8_t[58]` | 58 Bytes | DOS registers, relocations, and execution stub. |
| `0x3C` | `e_lfanew` | `uint32_t` | 4 Bytes | **File Offset** pointing to the start of `IMAGE_NT_HEADERS`. |

---

### B. NT Headers (`IMAGE_NT_HEADERS64` - 264 Bytes / `0x108`)

#### 1. Signature (4 Bytes)
* `0x00004550` (`"PE\0\0"`) - Identifies the PE file format.

#### 2. COFF File Header (`IMAGE_FILE_HEADER` - 20 Bytes / `0x14`)
Defines the target architecture and general binary attributes.

| Offset | Field | Type | Size | Description |
| :--- | :--- | :--- | :--- | :--- |
| `0x00` | `Machine` | `uint16_t` | 2 Bytes | Target architecture (`0x8664` = AMD64/x86_64, `0x014C` = i386). |
| `0x02` | `NumberOfSections` | `uint16_t` | 2 Bytes | Number of entries in the Section Header Table. |
| `0x04` | `TimeDateStamp` | `uint32_t` | 4 Bytes | POSIX compilation timestamp. |
| `0x08` | `PointerToSymbolTable` | `uint32_t` | 4 Bytes | COFF debug symbol table offset (usually `0`). |
| `0x0C` | `NumberOfSymbols` | `uint32_t` | 4 Bytes | Number of COFF debug symbols (usually `0`). |
| `0x10` | `SizeOfOptionalHeader`| `uint16_t` | 2 Bytes | Size of the Optional Header (`0xF0` / 240 bytes for PE32+). |
| `0x12` | `Characteristics` | `uint16_t` | 2 Bytes | Binary flags (`IMAGE_FILE_EXECUTABLE_IMAGE`, `IMAGE_FILE_DLL`). |

#### 3. Optional Header (`IMAGE_OPTIONAL_HEADER64` - 240 Bytes / `0xF0`)
Provides required execution parameters to the Windows loader.

* **Standard Fields (24 Bytes):**
  * `Magic` (`uint16_t`, 2B): `0x020B` (PE32+ / 64-bit), `0x010B` (PE32 / 32-bit).
  * `MajorLinkerVersion` / `MinorLinkerVersion` (`uint8_t` x 2, 2B): Linker toolset version.
  * `SizeOfCode` (`uint32_t`, 4B): Total size of executable code sections (`.text`).
  * `SizeOfInitializedData` (`uint32_t`, 4B): Total size of initialized data sections (`.data`, `.rdata`).
  * `SizeOfUninitializedData` (`uint32_t`, 4B): Size of BSS sections.
  * `AddressOfEntryPoint` (`uint32_t`, 4B): **RVA** of the first instruction executed by the main thread.
  * `BaseOfCode` (`uint32_t`, 4B): **RVA** of the code section base.

* **Windows-Specific Fields (88 Bytes):**
  * `ImageBase` (`uint64_t`, 8B): Preferred base address in virtual memory (default `0x140000000` for x64).
  * `SectionAlignment` (`uint32_t`, 4B): Page alignment in RAM (typically `0x1000` / 4 KB).
  * `FileAlignment` (`uint32_t`, 4B): Sector alignment on disk (typically `0x200` / 512 bytes).
  * `MajorOSVersion` / `MinorOSVersion` (`uint16_t` x 2, 4B): Minimum operating system requirements.
  * `SizeOfImage` (`uint32_t`, 4B): Total virtual address space required to load the image into RAM.
  * `SizeOfHeaders` (`uint32_t`, 4B): Combined size of DOS, NT, and Section headers on disk.
  * `CheckSum` (`uint32_t`, 4B): Kernel/Driver image integrity verification checksum.
  * `Subsystem` (`uint16_t`, 2B): Target environment (`2` = GUI, `3` = Console/CLI, `1` = Native Driver).
  * `DllCharacteristics` (`uint16_t`, 2B): Security flags (`0x0040` = Dynamic Base/ASLR, `0x0100` = NX/DEP, `0x4000` = Guard CF).
  * `SizeOfStackReserve` / `Commit` (`uint64_t` x 2, 16B): Thread stack allocation sizing.
  * `SizeOfHeapReserve` / `Commit` (`uint64_t` x 2, 16B): Default process heap allocation sizing.
  * `NumberOfRvaAndSizes` (`uint32_t`, 4B): Number of Data Directory entries (standard: `16`).

---

### C. Data Directories (`IMAGE_DATA_DIRECTORY[16]` - 128 Bytes)
An array of 16 entries at the end of the Optional Header. Each entry consists of an 8-byte structure:
* `VirtualAddress` (`uint32_t`, 4 Bytes): **RVA** of the directory structure.
* `Size` (`uint32_t`, 4 Bytes): Size of the directory structure in bytes.

| Index | Name | Description |
| :---: | :--- | :--- |
| **0** | `Export Table` | Functions exported by this module (primarily DLLs). |
| **1** | `Import Table` | Array of `IMAGE_IMPORT_DESCRIPTOR` structures for imported modules. |
| **2** | `Resource Table` | Icons, manifests, dialogs, and embedded media (`.rsrc`). |
| **3** | `Exception Table` | x64 Structured Exception Handling (SEH) unwind tables (`.pdata`). |
| **4** | `Certificate Table` | Authenticode digital signatures (**Uses File Offset, NOT RVA**). |
| **5** | `Base Relocation Table` | Delta fixup tables for relocatable images (`.reloc`). |
| **6** | `Debug Table` | Debugging information and CodeView PDB references. |
| **9** | `TLS Table` | Thread Local Storage callbacks and initialization templates (`.tls`). |
| **12**| `IAT` | Import Address Table containing resolved runtime pointers. |

---

### D. Section Headers (`IMAGE_SECTION_HEADER` - 40 Bytes / `0x28` each)
An array of descriptors defining the mapping from physical disk segments to virtual memory regions.

| Offset | Field | Type | Size | Description |
| :--- | :--- | :--- | :--- | :--- |
| `0x00` | `Name` | `uint8_t[8]` | 8 Bytes | 8-byte null-padded UTF-8/ASCII string (e.g., `".text\0\0\0"`). |
| `0x08` | `VirtualSize` | `uint32_t` | 4 Bytes | Actual size of the section once loaded in RAM. |
| `0x0C` | `VirtualAddress` | `uint32_t` | 4 Bytes | **RVA** where the section base is mapped in RAM. |
| `0x10` | `SizeOfRawData` | `uint32_t` | 4 Bytes | Size of section data stored physically in the file on disk. |
| `0x14` | `PointerToRawData`| `uint32_t` | 4 Bytes | **File Offset** to the section content on disk. |
| `0x18` | `PointerToRelocations` | `uint32_t` | 4 Bytes | Reserved for object files (always `0` in executables). |
| `0x1C` | `PointerToLinenumbers` | `uint32_t` | 4 Bytes | Reserved for COFF line numbers (deprecated, `0`). |
| `0x20` | `NumberOfRelocations` | `uint16_t` | 2 Bytes | Set to `0` for executable images. |
| `0x22` | `NumberOfLinenumbers` | `uint16_t` | 2 Bytes | Set to `0` for executable images. |
| `0x24` | `Characteristics` | `uint32_t` | 4 Bytes | Memory flags (`0x20000000` = Execute, `0x40000000` = Read, `0x80000000` = Write, `0x00000020` = Code). |

---

### E. Import Subsystem Architecture (`IMAGE_IMPORT_DESCRIPTOR`)
Located via `DataDirectory[1].VirtualAddress` $\to$ `RvaToOffset()`. Iterated as an array of 20-byte descriptors terminated by a NULL descriptor (all fields zeroed).

IMAGE_IMPORT_DESCRIPTOR (20 Bytes)
├── OriginalFirstThunk (RVA) ──> [ Import Lookup Table / INT ] ──> IMAGE_IMPORT_BY_NAME ("CreateFileW")
├── TimeDateStamp
├── ForwarderChain
├── Name (RVA) ───────────────> ASCII String ("KERNEL32.dll\0")
└── FirstThunk (RVA) ──────────> [ Import Address Table / IAT ] ──> Overwritten by Loader with absolute VA


#### Descriptor Fields
1. **`OriginalFirstThunk` (INT / ILT RVA):** Points to an array of `uint64_t` thunk entries containing function names or ordinal indicators. Remains unmodified during runtime.
2. **`Name` (RVA):** Points to the null-terminated ASCII string identifying the library module.
3. **`FirstThunk` (IAT RVA):** Points to an identical array of `uint64_t` entries on disk. At runtime, the loader resolves API pointers via `GetProcAddress` and overwrites the IAT entries with absolute virtual addresses.

#### Thunk Evaluation (64-Bit Entry: `uint64_t`)
* **Ordinal Import:** If the Most Significant Bit (MSB) is set (`val & 0x8000000000000000ULL`), the lower 16 bits (`val & 0xFFFF`) define the numeric export ordinal.
* **Named Import:** If the MSB is cleared, the value is an RVA pointing to an `IMAGE_IMPORT_BY_NAME` structure:
  * `Hint` (`uint16_t`, 2 Bytes): Export table index suggestion.
  * `Name` (`char[]`, Variable): Null-terminated ASCII function identifier.

---

## 3. Defensive Parser Implementation Guidelines

To prevent vulnerabilities (Out-of-Bounds Reads, Denial of Service via Malformed PE) when parsing untrusted binaries:

* **File Boundary Validation:** Verify `fileSize >= sizeof(IMAGE_DOS_HEADER)` before dereferencing `e_lfanew`.
* **NT Boundary Checks:** Ensure `dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) <= fileSize`.
* **Section Array Integrity:** Ensure `ntHeader + SizeOfOptionalHeader + (NumberOfSections * sizeof(IMAGE_SECTION_HEADER)) <= fileBase + fileSize`.
* **Integer Overflow Avoidance:** Always compare bounds using subtraction or validated boundaries (e.g., `offset <= fileSize - targetSize`) instead of unbounded pointer arithmetic additions.

* **Phase 1: Binary Mapping & Fundamental Headers (Completed)**
  * File descriptor validation, file sizing via `fstat`, and memory mapping with `mmap`.
  * DOS Header validation (`e_magic == 0x5A4D`) and `e_lfanew` boundary validation.
  * NT Header signature checking (`0x00004550` / `"PE\0\0"`).
  * COFF File Header validation (`Machine`, `NumberOfSections`, `Characteristics`).
  * Optional Header validation (`Magic == 0x020B`, `ImageBase`, `AddressOfEntryPoint`).
  * Section Headers enumeration and verification (`IMAGE_SECTION_HEADER`).

* **Phase 2: Virtual-to-Physical Translation & Data Directories (In Progress)**
  * Mathematical engine for translating Relative Virtual Addresses (RVAs) to raw disk offsets (`RvaToOffset`).
  * Mapping and extraction of the 16 `IMAGE_DATA_DIRECTORY` entries located in the Optional Header.
  * Validation of Data Directory targets against physical section boundaries.

* **Phase 3: Import Directory Analysis (IAT & INT)**
  * Parsing `IMAGE_IMPORT_DESCRIPTOR` arrays for referenced DLL modules.
  * Traversal of the Import Lookup Table (INT) and Import Address Table (IAT).
  * Resolving imports by name (`IMAGE_IMPORT_BY_NAME`) versus import by ordinal.

* **Phase 4: Export Directory Analysis**
  * Extraction of `IMAGE_EXPORT_DIRECTORY` for dynamic libraries (DLLs).
  * Resolving Address Table, Name Pointer Table, and Ordinal Table.
  * Detection of forwarded exports.

* **Phase 5: Advanced Structures (Relocations & TLS)**
  * Base Relocation block parsing (`.reloc`) for ASLR delta analysis.
  * Thread Local Storage (`.tls`) directory extraction for initialization callback identification.

* **Phase 6: Heuristics & Anomaly Detection**
  * Shannon Entropy calculation per section to detect packers, crypters, and compressed payloads.
  * Section header anomaly detection (e.g., W+X permissions, raw size vs. virtual size discrepancies).
  * Authenticode digital signature extraction via the Security Directory.

---

## 3. OS & Loader Mechanics: Disk vs. Memory Layout

The Windows OS Loader maps binaries from disk into RAM using distinct alignment rules:

* **File Alignment (Disk Image):** Stored contiguously in units aligned to `FileAlignment` (typically `0x200` / 512 bytes) to minimize physical storage. Locations are represented as **File Offsets** (raw byte indices from `fileData[0]`).
* **Section Alignment (RAM Image):** Mapped into virtual address space aligned to `SectionAlignment` (typically `0x1000` / 4 KB page boundaries). Locations are represented as **Relative Virtual Addresses (RVA)** — offsets relative to the base address (`ImageBase`).