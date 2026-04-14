# Tiny Windows Executable Builder

This repository explores an attempt to create the smallest possible valid Windows Portable Executable (PE) files from scratch using Python. Specifically, these executables are constrained to the **GUI Subsystem** (`Subsystem = 2`), ensuring they run silently in the background without opening a command prompt or console window.

Instead of relying on a compiler or assembler, these Python scripts manually construct and write every byte of the PE layout (DOS header, COFF header, Optional Header, and Section header) directly to disk.

## Included Scripts

There are two distinct builders for 32-bit and 64-bit Windows architectures.

*   `build_tiny32.py`
    *   **Architecture:** 32-bit (`i386`)
    *   **Output:** `tiny32.exe`
    *   **Size:** 331 bytes
    *   **Details:** Uses a PE32 Optional Header. It maintains a minimum of 13 data directories to prevent modern Windows PE loaders from rejecting the executable.

*   `build_tiny64.py`
    *   **Architecture:** 64-bit (`AMD64`)
    *   **Output:** `tiny64.exe` 
    *   **Size:** 331 bytes
    *   **Details:** Uses a PE32+ Optional Header. Because of the way 64-bit fields are structured, it only requires 11 data directories to generate a valid loadable image.

## How It Works

By writing out the binary structures directly using Python's `struct` library, we can aggressively minimize the executable's footprint. The process drops any padding and features that aren't strictly required to appease the Windows kernel loader:

1.  **DOS Header:** Minimized to just the `MZ` signature and the `e_lfanew` pointer to the PE header.
2.  **Section Alignment:** Both `SectionAlignment` and `FileAlignment` are reduced to `4` (rather than the standard `0x1000` and `0x200`), allowing the headers and the code section to be compactly packed.
3.  **GUI Subsystem:** The Optional Header's `Subsystem` is set to `2` (Windows GUI), ensuring no console is spawned.
4.  **Payload:** The actual executable code is just a clean 3-byte exit sequence: `\x31\xc0\xc3` (`xor eax, eax ; ret`), which cleanly exits via the loader's `BaseThreadInitThunk`.

## Usage

Simply run either script using Python 3. No external dependencies are required.

```bash
# Build the 32-bit version
python build_tiny32.py

# Build the 64-bit version
python build_tiny64.py
```
