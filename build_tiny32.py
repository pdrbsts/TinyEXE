import struct, os, sys

# 13 is the minimum number of data directories for 32-bit Windows PE Loader
NUM_DATA_DIRS = int(sys.argv[1]) if len(sys.argv) > 1 else 13

IMAGE_BASE = 0x400000
SECT_ALIGN = 4
FILE_ALIGN = 4

def align(x, a): return (x + a - 1) & ~(a - 1)

# Entry code (x86): xor eax, eax ; ret
code = b'\x31\xc0\xc3'

# Sizes of fixed parts
dos_sz   = 0x40
coff_sz  = 24
opt_sz   = 96 + 8 * NUM_DATA_DIRS
sect_sz  = 40                 # one section header
headers_sz = dos_sz + coff_sz + opt_sz + sect_sz

# Place code immediately after headers (no padding since alignments = 4 and headers_sz % 4 == 0)
assert headers_sz % FILE_ALIGN == 0
code_raw_ptr = headers_sz
code_rva     = align(headers_sz, SECT_ALIGN)

total_size   = code_raw_ptr + len(code)
size_of_image   = align(code_rva + len(code), SECT_ALIGN)
size_of_headers = align(headers_sz, FILE_ALIGN)

# --- DOS header ---
dos = b'MZ' + b'\x00' * 0x3a + struct.pack('<I', dos_sz)

# --- COFF header ---
coff = b''
coff += b'PE\x00\x00'
coff += struct.pack('<H', 0x014C)          # Machine = I386
coff += struct.pack('<H', 1)               # NumberOfSections
coff += struct.pack('<I', 0)               # TimeDateStamp
coff += struct.pack('<I', 0)               # PointerToSymbolTable
coff += struct.pack('<I', 0)               # NumberOfSymbols
coff += struct.pack('<H', opt_sz)          # SizeOfOptionalHeader
coff += struct.pack('<H', 0x0102)          # EXECUTABLE_IMAGE | 32BIT_MACHINE
assert len(coff) == coff_sz

# --- Optional Header (PE32) ---
opt = b''
opt += struct.pack('<H', 0x010b)           # Magic = PE32
opt += struct.pack('<B', 0)                # MajorLinkerVersion
opt += struct.pack('<B', 0)                # MinorLinkerVersion
opt += struct.pack('<I', len(code))        # SizeOfCode
opt += struct.pack('<I', 0)                # SizeOfInitializedData
opt += struct.pack('<I', 0)                # SizeOfUninitializedData
opt += struct.pack('<I', code_rva)         # AddressOfEntryPoint
opt += struct.pack('<I', code_rva)         # BaseOfCode
opt += struct.pack('<I', 0)                # BaseOfData
opt += struct.pack('<I', IMAGE_BASE)       # ImageBase
opt += struct.pack('<I', SECT_ALIGN)       # SectionAlignment
opt += struct.pack('<I', FILE_ALIGN)       # FileAlignment
opt += struct.pack('<H', 6)                # MajorOSVersion
opt += struct.pack('<H', 0)                # MinorOSVersion
opt += struct.pack('<H', 0)                # MajorImageVersion
opt += struct.pack('<H', 0)                # MinorImageVersion
opt += struct.pack('<H', 6)                # MajorSubsystemVersion
opt += struct.pack('<H', 0)                # MinorSubsystemVersion
opt += struct.pack('<I', 0)                # Win32VersionValue
opt += struct.pack('<I', size_of_image)    # SizeOfImage
opt += struct.pack('<I', size_of_headers)  # SizeOfHeaders
opt += struct.pack('<I', 0)                # CheckSum
opt += struct.pack('<H', 2)                # Subsystem = GUI (no console)
opt += struct.pack('<H', 0)                # DllCharacteristics
opt += struct.pack('<I', 0x100000)         # SizeOfStackReserve
opt += struct.pack('<I', 0x1000)           # SizeOfStackCommit
opt += struct.pack('<I', 0x100000)         # SizeOfHeapReserve
opt += struct.pack('<I', 0x1000)           # SizeOfHeapCommit
opt += struct.pack('<I', 0)                # LoaderFlags
opt += struct.pack('<I', NUM_DATA_DIRS)    # NumberOfRvaAndSizes
opt += b'\x00' * (8 * NUM_DATA_DIRS)       # empty data directories
assert len(opt) == opt_sz

# --- Section header (one section ".t") ---
section = b''
section += b'.t\x00\x00\x00\x00\x00\x00'   # Name[8]
section += struct.pack('<I', len(code))    # VirtualSize
section += struct.pack('<I', code_rva)     # VirtualAddress
section += struct.pack('<I', len(code))    # SizeOfRawData
section += struct.pack('<I', code_raw_ptr) # PointerToRawData
section += struct.pack('<I', 0)            # PointerToRelocations
section += struct.pack('<I', 0)            # PointerToLinenumbers
section += struct.pack('<H', 0)            # NumberOfRelocations
section += struct.pack('<H', 0)            # NumberOfLinenumbers
# Characteristics: CNT_CODE | MEM_EXECUTE | MEM_READ
section += struct.pack('<I', 0x60000020)
assert len(section) == sect_sz

image = dos + coff + opt + section + code

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tiny32.exe')
with open(out, 'wb') as f:
    f.write(image)

print(f'wrote {out}: {len(image)} bytes')
