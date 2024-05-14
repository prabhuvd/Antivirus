import os

# Lookup table with binary patterns, lengths, and corresponding file extensions
LOOKUP_TABLE = {
    '.exe': (b'\x4d\x5a', 2),  # Pattern and length for PE executable
    '.dll': (b'\x4d\x5a', 2),  # Pattern and length for DLL
    '.elf': (b'\x7fELF', 4),   # Pattern and length for ELF executable
    '.so': (b'\x7fELF', 4),    # Pattern and length for Shared Object
    '.jpg': (b'\xff\xd8\xff', 3),  # Pattern and length for JPEG
    '.png': (b'\x89PNG', 4),   # Pattern and length for PNG
    '.gif': (b'GIF87a', 6),    # Pattern and length for GIF87a
    '.gif': (b'GIF89a', 6),    # Pattern and length for GIF89a
    '.pdf': (b'\x25\x50\x44\x46', 4),  # Pattern and length for PDF
    '.zip': (b'\x50\x4b\x03\x04', 4),  # Pattern and length for ZIP
    '.gz': (b'\x1f\x8b', 2),   # Pattern and length for GZIP
    '.bz2': (b'\x42\x5a\x68', 3),  # Pattern and length for bzip2
    '.xz': (b'\xfd\x37\x7a\x58\x5a\x00', 6),  # Pattern and length for XZ
    '.7z': (b'\x37\x7a\xbc\xaf\x27\x1c', 6),  # Pattern and length for 7-Zip
    '.doc': (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 8),  # Pattern and length for DOC
    '.docx': (b'\x50\x4b\x03\x04', 4),  # Pattern and length for DOCX
    '.xls': (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 8),  # Pattern and length for XLS
    '.xlsx': (b'\x50\x4b\x03\x04', 4),  # Pattern and length for XLSX
    '.ppt': (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 8),  # Pattern and length for PPT
    '.pptx': (b'\x50\x4b\x03\x04', 4),  # Pattern and length for PPTX
    '.mp3': (b'\x49\x44\x33', 3),  # Pattern and length for MP3
    '.wav': (b'\x52\x49\x46\x46', 4),  # Pattern and length for WAV
    '.avi': (b'\x52\x49\x46\x46', 4),  # Pattern and length for AVI
    '.mov': (b'\x00\x00\x00\x14\x66\x74\x79\x70', 8),  # Pattern and length for MOV
    '.mkv': (b'\x1a\x45\xdf\xa3', 4),  # Pattern and length for MKV
    '.mp4': (b'\x00\x00\x00\x18\x66\x74\x79\x70', 8),  # Pattern and length for MP4
    # Add more entries as needed
}

SCANNED_FILES = []
SKIPPED_FILES = []
POTENTIAL_VIRUSES = []
TOTAL_SCANNED = 0

LOG_FILE = "scan_log.txt"


def scan_files(folder_path):
    global TOTAL_SCANNED  # Use the global variable for tracking
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            TOTAL_SCANNED += 1  # Increment the total scanned count
            SCANNED_FILES.append(file_path)  # Add file to the scanned list
            check_file(file_path)

    write_log_file()

    if SKIPPED_FILES:
        print("The following files were skipped due to unknown file extensions:")
        for skipped_file in SKIPPED_FILES:
            print(skipped_file)

    if POTENTIAL_VIRUSES:
        print("\nThe following files are potentially infected:")
        for infected_file in POTENTIAL_VIRUSES:
            print(infected_file)

    print(f"\nSummary:")
    print(f"Total files scanned: {TOTAL_SCANNED}")
    print(f"Files skipped: {len(SKIPPED_FILES)}")
    print(f"Potential viruses detected: {len(POTENTIAL_VIRUSES)}")


def check_file(file_path):
    try:
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()  # Convert extension to lowercase
        if ext in LOOKUP_TABLE:
            pattern, length = LOOKUP_TABLE[ext]
            with open(file_path, 'rb') as file:
                file_header = file.read(length)
                if file_header.startswith(pattern):
                    print(f"{file_path}: Good")
                else:
                    print(f"{file_path}: Potential virus detected")
                    POTENTIAL_VIRUSES.append(file_path)
        else:
            SKIPPED_FILES.append(file_path)
    except Exception as e:
        print(f"Error processing {file_path}: {e}")


def write_log_file():
    with open(LOG_FILE, "w", encoding="utf-8") as log:
        log.write("Scanned Files:\n")
        for file_path in SCANNED_FILES:
            log.write(f"{file_path}\n")

        log.write("\nSkipped Files:\n")
        for skipped_file in SKIPPED_FILES:
            log.write(f"{skipped_file}\n")

        log.write("\nPotential Viruses:\n")
        for infected_file in POTENTIAL_VIRUSES:
            log.write(f"{infected_file}\n")


# Example usage
scan_files('c:\\Program Files')