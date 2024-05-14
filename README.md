## Overview
Shields your computer by scanning files for pre-defined malicious code patterns.
Binary String Antivirus is a simple yet effective tool designed to detect file corruption by analyzing binary strings at the beginning of files. 
It checks for specific patterns that indicate potential corruption and provides alerts when such patterns are found.

 ## Features
- **Binary String Analysis:** The antivirus program examines the binary data at the beginning of files to identify patterns associated with corruption.
- **Corruption Detection:** By comparing binary strings against predefined patterns, the program determines whether a file may be corrupted.
- **Early Warning System:** Users are alerted promptly when potential corruption is detected, allowing them to take necessary actions to safeguard their data.


## How It Works
Binary String Antivirus employs a signature-based approach to detect corruption. It scans the initial portion of files for known patterns that commonly indicate corruption. If a match is found, the program notifies the user about the potential threat.

### Lookup table with binary patterns, lengths, and corresponding file extensions
<code>
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

</code>
