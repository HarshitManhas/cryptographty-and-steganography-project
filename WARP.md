# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Prerequisites

- Python 3.8+ installed
- Google Cloud Console account (for Google Drive integration)
- OAuth2 credentials for Google Drive API
- Basic understanding of cryptography concepts

## Essential Commands

### Quick Start
```bash
# Install dependencies
pip install -r requirements.txt

# Generate RSA encryption keys
python src/main.py --generate-keys

# Launch GUI application (recommended for beginners)
python src/main.py --gui

# Run comprehensive examples
python examples/basic_usage.py
```

### Command Line Interface
```bash
# Analyze a file to determine processing method
python src/main.py --analyze /path/to/file.pdf

# Hide text message in image
python src/main.py --hide "Secret message" --cover image.png --output stego.png

# Hide file (automatically routes to Google Drive for large files)
python src/main.py --hide-file document.pdf --cover image.png --output stego.png

# Extract hidden data from image
python src/main.py --extract stego.png

# Check image capacity for steganography
python src/main.py --capacity image.png

# Use password protection
python src/main.py --hide "Secret" --cover image.png --output stego.png --password
```

### Google Drive Setup
```bash
# 1. Download OAuth2 credentials from Google Cloud Console
# 2. Save as 'credentials.json' in project root
# 3. Authenticate (opens browser for OAuth flow)
python -c "from src.cloud.cloud_storage import CloudStorage; c = CloudStorage(); c.authenticate()"
```

### Testing and Development
```bash
# Run unit tests
pytest tests/

# Run comprehensive examples
python examples/basic_usage.py

# Test Google Drive integration
python src/cloud/google_drive.py

# Test file utilities
python src/utils/file_utils.py
```

## Architecture Overview

This is an **advanced steganography system** that combines multi-layer encryption with intelligent file routing. The system automatically determines the best processing method based on file size and type, routing large files to Google Drive and small files to direct steganography.

### Core Components

**main.py** - Enhanced CLI application (605 lines):
- `SteganographyApp` class orchestrates all operations
- Intelligent file analysis and routing logic
- Support for GUI launch, file analysis, and cloud integration
- Handles both text input and file upload scenarios

**GUI Application** (`src/gui/main_gui.py`) - Full-featured Tkinter interface:
- User-friendly file and image selection
- Real-time status updates and logging
- Password protection options
- Automatic cloud storage recommendations
- Progress tracking for long operations

**Google Drive Integration** (`src/cloud/google_drive.py`) - Production-ready cloud storage:
- OAuth2 authentication with token persistence
- Automatic folder creation and file organization
- Shareable link generation with proper permissions
- File metadata tracking and integrity verification

**Enhanced File Utilities** (`src/utils/file_utils.py`) - Intelligent file processing:
- MIME type detection using python-magic (fallback to mimetypes)
- File size thresholds: 10MB (small), 100MB (large)
- Support for 50+ file types including videos, audio, documents
- Processing method recommendations: `direct_text`, `direct_encryption`, `cloud_upload`

**Dual Encryption System** (`src/encryption/dual_encryption.py`):
- AES-256-CBC for symmetric encryption
- RSA-2048 for asymmetric key protection
- PBKDF2 with SHA-256 for password-based key derivation
- Base64 encoding for safe data transmission

**LSB Steganography** (`src/steganography/lsb_steganography.py`):
- Least Significant Bit method for invisible data embedding
- Support for RGB images (PNG, JPEG, BMP, TIFF)
- Delimiter-based data extraction
- Capacity calculation and validation

### Processing Flow

1. **File Analysis**: System analyzes file size, type, and determines optimal processing method
2. **Routing Decision**:
   - **Large files (>10MB)** → Upload to Google Drive → Hide shareable link
   - **Small text files** → Direct encryption and steganography
   - **Small binary files** → Base64 encoding → Encryption → Steganography
3. **Encryption**: Dual-layer AES+RSA encryption applied to all data
4. **Steganography**: Encrypted data embedded in user-selected cover image
5. **Output**: Stego image contains hidden encrypted data or cloud link

### Key Design Patterns

**Intelligent File Routing**: The `get_processing_method()` function analyzes files and recommends:
- Files >10MB or specific types (video/audio/archives) → Google Drive
- Text files <10MB → Direct embedding
- Other small files → Direct embedding with base64 encoding

**Cloud Storage Abstraction**: `CloudStorage` class provides unified interface supporting multiple providers (currently Google Drive with demo fallback).

**GUI-CLI Hybrid Architecture**: Single codebase supports both command-line and graphical interfaces with shared backend logic.

## Configuration

### File Size Thresholds
```python
SMALL_FILE_THRESHOLD = 10 * 1024 * 1024   # 10 MB
LARGE_FILE_THRESHOLD = 100 * 1024 * 1024  # 100 MB
```

### Supported File Types

**Direct Processing** (small files):
- Text files: `.txt`, `.md`, `.py`, `.js`, etc.
- Small images: under 10MB
- Small documents: under 10MB

**Google Drive Upload** (large files):
- Videos: `.mp4`, `.avi`, `.mov`, `.mkv`, `.webm`
- Audio: `.mp3`, `.wav`, `.flac`, `.aac`, `.ogg`
- Archives: `.zip`, `.rar`, `.7z`, `.tar`, `.gz`
- Large documents: `.pdf`, `.docx`, `.pptx` (when large)

### Encryption Configuration
- **AES**: 256-bit key, CBC mode, PKCS7 padding
- **RSA**: 2048-bit keys, OAEP padding with SHA-256
- **Key derivation**: PBKDF2-HMAC-SHA256, 100,000 iterations
- **Encoding**: Base64 for all encrypted data

### Google Drive Settings
- **Folder**: Creates "SteganographyFiles" folder automatically
- **Permissions**: Files are shareable via link (view-only)
- **Authentication**: OAuth2 with local token caching
- **Credentials**: Requires `credentials.json` from Google Cloud Console

## Project Structure

```
steganography-encryption-project/
├── src/
│   ├── main.py                      # Enhanced CLI application (605 lines)
│   ├── gui/
│   │   ├── __init__.py             # GUI module init
│   │   └── main_gui.py             # Tkinter GUI application (603 lines)
│   ├── steganography/
│   │   ├── __init__.py
│   │   └── lsb_steganography.py    # LSB steganography implementation
│   ├── encryption/
│   │   ├── __init__.py
│   │   └── dual_encryption.py      # AES+RSA encryption system
│   ├── cloud/
│   │   ├── __init__.py
│   │   ├── cloud_storage.py        # Enhanced cloud storage interface
│   │   └── google_drive.py         # Google Drive integration (391 lines)
│   └── utils/
│       ├── __init__.py
│       └── file_utils.py           # Comprehensive file utilities (471 lines)
├── examples/
│   └── basic_usage.py              # Comprehensive usage examples
├── tests/
│   ├── __init__.py
│   └── test_encryption.py          # Unit tests
├── keys/                           # Generated RSA keys (auto-created)
├── output/                         # Generated stego images (auto-created)
├── temp/                           # Temporary files (auto-created)
├── requirements.txt                # Enhanced dependencies
├── setup.py                        # Installation script
├── credentials.json                # Google Drive OAuth2 credentials (user-provided)
├── token.pickle                    # Google Drive token cache (auto-generated)
├── README.md                       # Project documentation
└── WARP.md                         # This file
```

## Development Workflow

### Setting Up Google Drive Integration
1. Go to Google Cloud Console (console.cloud.google.com)
2. Create new project or select existing one
3. Enable Google Drive API
4. Create OAuth2 credentials (Desktop application)
5. Download credentials as `credentials.json`
6. Place in project root directory
7. Run authentication: `python src/main.py --gui` → "Authenticate Google Drive"

### File Processing Decision Tree
```
Input File
    ├─ Size > 10MB? ──── YES ──── Upload to Google Drive ──── Hide Link
    └─ NO
        ├─ Text file? ──── YES ──── Direct encryption ──── Hide Content
        └─ Binary file? ── YES ──── Base64 encode ──── Encrypt ──── Hide
```

### Adding New Cloud Providers
1. Create new class in `src/cloud/` (following GoogleDriveStorage pattern)
2. Update `CloudStorage.__init__()` to support new provider
3. Add provider-specific authentication and upload methods
4. Update configuration documentation

### GUI Development
The GUI is built with Tkinter and follows these patterns:
- **Threading**: All long operations run in separate threads to prevent UI freezing
- **Status updates**: Real-time progress bars and status messages
- **Error handling**: User-friendly error dialogs with detailed logging
- **File validation**: Automatic file type and size validation

## Usage Examples

### Basic Text Hiding
```bash
# CLI
python src/main.py --hide "Secret message" --cover photo.png --output hidden.png
python src/main.py --extract hidden.png

# GUI
python src/main.py --gui
# Use interface to select text, image, and hide data
```

### Large File Handling
```bash
# Analyze file first
python src/main.py --analyze large_video.mp4
# Output: Processing method: cloud_upload

# Hide large file (automatically uploads to Google Drive)
python src/main.py --hide-file large_video.mp4 --cover photo.png --output stego.png
```

### Password Protection
```bash
# With password (CLI)
python src/main.py --hide "Secret" --cover image.png --output stego.png --password

# GUI automatically prompts for password when option is checked
python src/main.py --gui
```

### Batch Operations
```bash
# Check capacity of multiple images
find . -name "*.png" -exec python src/main.py --capacity {} \;

# Analyze all files in directory
find /path/to/files -type f -exec python src/main.py --analyze {} \;
```

## Security Considerations

### Current Security Features
- **Dual-layer encryption**: AES-256 + RSA-2048
- **Secure key derivation**: PBKDF2 with 100,000 iterations
- **Google Drive security**: OAuth2 authentication, encrypted connections
- **No plaintext storage**: All sensitive data encrypted before storage

### Production Recommendations
1. **Key Management**: Use hardware security modules or key management services
2. **Certificate Validation**: Implement certificate pinning for Google Drive connections
3. **Audit Logging**: Add comprehensive audit trails for all operations
4. **Access Controls**: Implement role-based access controls
5. **Rate Limiting**: Add rate limiting for API operations

## Troubleshooting

### Common Issues

1. **Google Drive Authentication Fails**:
   ```bash
   # Check credentials file
   ls -la credentials.json
   # Re-download from Google Cloud Console if missing
   # Ensure Google Drive API is enabled
   ```

2. **Large File Upload Fails**:
   ```bash
   # Check file size and Google Drive quota
   python src/main.py --analyze your_large_file.mp4
   # Try with smaller file first
   ```

3. **GUI Won't Launch**:
   ```bash
   # Install GUI dependencies
   pip install tkinter-dnd2 figlet
   # Check Python tkinter installation
   python -c "import tkinter; print('Tkinter available')"
   ```

4. **File Type Not Detected**:
   ```bash
   # Install python-magic for better file detection
   pip install python-magic
   # Check file info
   python src/main.py --analyze mysterious_file.xyz
   ```

5. **Image Capacity Issues**:
   ```bash
   # Check image capacity before hiding large data
   python src/main.py --capacity cover_image.png
   # Use larger image or compress data
   ```

### Debug Mode
Enable verbose logging by modifying the logging level:
```python
# In any module
logging.basicConfig(level=logging.DEBUG)
```

## Performance Optimization

### File Size Recommendations
- **Cover images**: Use PNG format, minimum 800x600 resolution
- **Small files**: Process files under 10MB locally for speed
- **Large files**: Use Google Drive for files over 10MB
- **Batch operations**: Process multiple files sequentially, not parallel

### Memory Usage
- Large files are streamed during upload/download
- Image processing loads entire image into memory
- Encryption processes data in chunks to manage memory

## Important Constraints

### Technical Limitations
- **Image formats**: Only RGB images supported (PNG, JPEG, BMP, TIFF)
- **File size**: Cover image capacity limits amount of data that can be hidden
- **Google Drive**: Requires active internet connection and valid credentials
- **Platform**: GUI requires tkinter support (available on most Python installations)

### Security Limitations
- **Mock attestation**: Current implementation uses basic file validation
- **Self-signed approach**: Uses generated RSA keys (not CA-signed)
- **Local storage**: Private keys stored locally without additional encryption
- **Network security**: Relies on Google Drive's security for cloud operations
