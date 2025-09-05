# Image-based Steganography with Multi-Layer Encryption

## Overview

This project implements a secure communication system that combines encryption with steganography. Secret messages are first encrypted using multiple cryptographic algorithms and then embedded within digital images, making them invisible to unauthorized parties.

## Features

- **Dual-layer encryption**: AES (Advanced Encryption Standard) + RSA asymmetric encryption
- **LSB Steganography**: Least Significant Bit method for hiding encrypted data in images
- **Large file support**: Secure sharing of multimedia files via encrypted cloud links
- **End-to-end security**: Complete confidentiality and protection against unauthorized access

## Methodology

### 1. Message Encryption
- Messages are first encrypted using AES symmetric encryption
- The ciphertext is then encrypted again using RSA asymmetric encryption
- This dual-layer approach provides enhanced security

### 2. Message Embedding (Steganography)
- The double-encrypted ciphertext is embedded into a cover image
- Uses the Least Significant Bit (LSB) method to ensure invisibility
- The existence of the secret message remains hidden

### 3. Message Extraction & Decryption
- Embedded ciphertext is extracted from the image at the receiver's end
- Data is decrypted first using RSA, then AES to recover the original message

### 4. Large File Support
- Large files (images, videos, audio) are uploaded to secure cloud storage
- Encrypted cloud links are embedded in cover images
- Enables safe sharing of large multimedia files

## Project Structure

```
steganography-encryption-project/
├── src/
│   ├── steganography/     # LSB steganography implementation
│   ├── encryption/        # AES and RSA encryption modules
│   ├── cloud/            # Cloud storage integration
│   └── utils/            # Utility functions
├── tests/                # Unit and integration tests
├── docs/                 # Documentation
├── examples/             # Sample usage and test files
├── config/               # Configuration files
└── requirements.txt      # Python dependencies
```

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd steganography-encryption-project

# Install dependencies
pip install -r requirements.txt

# Run the application
python src/main.py
```

## Usage

[Usage examples will be added as the project develops]

## Security Considerations

- Uses industry-standard encryption algorithms (AES-256, RSA-2048)
- Implements secure key generation and management
- Supports multiple image formats for steganography
- Provides secure cloud storage integration

## Contributing

[Contributing guidelines will be added]

## License

[License information will be added]
