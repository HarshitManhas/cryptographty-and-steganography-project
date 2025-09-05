# Getting Started

## Quick Setup

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Generate RSA Keys**
   ```bash
   python src/main.py --generate-keys
   ```

3. **Hide a Secret Message**
   ```bash
   python src/main.py --hide "Your secret message" --cover your_image.png --output stego_image.png
   ```

4. **Extract the Message**
   ```bash
   python src/main.py --extract stego_image.png
   ```

## Run Examples

Run the comprehensive example script:
```bash
python examples/basic_usage.py
```

## Run Tests

```bash
pytest tests/
```

## Key Features Implemented

✅ **LSB Steganography**: Hide data in image pixels using Least Significant Bit method
✅ **Dual Encryption**: AES-256-CBC + RSA-2048 for maximum security
✅ **CLI Interface**: Easy-to-use command-line interface
✅ **Cloud Integration**: Template for uploading large files to cloud storage
✅ **Password Support**: Optional password-based AES key derivation
✅ **File Utilities**: Helper functions for file operations
✅ **Comprehensive Tests**: Unit tests for all major components

## Usage Examples

### Basic Message Hiding
```bash
# Hide a message
python src/main.py --hide "Secret message" --cover image.png --output hidden.png

# Extract the message
python src/main.py --extract hidden.png
```

### With Password Protection
```bash
# Hide with password
python src/main.py --hide "Secret message" --cover image.png --output hidden.png --password

# Extract with password
python src/main.py --extract hidden.png --password
```

### Check Image Capacity
```bash
python src/main.py --capacity your_image.png
```

### Hide File Links (Cloud Storage)
```bash
python src/main.py --hide-file large_document.pdf --cover image.png --output hidden.png
```

## Project Structure

```
steganography-encryption-project/
├── src/
│   ├── main.py                    # Main CLI application
│   ├── steganography/            # LSB steganography module
│   ├── encryption/               # Dual encryption module
│   ├── cloud/                    # Cloud storage integration
│   └── utils/                    # File utilities
├── tests/                        # Unit tests
├── examples/                     # Usage examples
├── docs/                         # Documentation
├── requirements.txt              # Dependencies
└── setup.py                     # Installation script
```

## Next Steps

1. **Try the Examples**: Run `python examples/basic_usage.py` to see all features in action
2. **Read the Documentation**: Check the README.md for detailed information
3. **Customize**: Modify the cloud storage integration for your preferred provider
4. **Extend**: Add new steganography methods or encryption algorithms
5. **Test**: Run the test suite to ensure everything works correctly

Happy encrypting! 🔐✨
