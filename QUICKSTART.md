# 🚀 Quick Start Guide

## 📋 Prerequisites
- Python 3.8+
- Virtual environment (recommended)

## ⚡ Installation

### 1. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Install System Dependencies (Ubuntu/Debian)
```bash
sudo apt install python3-tk
```

### 4. Generate Encryption Keys
```bash
python src/main.py --generate-keys
```

## 🎯 Usage Examples

### 🖥️ GUI Application (Recommended for Beginners)
```bash
python src/main.py --gui
```

### 📝 Command Line Examples

#### Hide Text Message
```bash
python src/main.py --hide "Your secret message" --cover examples/complete_cover.png --output output/secret.png
```

#### Extract Hidden Message
```bash
python src/main.py --extract output/secret.png
```

#### Analyze File (Check Processing Method)
```bash
python src/main.py --analyze somefile.pdf
```

#### Hide Large File (Auto-uploads to Google Drive)
```bash
python src/main.py --hide-file large_video.mp4 --cover examples/complete_cover.png --output output/stego.png
```

#### Use Password Protection
```bash
python src/main.py --hide "Secret" --cover examples/complete_cover.png --output output/protected.png --password
```

## 🔐 Google Drive Setup (For Large Files)

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create project → Enable Google Drive API
3. Create OAuth2 credentials (Desktop application)
4. Download as `credentials.json` in project root
5. Run GUI and click "Authenticate Google Drive"

## 🧪 Test the System
```bash
python examples/basic_usage.py
```

## 📊 Features

✅ **Intelligent File Routing**: Large files → Google Drive, Small files → Direct encryption  
✅ **Multi-Layer Security**: AES-256 + RSA-2048 encryption  
✅ **GUI & CLI**: Choose your preferred interface  
✅ **50+ File Types**: Automatic MIME type detection  
✅ **Password Protection**: Optional password-based encryption  
✅ **LSB Steganography**: Invisible data hiding in images  

## 🎯 Quick Demo

1. **Generate keys**: `python src/main.py --generate-keys`
2. **Run examples**: `python examples/basic_usage.py`
3. **Launch GUI**: `python src/main.py --gui`
4. **Hide text**: Select text → Choose image → Click "Hide Data"

That's it! Your steganography system is ready to use! 🎉
