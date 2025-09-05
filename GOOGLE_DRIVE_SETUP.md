# 🔐 Google Drive Setup Guide

## 📋 Quick Setup for Google Drive Integration

To use Google Drive for uploading and sharing large files securely, follow these steps:

### Step 1: Create Google Cloud Project
1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Click "Create Project" or use existing project
3. Give your project a name (e.g., "Steganography App")

### Step 2: Enable Google Drive API
1. In the Google Cloud Console, go to **APIs & Services** > **Library**
2. Search for "Google Drive API"
3. Click on it and press **"Enable"**

### Step 3: Create OAuth2 Credentials
1. Go to **APIs & Services** > **Credentials**
2. Click **"+ Create Credentials"** > **"OAuth client ID"**
3. If prompted, configure OAuth consent screen:
   - Choose **"External"** for testing
   - Fill in app name: "Steganography App"
   - Add your email as developer email
   - Skip optional fields and save
4. For OAuth client ID:
   - Choose **"Desktop application"**
   - Name it: "Steganography Desktop App"
   - Click **"Create"**

### Step 4: Download Credentials
1. After creating, you'll see a download button (⬇️)
2. Download the JSON file
3. **IMPORTANT**: Rename it to exactly `credentials.json`
4. Place it in your project root folder:
   ```
   steganography-encryption-project/
   ├── credentials.json  ← Put it here
   ├── src/
   ├── examples/
   └── ...
   ```

### Step 5: Test Authentication
1. Run the GUI: `python src/main.py --gui`
2. Click **"Sign In to Google Drive"**
3. Your browser will open for Google authentication
4. Sign in with your Google account
5. Grant permissions to the app
6. You should see **"Authenticated ✓"** in the GUI

## 🎯 Using Google Drive Upload

Once authenticated:

1. **Click "Upload File to Google Drive"** in the GUI
2. **Select any file** (images, videos, documents, etc.)
3. **Wait for upload** - you'll see progress
4. **Get shareable link** - automatically generated
5. **Ready for steganography** - link is added to text area
6. **Select cover image** and click "Hide Data"

## ✨ What Happens Behind the Scenes

1. **File Upload**: Your file goes to your Google Drive
2. **Shareable Link**: System gets a public link to your file
3. **Encryption**: Link gets encrypted with AES-256 + RSA-2048
4. **Steganography**: Encrypted link is hidden in your cover image
5. **Result**: Cover image looks normal but contains encrypted Google Drive link

## 🛠️ Troubleshooting

**❌ "Credentials file not found"**
- Make sure `credentials.json` is in the project root
- Check the filename is exactly `credentials.json`

**❌ "Google Drive API not enabled"**
- Go back to Google Cloud Console
- Enable the Google Drive API

**❌ "Authentication failed"**
- Try deleting `token.pickle` and re-authenticate
- Check your internet connection
- Make sure you're using the correct Google account

**❌ "Upload failed"**
- Check your Google Drive has enough storage space
- Verify internet connection
- Try with a smaller file first

## 📁 File Organization

The system automatically:
- Creates a **"SteganographyFiles"** folder in your Google Drive
- Uploads all files to this organized location
- Generates shareable links that work for anyone
- Maintains file organization and security

That's it! Your Google Drive integration is ready! 🚀
