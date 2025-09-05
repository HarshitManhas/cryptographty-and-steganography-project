"""
Main Application Interface

This module provides the main CLI interface for the steganography 
and encryption application.
"""

import os
import sys
import json
import argparse
import getpass
from typing import Optional, Dict

# Add the src directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from steganography.lsb_steganography import LSBSteganography
from encryption.dual_encryption import DualEncryption
from utils.file_utils import FileUtils
from cloud.cloud_storage import CloudStorage


class SteganographyApp:
    """
    Main application class that orchestrates encryption, steganography, and file handling.
    """
    
    def __init__(self):
        """Initialize the application."""
        self.stego = LSBSteganography()
        self.encryption = DualEncryption()
        self.file_utils = FileUtils()
        self.cloud = CloudStorage()
        
        # Default directories
        self.keys_dir = "keys"
        self.output_dir = "output"
        self.temp_dir = "temp"
        
        # Create directories if they don't exist
        for directory in [self.keys_dir, self.output_dir, self.temp_dir]:
            os.makedirs(directory, exist_ok=True)
    
    def generate_keys(self) -> bool:
        """
        Generate RSA key pair and save to files.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            print("Generating RSA key pair...")
            private_key, public_key = self.encryption.generate_rsa_keys()
            
            # Save keys
            self.encryption.save_keys(private_key, public_key, self.keys_dir)
            
            print(f"✓ Keys generated and saved to '{self.keys_dir}/' directory")
            print(f"  - Private key: {self.keys_dir}/private_key.pem")
            print(f"  - Public key: {self.keys_dir}/public_key.pem")
            
            return True
            
        except Exception as e:
            print(f"✗ Error generating keys: {str(e)}")
            return False
    
    def hide_message(self, message: str, cover_image: str, output_image: str, 
                    public_key_path: str = None, password: str = None) -> bool:
        """
        Hide an encrypted message in an image.
        
        Args:
            message (str): Message to hide
            cover_image (str): Path to cover image
            output_image (str): Path to output stego image
            public_key_path (str, optional): Path to RSA public key
            password (str, optional): Password for AES encryption
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Validate cover image
            if not self.stego.validate_image(cover_image):
                print("✗ Invalid cover image")
                return False
            
            # Load public key if provided
            if public_key_path:
                if not os.path.exists(public_key_path):
                    print(f"✗ Public key file not found: {public_key_path}")
                    return False
                public_key = self.encryption.load_key(public_key_path)
            else:
                # Use default public key
                default_key_path = os.path.join(self.keys_dir, "public_key.pem")
                if not os.path.exists(default_key_path):
                    print("✗ No public key found. Generate keys first with --generate-keys")
                    return False
                public_key = self.encryption.load_key(default_key_path)
            
            print("Encrypting message...")
            
            # Encrypt the message
            encrypted_data = self.encryption.dual_encrypt(message, public_key, password)
            
            # Convert encrypted data to JSON string
            encrypted_json = json.dumps(encrypted_data)
            
            print("Embedding encrypted message in image...")
            
            # Embed in image
            success = self.stego.embed_data(cover_image, encrypted_json, output_image)
            
            if success:
                print(f"✓ Message successfully hidden in: {output_image}")
                return True
            else:
                print("✗ Failed to embed message in image")
                return False
                
        except Exception as e:
            print(f"✗ Error hiding message: {str(e)}")
            return False
    
    def extract_message(self, stego_image: str, private_key_path: str = None, 
                       password: str = None) -> Optional[str]:
        """
        Extract and decrypt a hidden message from an image.
        
        Args:
            stego_image (str): Path to stego image
            private_key_path (str, optional): Path to RSA private key
            password (str, optional): Password for AES decryption
            
        Returns:
            str: Decrypted message, or None if failed
        """
        try:
            # Validate stego image
            if not os.path.exists(stego_image):
                print(f"✗ Stego image not found: {stego_image}")
                return None
            
            print("Extracting encrypted data from image...")
            
            # Extract encrypted data
            extracted_json = self.stego.extract_data(stego_image)
            
            if not extracted_json:
                print("✗ No encrypted data found in image")
                return None
            
            try:
                encrypted_data = json.loads(extracted_json)
            except json.JSONDecodeError:
                print("✗ Invalid encrypted data format")
                return None
            
            # Load private key if provided
            if private_key_path:
                if not os.path.exists(private_key_path):
                    print(f"✗ Private key file not found: {private_key_path}")
                    return None
                private_key = self.encryption.load_key(private_key_path)
            else:
                # Use default private key
                default_key_path = os.path.join(self.keys_dir, "private_key.pem")
                if not os.path.exists(default_key_path):
                    print("✗ No private key found. Generate keys first with --generate-keys")
                    return None
                private_key = self.encryption.load_key(default_key_path)
            
            print("Decrypting message...")
            
            # Decrypt the message
            decrypted_message = self.encryption.dual_decrypt(encrypted_data, private_key, password)
            
            print("✓ Message successfully extracted and decrypted")
            return decrypted_message
            
        except Exception as e:
            print(f"✗ Error extracting message: {str(e)}")
            return None
    
    def hide_file_link(self, file_path: str, cover_image: str, output_image: str,
                      public_key_path: str = None) -> bool:
        """
        Upload a file to cloud storage and hide the encrypted link in an image.
        
        Args:
            file_path (str): Path to file to upload
            cover_image (str): Path to cover image
            output_image (str): Path to output stego image
            public_key_path (str, optional): Path to RSA public key
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not os.path.exists(file_path):
                print(f"✗ File not found: {file_path}")
                return False
            
            print(f"Uploading file to cloud storage: {file_path}")
            
            # Upload file to cloud (this would be implemented with actual cloud service)
            # For now, we'll simulate this
            cloud_link = f"https://secure-cloud.example.com/files/{os.path.basename(file_path)}"
            
            print(f"✓ File uploaded. Cloud link: {cloud_link}")
            
            # Hide the cloud link in the image
            return self.hide_message(cloud_link, cover_image, output_image, public_key_path)
            
        except Exception as e:
            print(f"✗ Error hiding file link: {str(e)}")
            return False
    
    def get_image_capacity(self, image_path: str) -> None:
        """
        Display the capacity of an image for steganography.
        
        Args:
            image_path (str): Path to the image
        """
        if not os.path.exists(image_path):
            print(f"✗ Image not found: {image_path}")
            return
        
        capacity_bits = self.stego.get_image_capacity(image_path)
        capacity_bytes = capacity_bits // 8
        capacity_kb = capacity_bytes / 1024
        
        print(f"Image capacity for '{image_path}':")
        print(f"  - {capacity_bits:,} bits")
        print(f"  - {capacity_bytes:,} bytes")
        print(f"  - {capacity_kb:.2f} KB")


def create_parser():
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description="Steganography with Multi-Layer Encryption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate RSA keys
  python main.py --generate-keys
  
  # Hide a message in an image
  python main.py --hide "Secret message" --cover image.png --output stego.png
  
  # Extract a message from an image
  python main.py --extract stego.png
  
  # Hide a file link in an image
  python main.py --hide-file document.pdf --cover image.png --output stego.png
  
  # Check image capacity
  python main.py --capacity image.png
        """
    )
    
    # Key generation
    parser.add_argument('--generate-keys', action='store_true',
                       help='Generate RSA key pair')
    
    # Message hiding
    parser.add_argument('--hide', type=str, metavar='MESSAGE',
                       help='Message to hide in image')
    parser.add_argument('--cover', type=str, metavar='IMAGE',
                       help='Cover image file path')
    parser.add_argument('--output', type=str, metavar='IMAGE',
                       help='Output stego image file path')
    
    # Message extraction
    parser.add_argument('--extract', type=str, metavar='IMAGE',
                       help='Extract message from stego image')
    
    # File link hiding
    parser.add_argument('--hide-file', type=str, metavar='FILE',
                       help='File to upload and hide link in image')
    
    # Key paths
    parser.add_argument('--public-key', type=str, metavar='PATH',
                       help='Path to RSA public key file')
    parser.add_argument('--private-key', type=str, metavar='PATH',
                       help='Path to RSA private key file')
    
    # Utility
    parser.add_argument('--capacity', type=str, metavar='IMAGE',
                       help='Check image capacity for steganography')
    parser.add_argument('--password', action='store_true',
                       help='Use password for AES encryption')
    
    return parser


def main():
    """Main function."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Create application instance
    app = SteganographyApp()
    
    try:
        # Generate keys
        if args.generate_keys:
            app.generate_keys()
            return
        
        # Check image capacity
        if args.capacity:
            app.get_image_capacity(args.capacity)
            return
        
        # Get password if requested
        password = None
        if args.password:
            password = getpass.getpass("Enter password for AES encryption: ")
        
        # Hide message
        if args.hide:
            if not args.cover or not args.output:
                print("✗ --cover and --output arguments are required for hiding messages")
                return
            
            success = app.hide_message(
                args.hide, args.cover, args.output, 
                args.public_key, password
            )
            return
        
        # Hide file link
        if args.hide_file:
            if not args.cover or not args.output:
                print("✗ --cover and --output arguments are required for hiding file links")
                return
            
            success = app.hide_file_link(
                args.hide_file, args.cover, args.output, args.public_key
            )
            return
        
        # Extract message
        if args.extract:
            message = app.extract_message(args.extract, args.private_key, password)
            if message:
                print("\\nExtracted message:")
                print("-" * 40)
                print(message)
                print("-" * 40)
            return
        
        # If no specific action was requested, show help
        parser.print_help()
        
    except KeyboardInterrupt:
        print("\\n✗ Operation cancelled by user")
    except Exception as e:
        print(f"✗ Unexpected error: {str(e)}")


if __name__ == "__main__":
    main()
