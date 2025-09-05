#!/usr/bin/env python3
"""
Basic Usage Example for Steganography with Multi-Layer Encryption

This script demonstrates how to use the steganography and encryption modules
to hide and extract secret messages in images.
"""

import os
import sys
import tempfile
from PIL import Image, ImageDraw
import numpy as np

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from steganography.lsb_steganography import LSBSteganography
from encryption.dual_encryption import DualEncryption


def create_sample_image(width=400, height=300, filename="sample_image.png"):
    """
    Create a sample image for testing steganography.
    
    Args:
        width (int): Image width
        height (int): Image height
        filename (str): Output filename
    
    Returns:
        str: Path to the created image
    """
    # Create a new image with RGB mode
    image = Image.new('RGB', (width, height), color='white')
    draw = ImageDraw.Draw(image)
    
    # Add some visual elements
    # Draw a gradient background
    for y in range(height):
        color_val = int(255 * y / height)
        draw.line([(0, y), (width, y)], fill=(color_val, 100, 255 - color_val))
    
    # Add some shapes
    draw.rectangle([50, 50, 150, 100], fill=(255, 0, 0), outline=(0, 0, 0))
    draw.ellipse([200, 80, 300, 180], fill=(0, 255, 0), outline=(0, 0, 0))
    draw.polygon([(320, 50), (350, 100), (290, 100)], fill=(0, 0, 255), outline=(0, 0, 0))
    
    # Save the image
    image_path = os.path.join(os.path.dirname(__file__), filename)
    image.save(image_path, 'PNG')
    
    print(f"Sample image created: {image_path}")
    return image_path


def basic_steganography_example():
    """Demonstrate basic steganography without encryption."""
    print("\\n" + "="*60)
    print("BASIC STEGANOGRAPHY EXAMPLE")
    print("="*60)
    
    # Create sample image
    cover_image = create_sample_image(filename="basic_cover.png")
    
    # Initialize steganography
    stego = LSBSteganography()
    
    # Secret message
    secret_message = "This is a secret message hidden using LSB steganography!"
    print(f"Secret message: {secret_message}")
    
    # Check image capacity
    capacity = stego.get_image_capacity(cover_image)
    print(f"Image capacity: {capacity} bits ({capacity // 8} bytes)")
    
    # Embed message
    stego_image = os.path.join(os.path.dirname(__file__), "basic_stego.png")
    success = stego.embed_data(cover_image, secret_message, stego_image)
    
    if success:
        print(f"✓ Message embedded successfully in: {stego_image}")
        
        # Extract message
        extracted_message = stego.extract_data(stego_image)
        
        if extracted_message:
            print(f"✓ Extracted message: {extracted_message}")
            print(f"✓ Messages match: {secret_message == extracted_message}")
        else:
            print("✗ Failed to extract message")
    else:
        print("✗ Failed to embed message")


def encryption_example():
    """Demonstrate dual-layer encryption."""
    print("\\n" + "="*60)
    print("ENCRYPTION EXAMPLE")
    print("="*60)
    
    # Initialize encryption
    encryption = DualEncryption()
    
    # Generate RSA keys
    print("Generating RSA key pair...")
    private_key, public_key = encryption.generate_rsa_keys()
    print("✓ RSA keys generated")
    
    # Secret message
    secret_message = "This is a confidential message encrypted with AES+RSA!"
    print(f"Original message: {secret_message}")
    
    # Encrypt message
    print("Encrypting message with dual-layer encryption...")
    encrypted_data = encryption.dual_encrypt(secret_message, public_key)
    print("✓ Message encrypted successfully")
    print(f"Encrypted keys: {list(encrypted_data.keys())}")
    
    # Decrypt message
    print("Decrypting message...")
    decrypted_message = encryption.dual_decrypt(encrypted_data, private_key)
    print(f"✓ Decrypted message: {decrypted_message}")
    print(f"✓ Messages match: {secret_message == decrypted_message}")


def complete_example():
    """Demonstrate complete steganography + encryption workflow."""
    print("\\n" + "="*60)
    print("COMPLETE STEGANOGRAPHY + ENCRYPTION EXAMPLE")
    print("="*60)
    
    # Initialize modules
    stego = LSBSteganography()
    encryption = DualEncryption()
    
    # Generate RSA keys
    print("1. Generating RSA key pair...")
    private_key, public_key = encryption.generate_rsa_keys()
    
    # Create sample image
    print("2. Creating sample image...")
    cover_image = create_sample_image(filename="complete_cover.png")
    
    # Secret message
    secret_message = "TOP SECRET: The eagle flies at midnight. Operation Bluebird is a go!"
    print(f"3. Secret message: {secret_message}")
    
    # Encrypt message
    print("4. Encrypting message with dual-layer encryption...")
    encrypted_data = encryption.dual_encrypt(secret_message, public_key)
    
    # Convert encrypted data to JSON string for embedding
    import json
    encrypted_json = json.dumps(encrypted_data)
    print(f"   Encrypted data size: {len(encrypted_json)} characters")
    
    # Embed encrypted data in image
    print("5. Embedding encrypted data in image using LSB steganography...")
    stego_image = os.path.join(os.path.dirname(__file__), "complete_stego.png")
    embed_success = stego.embed_data(cover_image, encrypted_json, stego_image)
    
    if not embed_success:
        print("✗ Failed to embed encrypted data")
        return
    
    print(f"✓ Encrypted data embedded in: {stego_image}")
    
    # --- Receiver side ---
    print("\\n--- RECEIVER SIDE ---")
    
    # Extract encrypted data from image
    print("6. Extracting encrypted data from stego image...")
    extracted_json = stego.extract_data(stego_image)
    
    if not extracted_json:
        print("✗ Failed to extract encrypted data")
        return
    
    try:
        extracted_encrypted_data = json.loads(extracted_json)
        print("✓ Encrypted data extracted successfully")
    except json.JSONDecodeError:
        print("✗ Invalid encrypted data format")
        return
    
    # Decrypt the extracted data
    print("7. Decrypting extracted data...")
    final_message = encryption.dual_decrypt(extracted_encrypted_data, private_key)
    
    print(f"✓ Final decrypted message: {final_message}")
    print(f"✓ Complete process successful: {secret_message == final_message}")
    
    # Compare image files
    print("\\n8. Comparing original and stego images...")
    original_size = os.path.getsize(cover_image)
    stego_size = os.path.getsize(stego_image)
    print(f"   Original image: {original_size:,} bytes")
    print(f"   Stego image: {stego_size:,} bytes")
    print(f"   Size difference: {stego_size - original_size:,} bytes")


def password_encryption_example():
    """Demonstrate encryption with password-based AES key."""
    print("\\n" + "="*60)
    print("PASSWORD-BASED ENCRYPTION EXAMPLE")
    print("="*60)
    
    # Initialize modules
    stego = LSBSteganography()
    encryption = DualEncryption()
    
    # Generate RSA keys
    private_key, public_key = encryption.generate_rsa_keys()
    
    # Secret message and password
    secret_message = "This message is encrypted with a password!"
    password = "my_secure_password_123"
    
    print(f"Secret message: {secret_message}")
    print(f"Password: {'*' * len(password)}")
    
    # Encrypt with password
    print("Encrypting with password-based AES key...")
    encrypted_data = encryption.dual_encrypt(secret_message, public_key, password)
    print("✓ Message encrypted with password")
    
    # Decrypt with password
    print("Decrypting with password...")
    decrypted_message = encryption.dual_decrypt(encrypted_data, private_key, password)
    print(f"✓ Decrypted message: {decrypted_message}")
    print(f"✓ Success: {secret_message == decrypted_message}")
    
    # Try decrypting with wrong password (should fail)
    print("\\nTrying with wrong password...")
    try:
        wrong_decryption = encryption.dual_decrypt(encrypted_data, private_key, "wrong_password")
        print("✗ Unexpected success with wrong password!")
    except Exception as e:
        print(f"✓ Correctly failed with wrong password: {type(e).__name__}")


def main():
    """Run all examples."""
    print("STEGANOGRAPHY WITH MULTI-LAYER ENCRYPTION - EXAMPLES")
    print("=" * 80)
    
    try:
        # Run examples
        basic_steganography_example()
        encryption_example()
        complete_example()
        password_encryption_example()
        
        print("\\n" + "="*80)
        print("ALL EXAMPLES COMPLETED SUCCESSFULLY!")
        print("="*80)
        
        print("\\nGenerated files in examples directory:")
        example_dir = os.path.dirname(__file__)
        for filename in os.listdir(example_dir):
            if filename.endswith('.png'):
                file_path = os.path.join(example_dir, filename)
                size = os.path.getsize(file_path)
                print(f"  - {filename} ({size:,} bytes)")
        
    except Exception as e:
        print(f"\\n✗ Error running examples: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
