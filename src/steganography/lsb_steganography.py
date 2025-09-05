"""
LSB (Least Significant Bit) Steganography Module

This module implements steganography techniques to hide encrypted data within images
using the Least Significant Bit method.
"""

import os
import numpy as np
from PIL import Image
import logging
from typing import Union, Tuple, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LSBSteganography:
    """
    LSB Steganography class for hiding and extracting data from images.
    """
    
    def __init__(self):
        """Initialize the LSB Steganography class."""
        self.delimiter = "<<<END_OF_MESSAGE>>>"
        
    def _text_to_binary(self, text: str) -> str:
        """
        Convert text to binary representation.
        
        Args:
            text (str): Input text to convert
            
        Returns:
            str: Binary representation of the text
        """
        binary_text = ''.join(format(ord(char), '08b') for char in text)
        return binary_text
    
    def _binary_to_text(self, binary: str) -> str:
        """
        Convert binary representation back to text.
        
        Args:
            binary (str): Binary string to convert
            
        Returns:
            str: Decoded text
        """
        text = ''
        for i in range(0, len(binary), 8):
            byte = binary[i:i+8]
            if len(byte) == 8:
                text += chr(int(byte, 2))
        return text
    
    def _modify_lsb(self, pixel_value: int, bit: str) -> int:
        """
        Modify the least significant bit of a pixel value.
        
        Args:
            pixel_value (int): Original pixel value
            bit (str): Bit to embed ('0' or '1')
            
        Returns:
            int: Modified pixel value
        """
        if bit == '0':
            return pixel_value & 0xFE  # Set LSB to 0
        else:
            return pixel_value | 0x01  # Set LSB to 1
    
    def _extract_lsb(self, pixel_value: int) -> str:
        """
        Extract the least significant bit from a pixel value.
        
        Args:
            pixel_value (int): Pixel value to extract from
            
        Returns:
            str: The LSB as '0' or '1'
        """
        return str(pixel_value & 0x01)
    
    def embed_data(self, cover_image_path: str, secret_data: str, output_image_path: str) -> bool:
        """
        Embed secret data into a cover image using LSB steganography.
        
        Args:
            cover_image_path (str): Path to the cover image
            secret_data (str): Secret data to embed
            output_image_path (str): Path to save the stego image
            
        Returns:
            bool: True if embedding successful, False otherwise
        """
        try:
            # Load the cover image
            image = Image.open(cover_image_path)
            
            # Convert to RGB if necessary
            if image.mode != 'RGB':
                image = image.convert('RGB')
                
            # Convert image to numpy array
            img_array = np.array(image)
            height, width, channels = img_array.shape
            
            # Add delimiter to the secret data
            data_with_delimiter = secret_data + self.delimiter
            
            # Convert data to binary
            binary_data = self._text_to_binary(data_with_delimiter)
            
            # Check if the image can accommodate the data
            max_capacity = height * width * channels
            if len(binary_data) > max_capacity:
                logger.error(f"Image too small. Need {len(binary_data)} bits, but image can hold {max_capacity} bits")
                return False
            
            # Embed the data
            data_index = 0
            for i in range(height):
                for j in range(width):
                    for k in range(channels):
                        if data_index < len(binary_data):
                            # Modify the LSB of the current pixel
                            img_array[i][j][k] = self._modify_lsb(
                                img_array[i][j][k], 
                                binary_data[data_index]
                            )
                            data_index += 1
                        else:
                            # All data has been embedded
                            break
                    if data_index >= len(binary_data):
                        break
                if data_index >= len(binary_data):
                    break
            
            # Create the stego image
            stego_image = Image.fromarray(img_array)
            
            # Save the stego image
            stego_image.save(output_image_path, format='PNG')
            
            logger.info(f"Data successfully embedded. Stego image saved to: {output_image_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error embedding data: {str(e)}")
            return False
    
    def extract_data(self, stego_image_path: str) -> Optional[str]:
        """
        Extract secret data from a stego image.
        
        Args:
            stego_image_path (str): Path to the stego image
            
        Returns:
            str: Extracted secret data, or None if extraction failed
        """
        try:
            # Load the stego image
            image = Image.open(stego_image_path)
            
            # Convert to RGB if necessary
            if image.mode != 'RGB':
                image = image.convert('RGB')
                
            # Convert image to numpy array
            img_array = np.array(image)
            height, width, channels = img_array.shape
            
            # Extract binary data
            binary_data = ""
            for i in range(height):
                for j in range(width):
                    for k in range(channels):
                        # Extract LSB
                        binary_data += self._extract_lsb(img_array[i][j][k])
            
            # Convert binary to text
            extracted_text = self._binary_to_text(binary_data)
            
            # Find the delimiter and extract the actual message
            if self.delimiter in extracted_text:
                secret_data = extracted_text.split(self.delimiter)[0]
                logger.info("Data successfully extracted from stego image")
                return secret_data
            else:
                logger.error("Delimiter not found. The image may not contain embedded data.")
                return None
                
        except Exception as e:
            logger.error(f"Error extracting data: {str(e)}")
            return None
    
    def get_image_capacity(self, image_path: str) -> int:
        """
        Calculate the maximum data capacity of an image in bits.
        
        Args:
            image_path (str): Path to the image
            
        Returns:
            int: Maximum capacity in bits
        """
        try:
            image = Image.open(image_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            height, width, channels = img_array.shape
            
            capacity = height * width * channels
            logger.info(f"Image capacity: {capacity} bits ({capacity // 8} bytes)")
            return capacity
            
        except Exception as e:
            logger.error(f"Error calculating capacity: {str(e)}")
            return 0
    
    def validate_image(self, image_path: str) -> bool:
        """
        Validate if the image is suitable for steganography.
        
        Args:
            image_path (str): Path to the image
            
        Returns:
            bool: True if image is valid, False otherwise
        """
        try:
            if not os.path.exists(image_path):
                logger.error("Image file does not exist")
                return False
                
            image = Image.open(image_path)
            
            # Check if image can be converted to RGB
            if image.mode not in ['RGB', 'RGBA', 'L']:
                logger.warning(f"Image mode {image.mode} may not be suitable")
                
            # Check image size
            width, height = image.size
            if width < 10 or height < 10:
                logger.error("Image too small for steganography")
                return False
                
            logger.info(f"Image validated successfully: {width}x{height}, mode: {image.mode}")
            return True
            
        except Exception as e:
            logger.error(f"Error validating image: {str(e)}")
            return False


def main():
    """
    Demo function to test the LSB steganography functionality.
    """
    stego = LSBSteganography()
    
    # This would be used in actual implementation
    print("LSB Steganography module initialized successfully")
    print("Use embed_data() and extract_data() methods for steganography operations")


if __name__ == "__main__":
    main()
