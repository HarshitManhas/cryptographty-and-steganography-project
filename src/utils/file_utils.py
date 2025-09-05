"""
File Utilities Module

This module provides utility functions for file operations.
"""

import os
import hashlib
import shutil
from typing import Optional, List
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FileUtils:
    """
    Utility class for file operations.
    """
    
    @staticmethod
    def calculate_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """
        Calculate hash of a file.
        
        Args:
            file_path (str): Path to the file
            algorithm (str): Hash algorithm ('sha256', 'md5', 'sha1')
            
        Returns:
            str: File hash, or None if error
        """
        try:
            hash_obj = hashlib.new(algorithm)
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            
            file_hash = hash_obj.hexdigest()
            logger.info(f"Hash calculated for {file_path}: {file_hash}")
            return file_hash
            
        except Exception as e:
            logger.error(f"Error calculating hash: {str(e)}")
            return None
    
    @staticmethod
    def get_file_size(file_path: str) -> Optional[int]:
        """
        Get file size in bytes.
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            int: File size in bytes, or None if error
        """
        try:
            size = os.path.getsize(file_path)
            logger.info(f"File size for {file_path}: {size} bytes")
            return size
            
        except Exception as e:
            logger.error(f"Error getting file size: {str(e)}")
            return None
    
    @staticmethod
    def validate_file(file_path: str, max_size: int = None) -> bool:
        """
        Validate if a file exists and meets size requirements.
        
        Args:
            file_path (str): Path to the file
            max_size (int, optional): Maximum file size in bytes
            
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            if not os.path.exists(file_path):
                logger.error(f"File does not exist: {file_path}")
                return False
            
            if not os.path.isfile(file_path):
                logger.error(f"Path is not a file: {file_path}")
                return False
            
            file_size = FileUtils.get_file_size(file_path)
            if file_size is None:
                return False
            
            if max_size and file_size > max_size:
                logger.error(f"File too large: {file_size} bytes > {max_size} bytes")
                return False
            
            logger.info(f"File validation successful: {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error validating file: {str(e)}")
            return False
    
    @staticmethod
    def create_backup(file_path: str, backup_dir: str = "backups") -> Optional[str]:
        """
        Create a backup copy of a file.
        
        Args:
            file_path (str): Path to the file to backup
            backup_dir (str): Directory to store backup
            
        Returns:
            str: Path to backup file, or None if error
        """
        try:
            if not os.path.exists(file_path):
                logger.error(f"File does not exist: {file_path}")
                return None
            
            # Create backup directory if it doesn't exist
            os.makedirs(backup_dir, exist_ok=True)
            
            # Generate backup filename
            filename = os.path.basename(file_path)
            name, ext = os.path.splitext(filename)
            backup_filename = f"{name}_backup{ext}"
            backup_path = os.path.join(backup_dir, backup_filename)
            
            # Copy file
            shutil.copy2(file_path, backup_path)
            
            logger.info(f"Backup created: {backup_path}")
            return backup_path
            
        except Exception as e:
            logger.error(f"Error creating backup: {str(e)}")
            return None
    
    @staticmethod
    def clean_temp_files(temp_dir: str) -> bool:
        """
        Clean temporary files from a directory.
        
        Args:
            temp_dir (str): Directory containing temp files
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not os.path.exists(temp_dir):
                logger.info(f"Temp directory doesn't exist: {temp_dir}")
                return True
            
            for filename in os.listdir(temp_dir):
                file_path = os.path.join(temp_dir, filename)
                if os.path.isfile(file_path):
                    os.remove(file_path)
                    logger.info(f"Removed temp file: {file_path}")
            
            logger.info(f"Temp directory cleaned: {temp_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Error cleaning temp files: {str(e)}")
            return False
    
    @staticmethod
    def get_supported_image_formats() -> List[str]:
        """
        Get list of supported image formats.
        
        Returns:
            List[str]: List of supported image extensions
        """
        return ['.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.tif']
    
    @staticmethod
    def is_image_file(file_path: str) -> bool:
        """
        Check if a file is a supported image format.
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            bool: True if it's a supported image, False otherwise
        """
        try:
            _, ext = os.path.splitext(file_path.lower())
            supported_formats = FileUtils.get_supported_image_formats()
            
            is_image = ext in supported_formats
            logger.info(f"Image format check for {file_path}: {is_image}")
            return is_image
            
        except Exception as e:
            logger.error(f"Error checking image format: {str(e)}")
            return False


def main():
    """
    Demo function to test file utilities.
    """
    file_utils = FileUtils()
    
    print("File Utilities module initialized successfully")
    print("Available functions:")
    print("- calculate_hash()")
    print("- get_file_size()")
    print("- validate_file()")
    print("- create_backup()")
    print("- clean_temp_files()")
    print("- is_image_file()")


if __name__ == "__main__":
    main()
