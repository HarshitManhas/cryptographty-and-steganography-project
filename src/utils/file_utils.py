"""
File Utilities Module

This module provides utilities for file operations, type detection,
and size-based routing for the steganography application.
"""

import os
import mimetypes
import hashlib
from typing import Dict, Tuple, Optional, List
from pathlib import Path
import logging

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

try:
    import humanize
    HAS_HUMANIZE = True
except ImportError:
    HAS_HUMANIZE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FileUtils:
    """
    Utility class for file operations and analysis.
    """
    
    # File size thresholds (in bytes)
    SMALL_FILE_THRESHOLD = 10 * 1024 * 1024  # 10 MB
    LARGE_FILE_THRESHOLD = 100 * 1024 * 1024  # 100 MB
    
    # Supported image formats for steganography
    SUPPORTED_IMAGE_FORMATS = {
        '.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.tif'
    }
    
    # Large file types that should go to cloud storage
    LARGE_FILE_TYPES = {
        # Video formats
        'video/mp4', 'video/avi', 'video/mov', 'video/wmv', 'video/flv',
        'video/webm', 'video/mkv', 'video/m4v', 'video/3gp',
        # Audio formats
        'audio/mp3', 'audio/wav', 'audio/flac', 'audio/aac', 'audio/ogg',
        'audio/wma', 'audio/m4a',
        # Archive formats
        'application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed',
        'application/x-tar', 'application/gzip',
        # Document formats (large ones)
        'application/pdf', 'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    }
    
    def __init__(self):
        """Initialize FileUtils."""
        self.magic_mime = None
        if HAS_MAGIC:
            try:
                self.magic_mime = magic.Magic(mime=True)
            except Exception as e:
                logger.warning(f"Failed to initialize python-magic: {e}")
                logger.info("Install python-magic for better file type detection: pip install python-magic")
                self.magic_mime = None
    
    def get_file_info(self, file_path: str) -> Dict[str, any]:
        """
        Get comprehensive information about a file.
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            Dict[str, any]: File information including size, type, etc.
        """
        try:
            if not os.path.exists(file_path):
                return {'error': 'File not found'}
            
            stat_info = os.stat(file_path)
            file_size = stat_info.st_size
            
            info = {
                'file_path': file_path,
                'file_name': os.path.basename(file_path),
                'file_size': file_size,
                'file_size_human': self._human_readable_size(file_size),
                'file_extension': Path(file_path).suffix.lower(),
                'mime_type': self.get_mime_type(file_path),
                'is_large_file': self.is_large_file(file_path),
                'should_use_cloud': self.should_use_cloud_storage(file_path),
                'is_supported_image': self.is_supported_image(file_path),
                'processing_method': self.get_processing_method(file_path),
                'file_hash': self.calculate_file_hash(file_path)
            }
            
            return info
            
        except Exception as e:
            logger.error(f"Error getting file info: {str(e)}")
            return {'error': str(e)}
    
    def get_mime_type(self, file_path: str) -> str:
        """
        Get MIME type of a file.
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            str: MIME type
        """
        try:
            # Try python-magic first (more accurate)
            if self.magic_mime:
                try:
                    mime_type = self.magic_mime.from_file(file_path)
                    if mime_type:
                        return mime_type
                except Exception:
                    pass  # Fall through to mimetypes
            
            # Fall back to mimetypes module
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type:
                return mime_type
            
            # Additional fallback based on file extension
            extension = Path(file_path).suffix.lower()
            extension_map = {
                '.txt': 'text/plain',
                '.py': 'text/x-python',
                '.js': 'application/javascript',
                '.json': 'application/json',
                '.html': 'text/html',
                '.css': 'text/css',
                '.xml': 'application/xml',
                '.csv': 'text/csv',
                '.md': 'text/markdown',
                '.pdf': 'application/pdf',
                '.doc': 'application/msword',
                '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                '.mp4': 'video/mp4',
                '.avi': 'video/x-msvideo',
                '.mp3': 'audio/mpeg',
                '.wav': 'audio/wav',
                '.zip': 'application/zip',
                '.tar': 'application/x-tar',
                '.gz': 'application/gzip'
            }
            
            return extension_map.get(extension, 'application/octet-stream')
            
        except Exception as e:
            logger.error(f"Error detecting MIME type: {str(e)}")
            return 'application/octet-stream'
    
    def is_large_file(self, file_path: str) -> bool:
        """
        Check if a file is considered large.
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            bool: True if file is large, False otherwise
        """
        try:
            file_size = os.path.getsize(file_path)
            return file_size > self.LARGE_FILE_THRESHOLD
        except Exception:
            return False
    
    def should_use_cloud_storage(self, file_path: str) -> bool:
        """
        Determine if a file should be uploaded to cloud storage.
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            bool: True if should use cloud storage, False otherwise
        """
        try:
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > self.SMALL_FILE_THRESHOLD:
                return True
            
            # Check file type
            mime_type = self.get_mime_type(file_path)
            if mime_type in self.LARGE_FILE_TYPES:
                return True
            
            return False
            
        except Exception:
            return False
    
    def is_supported_image(self, file_path: str) -> bool:
        """
        Check if a file is a supported image format for steganography.
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            bool: True if supported image format, False otherwise
        """
        try:
            extension = Path(file_path).suffix.lower()
            return extension in self.SUPPORTED_IMAGE_FORMATS
        except Exception:
            return False
    
    def get_processing_method(self, file_path: str) -> str:
        """
        Determine the best processing method for a file.
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            str: Processing method ('direct_text', 'direct_encryption', 'cloud_upload')
        """
        try:
            mime_type = self.get_mime_type(file_path)
            file_size = os.path.getsize(file_path)
            
            # Text files under threshold
            if mime_type.startswith('text/') and file_size <= self.SMALL_FILE_THRESHOLD:
                return 'direct_text'
            
            # Small files that can be directly encrypted
            if file_size <= self.SMALL_FILE_THRESHOLD:
                return 'direct_encryption'
            
            # Large files go to cloud
            return 'cloud_upload'
            
        except Exception:
            return 'cloud_upload'  # Safe default
    
    def calculate_file_hash(self, file_path: str, algorithm: str = 'sha256') -> str:
        """
        Calculate hash of a file.
        
        Args:
            file_path (str): Path to the file
            algorithm (str): Hash algorithm to use
            
        Returns:
            str: File hash
        """
        try:
            hash_obj = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating file hash: {str(e)}")
            return ''
    
    def _human_readable_size(self, size_bytes: int) -> str:
        """
        Convert bytes to human readable format.
        
        Args:
            size_bytes (int): Size in bytes
            
        Returns:
            str: Human readable size
        """
        if HAS_HUMANIZE:
            return humanize.naturalsize(size_bytes, binary=True)
        
        # Fallback implementation
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"
    
    def find_image_files(self, directory: str) -> List[str]:
        """
        Find all supported image files in a directory.
        
        Args:
            directory (str): Directory to search
            
        Returns:
            List[str]: List of image file paths
        """
        try:
            image_files = []
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    if self.is_supported_image(file_path):
                        image_files.append(file_path)
            return sorted(image_files)
        except Exception as e:
            logger.error(f"Error finding image files: {str(e)}")
            return []
    
    def validate_file(self, file_path: str) -> Tuple[bool, str]:
        """
        Validate if a file can be processed.
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        try:
            if not os.path.exists(file_path):
                return False, "File does not exist"
            
            if not os.path.isfile(file_path):
                return False, "Path is not a file"
            
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                return False, "File is empty"
            
            # Check read permissions
            if not os.access(file_path, os.R_OK):
                return False, "No read permission for file"
            
            return True, "File is valid"
            
        except Exception as e:
            return False, f"Error validating file: {str(e)}"


def main():
    """
    Demo function to test file utilities.
    """
    utils = FileUtils()
    
    print("File Utilities module initialized successfully")
    print(f"Small file threshold: {utils._human_readable_size(utils.SMALL_FILE_THRESHOLD)}")
    print(f"Large file threshold: {utils._human_readable_size(utils.LARGE_FILE_THRESHOLD)}")
    print(f"Supported image formats: {', '.join(utils.SUPPORTED_IMAGE_FORMATS)}")
    
    print("\nAvailable methods:")
    print("- get_file_info(path)")
    print("- is_large_file(path)")
    print("- should_use_cloud_storage(path)")
    print("- is_supported_image(path)")
    print("- get_processing_method(path)")
    print("- find_image_files(directory)")
    print("- validate_file(path)")


if __name__ == "__main__":
    main()
