"""
Cloud Storage Integration Module

This module provides integration with cloud storage services for 
uploading and managing large files securely, with primary support
for Google Drive integration.
"""

import os
import hashlib
import time
from typing import Optional, Dict, Any
import logging

# Import Google Drive integration
try:
    from .google_drive import GoogleDriveStorage
    HAS_GOOGLE_DRIVE = True
except ImportError:
    HAS_GOOGLE_DRIVE = False
    logger.warning("Google Drive integration not available")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CloudStorage:
    """
    Enhanced cloud storage integration class with Google Drive support.
    
    This class acts as a unified interface for different cloud storage providers,
    with primary support for Google Drive and fallback to demo mode.
    """
    
    def __init__(self, provider: str = "google_drive", config: Dict[str, Any] = None):
        """
        Initialize cloud storage.
        
        Args:
            provider (str): Cloud provider name ('google_drive' or 'demo')
            config (Dict[str, Any], optional): Configuration for the cloud provider
        """
        self.provider = provider
        self.config = config or {}
        self.upload_url_base = "https://secure-cloud.example.com/files/"
        
        # Initialize provider-specific storage
        self.google_drive = None
        if provider == "google_drive" and HAS_GOOGLE_DRIVE:
            try:
                credentials_path = self.config.get('credentials_path', 'credentials.json')
                token_path = self.config.get('token_path', 'token.pickle')
                self.google_drive = GoogleDriveStorage(credentials_path, token_path)
                logger.info("Google Drive storage initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Google Drive: {e}")
                self.provider = "demo"  # Fallback to demo mode
        
        logger.info(f"Cloud storage initialized with provider: {self.provider}")
    
    def upload_file(self, file_path: str, encrypt: bool = True, folder_name: str = "SteganographyFiles") -> Optional[Dict[str, str]]:
        """
        Upload a file to cloud storage using the configured provider.
        
        Args:
            file_path (str): Path to the file to upload
            encrypt (bool): Whether to encrypt the file during upload (for demo mode)
            folder_name (str): Folder name in cloud storage
            
        Returns:
            Dict[str, str]: Upload result with file info, or None if failed
        """
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return None
            
            # Use Google Drive if available
            if self.provider == "google_drive" and self.google_drive:
                return self._upload_to_google_drive(file_path, folder_name)
            
            # Fallback to demo mode
            return self._upload_demo_mode(file_path, encrypt)
            
        except Exception as e:
            logger.error(f"Error uploading file: {str(e)}")
            return None
    
    def _upload_to_google_drive(self, file_path: str, folder_name: str) -> Optional[Dict[str, str]]:
        """
        Upload file to Google Drive.
        
        Args:
            file_path (str): Path to the file to upload
            folder_name (str): Google Drive folder name
            
        Returns:
            Dict[str, str]: Upload result with file info, or None if failed
        """
        try:
            # Authenticate if needed
            if not self.google_drive.is_authenticated():
                logger.info("Authenticating with Google Drive...")
                if not self.google_drive.authenticate():
                    logger.error("Google Drive authentication failed")
                    return None
            
            # Upload to Google Drive
            upload_result = self.google_drive.upload_file(file_path, folder_name)
            
            if upload_result:
                # Format result to match CloudStorage interface
                result = {
                    'file_id': upload_result['file_id'],
                    'file_name': upload_result['file_name'],
                    'file_size': upload_result['file_size'],
                    'cloud_url': upload_result['shareable_link'],
                    'view_link': upload_result.get('view_link', ''),
                    'download_link': upload_result.get('download_link', ''),
                    'folder_name': upload_result['folder_name'],
                    'encrypted': 'false',  # Google Drive handles its own encryption
                    'upload_time': str(int(time.time())),
                    'provider': 'google_drive',
                    'upload_status': upload_result['upload_status']
                }
                
                logger.info(f"✓ File uploaded to Google Drive successfully")
                return result
            else:
                logger.error("Google Drive upload failed")
                return None
                
        except Exception as e:
            logger.error(f"Error uploading to Google Drive: {str(e)}")
            return None
    
    def _upload_demo_mode(self, file_path: str, encrypt: bool = True) -> Optional[Dict[str, str]]:
        """
        Simulate file upload in demo mode.
        
        Args:
            file_path (str): Path to the file to upload
            encrypt (bool): Whether to encrypt the file during upload
            
        Returns:
            Dict[str, str]: Simulated upload result
        """
        try:
            # Get file information
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            # Calculate file hash for integrity
            file_hash = self._calculate_file_hash(file_path)
            
            # Generate unique file ID
            file_id = self._generate_file_id(file_name, file_hash)
            
            # Simulate upload process
            logger.info(f"[DEMO MODE] Uploading {file_name} ({file_size} bytes)...")
            
            # Simulate upload delay
            time.sleep(1)
            
            # Generate cloud URL
            cloud_url = f"{self.upload_url_base}{file_id}"
            
            # Prepare result
            result = {
                'file_id': file_id,
                'file_name': file_name,
                'file_size': str(file_size),
                'file_hash': file_hash,
                'cloud_url': cloud_url,
                'encrypted': str(encrypt),
                'upload_time': str(int(time.time())),
                'provider': 'demo',
                'upload_status': 'success'
            }
            
            logger.info(f"[DEMO MODE] File upload simulated: {cloud_url}")
            return result
            
        except Exception as e:
            logger.error(f"Error in demo upload: {str(e)}")
            return None
    
    def download_file(self, cloud_url: str, output_path: str, decrypt: bool = True) -> bool:
        """
        Download a file from cloud storage.
        
        Args:
            cloud_url (str): URL of the file in cloud storage
            output_path (str): Local path to save the downloaded file
            decrypt (bool): Whether to decrypt the file after download
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info(f"Downloading file from: {cloud_url}")
            
            # In a real implementation, this would:
            # 1. Connect to cloud storage API
            # 2. Download the file
            # 3. Optionally decrypt it
            # 4. Save to local path
            
            # For demo purposes, we'll just simulate this
            logger.info(f"File would be downloaded to: {output_path}")
            logger.info("Note: This is a demo implementation")
            
            return True
            
        except Exception as e:
            logger.error(f"Error downloading file: {str(e)}")
            return False
    
    def delete_file(self, cloud_url: str) -> bool:
        """
        Delete a file from cloud storage.
        
        Args:
            cloud_url (str): URL of the file to delete
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info(f"Deleting file from cloud: {cloud_url}")
            
            # In a real implementation, this would call the cloud provider's delete API
            # For demo purposes, we'll just log it
            logger.info("File deletion completed (demo)")
            
            return True
            
        except Exception as e:
            logger.error(f"Error deleting file: {str(e)}")
            return False
    
    def get_file_info(self, cloud_url: str) -> Optional[Dict[str, str]]:
        """
        Get information about a file in cloud storage.
        
        Args:
            cloud_url (str): URL of the file
            
        Returns:
            Dict[str, str]: File information, or None if not found
        """
        try:
            # Extract file ID from URL
            file_id = cloud_url.split('/')[-1]
            
            # In a real implementation, this would query the cloud provider
            # For demo, return simulated info
            info = {
                'file_id': file_id,
                'cloud_url': cloud_url,
                'status': 'available',
                'provider': self.provider
            }
            
            logger.info(f"File info retrieved for: {file_id}")
            return info
            
        except Exception as e:
            logger.error(f"Error getting file info: {str(e)}")
            return None
    
    def generate_secure_link(self, cloud_url: str, expiry_hours: int = 24) -> Optional[str]:
        """
        Generate a secure, time-limited download link.
        
        Args:
            cloud_url (str): Original cloud URL
            expiry_hours (int): Link expiry time in hours
            
        Returns:
            str: Secure download link, or None if failed
        """
        try:
            # Generate secure token
            timestamp = str(int(time.time()))
            secure_token = hashlib.sha256(f"{cloud_url}{timestamp}".encode()).hexdigest()[:16]
            
            # Create secure link
            secure_link = f"{cloud_url}?token={secure_token}&expires={timestamp}&duration={expiry_hours}"
            
            logger.info(f"Secure link generated (expires in {expiry_hours}h)")
            return secure_link
            
        except Exception as e:
            logger.error(f"Error generating secure link: {str(e)}")
            return None
    
    def validate_cloud_url(self, cloud_url: str) -> bool:
        """
        Validate if a cloud URL is properly formatted.
        
        Args:
            cloud_url (str): URL to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            # Check if URL starts with expected base
            if not cloud_url.startswith(self.upload_url_base):
                logger.warning(f"URL doesn't match expected format: {cloud_url}")
                return False
            
            # Check if URL has file ID
            file_id = cloud_url.split('/')[-1]
            if len(file_id) < 10:  # Minimum expected length
                logger.warning(f"Invalid file ID in URL: {file_id}")
                return False
            
            logger.info(f"Cloud URL validation successful: {cloud_url}")
            return True
            
        except Exception as e:
            logger.error(f"Error validating cloud URL: {str(e)}")
            return False
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """
        Calculate SHA-256 hash of a file.
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            str: SHA-256 hash of the file
        """
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def _generate_file_id(self, file_name: str, file_hash: str) -> str:
        """
        Generate a unique file ID.
        
        Args:
            file_name (str): Original file name
            file_hash (str): File hash
            
        Returns:
            str: Unique file ID
        """
        timestamp = str(int(time.time()))
        unique_string = f"{file_name}{file_hash}{timestamp}"
        file_id = hashlib.sha256(unique_string.encode()).hexdigest()[:32]
        return file_id
    
    def authenticate(self) -> bool:
        """
        Authenticate with the cloud storage provider.
        
        Returns:
            bool: True if authentication successful, False otherwise
        """
        if self.provider == "google_drive" and self.google_drive:
            return self.google_drive.authenticate()
        
        # Demo mode doesn't require authentication
        return True
    
    def is_authenticated(self) -> bool:
        """
        Check if authenticated with the cloud storage provider.
        
        Returns:
            bool: True if authenticated, False otherwise
        """
        if self.provider == "google_drive" and self.google_drive:
            return self.google_drive.is_authenticated()
        
        # Demo mode is always "authenticated"
        return True
    
    def list_files(self, folder_name: str = "SteganographyFiles", limit: int = 10) -> list:
        """
        List files in cloud storage.
        
        Args:
            folder_name (str): Folder name to list files from
            limit (int): Maximum number of files to return
            
        Returns:
            list: List of file information
        """
        if self.provider == "google_drive" and self.google_drive:
            return self.google_drive.list_files(folder_name, limit)
        
        # Demo mode returns empty list
        logger.info("[DEMO MODE] No files to list")
        return []
    
    def get_provider_info(self) -> Dict[str, str]:
        """
        Get information about the cloud provider.
        
        Returns:
            Dict[str, str]: Provider information
        """
        info = {
            'provider': self.provider,
            'status': 'active',
            'features': 'upload,download,delete,secure_links'
        }
        
        if self.provider == "google_drive":
            info.update({
                'service': 'Google Drive API v3',
                'authentication': 'OAuth2',
                'folder_support': 'yes',
                'sharing': 'shareable_links'
            })
        else:
            info.update({
                'upload_url_base': self.upload_url_base,
                'note': 'Demo mode - files not actually uploaded'
            })
        
        return info


def main():
    """
    Demo function to test cloud storage functionality.
    """
    print("=" * 60)
    print("CLOUD STORAGE MODULE DEMO")
    print("=" * 60)
    
    # Test with Google Drive (if available)
    if HAS_GOOGLE_DRIVE:
        print("\n1. Testing Google Drive integration...")
        cloud_gd = CloudStorage(provider="google_drive")
        print(f"   Provider: {cloud_gd.provider}")
        print(f"   Authenticated: {cloud_gd.is_authenticated()}")
        
        provider_info = cloud_gd.get_provider_info()
        print(f"   Provider info: {provider_info}")
    else:
        print("\n1. Google Drive integration not available")
        print("   Install google-api-python-client to enable")
    
    # Test with demo mode
    print("\n2. Testing Demo Mode...")
    cloud_demo = CloudStorage(provider="demo")
    print(f"   Provider: {cloud_demo.provider}")
    print(f"   Authenticated: {cloud_demo.is_authenticated()}")
    
    provider_info = cloud_demo.get_provider_info()
    print(f"   Provider info: {provider_info}")
    
    print("\nAvailable methods:")
    print("- upload_file(file_path, encrypt=True, folder_name='SteganographyFiles')")
    print("- download_file(cloud_url, output_path)")
    print("- delete_file(cloud_url)")
    print("- authenticate()")
    print("- is_authenticated()")
    print("- list_files(folder_name, limit)")
    print("- generate_secure_link(cloud_url, expiry_hours)")
    print("- validate_cloud_url(cloud_url)")
    print("- get_provider_info()")
    
    print("\n" + "=" * 60)
    print("To use Google Drive:")
    print("1. Go to Google Cloud Console")
    print("2. Create a project and enable Google Drive API")
    print("3. Create OAuth2 credentials")
    print("4. Download credentials as 'credentials.json'")
    print("5. Place in project root directory")
    print("6. Run cloud.authenticate()")
    print("=" * 60)


if __name__ == "__main__":
    main()
