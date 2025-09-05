"""
Google Drive Integration Module

This module provides integration with Google Drive API for uploading large files
and generating shareable links for secure communication.
"""

import os
import json
import logging
import pickle
from typing import Optional, Dict, Any, List
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GoogleDriveStorage:
    """
    Google Drive storage integration class for uploading and managing files.
    """
    
    # Google Drive API scopes
    SCOPES = ['https://www.googleapis.com/auth/drive.file']
    
    def __init__(self, credentials_path: str = "credentials.json", token_path: str = "token.pickle"):
        """
        Initialize Google Drive storage.
        
        Args:
            credentials_path (str): Path to OAuth2 credentials JSON file
            token_path (str): Path to store authentication token
        """
        self.credentials_path = credentials_path
        self.token_path = token_path
        self.service = None
        self.credentials = None
        
        logger.info("Google Drive storage initialized")
    
    def authenticate(self) -> bool:
        """
        Authenticate with Google Drive API using OAuth2.
        
        Returns:
            bool: True if authentication successful, False otherwise
        """
        try:
            creds = None
            
            # Check if token file exists
            if os.path.exists(self.token_path):
                with open(self.token_path, 'rb') as token:
                    creds = pickle.load(token)
            
            # If there are no (valid) credentials available, let the user log in
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    logger.info("Refreshing expired credentials...")
                    creds.refresh(Request())
                else:
                    if not os.path.exists(self.credentials_path):
                        logger.error(f"Credentials file not found: {self.credentials_path}")
                        logger.info("Please download OAuth2 credentials from Google Cloud Console")
                        logger.info("and save as 'credentials.json' in the project root")
                        return False
                    
                    logger.info("Starting OAuth2 authentication flow...")
                    flow = InstalledAppFlow.from_client_secrets_file(
                        self.credentials_path, self.SCOPES)
                    creds = flow.run_local_server(port=0)
                
                # Save the credentials for the next run
                with open(self.token_path, 'wb') as token:
                    pickle.dump(creds, token)
            
            # Build the service
            self.service = build('drive', 'v3', credentials=creds)
            self.credentials = creds
            
            logger.info("✓ Google Drive authentication successful")
            return True
            
        except Exception as e:
            logger.error(f"✗ Google Drive authentication failed: {str(e)}")
            return False
    
    def upload_file(self, file_path: str, folder_name: str = "SteganographyFiles") -> Optional[Dict[str, str]]:
        """
        Upload a file to Google Drive and return shareable link.
        
        Args:
            file_path (str): Path to the file to upload
            folder_name (str): Google Drive folder name to upload to
            
        Returns:
            Dict[str, str]: Upload result with file info and shareable link, or None if failed
        """
        try:
            if not self.service:
                if not self.authenticate():
                    return None
            
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return None
            
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            logger.info(f"Uploading {file_name} ({file_size:,} bytes) to Google Drive...")
            
            # Create or get folder
            folder_id = self._get_or_create_folder(folder_name)
            if not folder_id:
                logger.error("Failed to create/access Google Drive folder")
                return None
            
            # Prepare file metadata
            file_metadata = {
                'name': file_name,
                'parents': [folder_id]
            }
            
            # Create media upload
            media = MediaFileUpload(file_path, resumable=True)
            
            # Upload file
            request = self.service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id,name,size,webViewLink,webContentLink'
            )
            
            file_info = request.execute()
            
            # Make file shareable (anyone with link can view)
            self._make_file_shareable(file_info['id'])
            
            # Get shareable link
            shareable_link = self._get_shareable_link(file_info['id'])
            
            result = {
                'file_id': file_info['id'],
                'file_name': file_info['name'],
                'file_size': file_info.get('size', str(file_size)),
                'view_link': file_info.get('webViewLink', ''),
                'download_link': file_info.get('webContentLink', ''),
                'shareable_link': shareable_link,
                'folder_name': folder_name,
                'upload_status': 'success'
            }
            
            logger.info(f"✓ File uploaded successfully")
            logger.info(f"  File ID: {file_info['id']}")
            logger.info(f"  Shareable Link: {shareable_link}")
            
            return result
            
        except Exception as e:
            logger.error(f"✗ Error uploading file to Google Drive: {str(e)}")
            return None
    
    def _get_or_create_folder(self, folder_name: str) -> Optional[str]:
        """
        Get existing folder or create a new one in Google Drive.
        
        Args:
            folder_name (str): Name of the folder
            
        Returns:
            str: Folder ID, or None if failed
        """
        try:
            # Search for existing folder
            query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder'"
            results = self.service.files().list(q=query, fields="files(id, name)").execute()
            folders = results.get('files', [])
            
            if folders:
                logger.info(f"Using existing folder: {folder_name}")
                return folders[0]['id']
            
            # Create new folder
            folder_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            
            folder = self.service.files().create(body=folder_metadata, fields='id').execute()
            logger.info(f"Created new folder: {folder_name}")
            
            return folder.get('id')
            
        except Exception as e:
            logger.error(f"Error creating/accessing folder: {str(e)}")
            return None
    
    def _make_file_shareable(self, file_id: str) -> bool:
        """
        Make a file shareable (anyone with link can view).
        
        Args:
            file_id (str): Google Drive file ID
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            permission = {
                'type': 'anyone',
                'role': 'reader'
            }
            
            self.service.permissions().create(
                fileId=file_id,
                body=permission
            ).execute()
            
            logger.info(f"File made shareable: {file_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error making file shareable: {str(e)}")
            return False
    
    def _get_shareable_link(self, file_id: str) -> str:
        """
        Get the shareable link for a file.
        
        Args:
            file_id (str): Google Drive file ID
            
        Returns:
            str: Shareable link
        """
        return f"https://drive.google.com/file/d/{file_id}/view?usp=sharing"
    
    def get_file_info(self, file_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a file in Google Drive.
        
        Args:
            file_id (str): Google Drive file ID
            
        Returns:
            Dict[str, Any]: File information, or None if not found
        """
        try:
            if not self.service:
                if not self.authenticate():
                    return None
            
            file_info = self.service.files().get(
                fileId=file_id,
                fields='id,name,size,mimeType,createdTime,modifiedTime,webViewLink,webContentLink'
            ).execute()
            
            logger.info(f"Retrieved file info for: {file_info['name']}")
            return file_info
            
        except Exception as e:
            logger.error(f"Error getting file info: {str(e)}")
            return None
    
    def delete_file(self, file_id: str) -> bool:
        """
        Delete a file from Google Drive.
        
        Args:
            file_id (str): Google Drive file ID
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not self.service:
                if not self.authenticate():
                    return False
            
            self.service.files().delete(fileId=file_id).execute()
            logger.info(f"File deleted successfully: {file_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting file: {str(e)}")
            return False
    
    def list_files(self, folder_name: str = "SteganographyFiles", limit: int = 10) -> List[Dict[str, Any]]:
        """
        List files in a specific folder.
        
        Args:
            folder_name (str): Name of the folder to list files from
            limit (int): Maximum number of files to return
            
        Returns:
            List[Dict[str, Any]]: List of file information
        """
        try:
            if not self.service:
                if not self.authenticate():
                    return []
            
            # Get folder ID
            folder_id = self._get_or_create_folder(folder_name)
            if not folder_id:
                return []
            
            # List files in folder
            query = f"'{folder_id}' in parents"
            results = self.service.files().list(
                q=query,
                pageSize=limit,
                fields="files(id,name,size,mimeType,createdTime,modifiedTime)"
            ).execute()
            
            files = results.get('files', [])
            logger.info(f"Found {len(files)} files in folder '{folder_name}'")
            
            return files
            
        except Exception as e:
            logger.error(f"Error listing files: {str(e)}")
            return []
    
    def is_authenticated(self) -> bool:
        """
        Check if the client is authenticated with Google Drive.
        
        Returns:
            bool: True if authenticated, False otherwise
        """
        return self.service is not None and self.credentials is not None
    
    def get_auth_status(self) -> Dict[str, str]:
        """
        Get authentication status information.
        
        Returns:
            Dict[str, str]: Authentication status details
        """
        if self.is_authenticated():
            return {
                'status': 'authenticated',
                'token_file': self.token_path,
                'credentials_file': self.credentials_path,
                'service': 'Google Drive API v3'
            }
        else:
            return {
                'status': 'not_authenticated',
                'token_file': self.token_path,
                'credentials_file': self.credentials_path,
                'service': 'Google Drive API v3'
            }


def main():
    """
    Demo function to test Google Drive functionality.
    """
    drive = GoogleDriveStorage()
    
    print("Google Drive Storage module initialized")
    print("Available methods:")
    print("- authenticate()")
    print("- upload_file()")
    print("- get_file_info()")
    print("- delete_file()")
    print("- list_files()")
    
    # Check authentication status
    auth_status = drive.get_auth_status()
    print(f"\nAuthentication status: {auth_status['status']}")
    
    if not drive.is_authenticated():
        print("\nTo authenticate:")
        print("1. Download OAuth2 credentials from Google Cloud Console")
        print("2. Save as 'credentials.json' in project root")
        print("3. Run drive.authenticate()")


if __name__ == "__main__":
    main()
