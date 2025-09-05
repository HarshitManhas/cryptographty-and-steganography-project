"""
GUI Application for Steganography with Multi-Layer Encryption

This module provides a graphical user interface for the steganography application,
allowing users to easily select files, choose cover images, and manage the
encryption and steganography process.
"""

import os
import sys
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
from typing import Optional, Dict, Any
import logging
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from steganography.lsb_steganography import LSBSteganography
from encryption.dual_encryption import DualEncryption
from utils.file_utils import FileUtils
from cloud.cloud_storage import CloudStorage

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SteganographyGUI:
    """
    Main GUI application for steganography with multi-layer encryption.
    """
    
    def __init__(self, root):
        """
        Initialize the GUI application.
        
        Args:
            root: Tkinter root window
        """
        self.root = root
        self.root.title("Steganography with Multi-Layer Encryption")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Initialize modules
        self.stego = LSBSteganography()
        self.encryption = DualEncryption()
        self.file_utils = FileUtils()
        self.cloud = CloudStorage(provider="google_drive")
        
        # Application state
        self.selected_file_path = None
        self.selected_cover_image = None
        self.output_image_path = None
        self.current_operation = None
        
        # Create directories
        os.makedirs("keys", exist_ok=True)
        os.makedirs("output", exist_ok=True)
        os.makedirs("temp", exist_ok=True)
        
        # Setup GUI
        self.setup_gui()
        
        logger.info("Steganography GUI initialized")
    
    def setup_gui(self):
        """Setup the GUI layout and widgets."""
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        # Don't let row 6 expand, it should be fixed size
        # Let row 10 (log area) expand instead
        main_frame.rowconfigure(10, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Steganography with Multi-Layer Encryption", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # File selection section
        ttk.Label(main_frame, text="1. Select File/Text to Hide:", font=('Arial', 12, 'bold')).grid(
            row=1, column=0, columnspan=3, sticky=tk.W, pady=(0, 5))
        
        # File input frame
        file_frame = ttk.Frame(main_frame)
        file_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        file_frame.columnconfigure(1, weight=1)
        
        ttk.Button(file_frame, text="Select File", command=self.select_file).grid(
            row=0, column=0, padx=(0, 10))
        self.file_label = ttk.Label(file_frame, text="No file selected", foreground="gray")
        self.file_label.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        # Text input option
        ttk.Label(main_frame, text="Or enter text directly:", font=('Arial', 10)).grid(
            row=3, column=0, columnspan=3, sticky=tk.W, pady=(10, 5))
        
        self.text_input = scrolledtext.ScrolledText(main_frame, height=4, width=80)
        self.text_input.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Cover image selection
        ttk.Label(main_frame, text="2. Select Cover Image:", font=('Arial', 12, 'bold')).grid(
            row=5, column=0, columnspan=3, sticky=tk.W, pady=(10, 5))
        
        # Cover image frame - make it more visible with temporary styling
        cover_frame = ttk.LabelFrame(main_frame, text="Cover Image Selection", padding="10")
        cover_frame.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 15))
        cover_frame.columnconfigure(1, weight=1)
        
        # Make cover image button more prominent
        self.cover_button = ttk.Button(cover_frame, text="[IMAGE] Select Cover Image", 
                                      command=self.select_cover_image,
                                      width=25)
        self.cover_button.grid(row=0, column=0, padx=(0, 15), pady=5)
        
        self.cover_label = ttk.Label(cover_frame, text="No cover image selected", foreground="gray")
        self.cover_label.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # Options frame
        options_frame = ttk.LabelFrame(main_frame, text="Options", padding="10")
        options_frame.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        options_frame.columnconfigure(1, weight=1)
        
        # Password option
        self.use_password = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Use password protection", variable=self.use_password).grid(
            row=0, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        # Cloud storage option
        self.use_cloud = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Force upload to Google Drive", 
                       variable=self.use_cloud).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        # Output file selection
        ttk.Label(options_frame, text="Output file:").grid(row=2, column=0, sticky=tk.W, pady=(10, 2))
        
        output_frame = ttk.Frame(options_frame)
        output_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        output_frame.columnconfigure(1, weight=1)
        
        ttk.Button(output_frame, text="Choose Output", command=self.select_output_file).grid(
            row=0, column=0, padx=(0, 10))
        self.output_label = ttk.Label(output_frame, text="output/stego_image.png", foreground="gray")
        self.output_label.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        # Google Drive section
        gdrive_frame = ttk.LabelFrame(main_frame, text="Google Drive Integration", padding="10")
        gdrive_frame.grid(row=8, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        gdrive_frame.columnconfigure(1, weight=1)
        
        # Google Drive authentication status
        self.gdrive_status_var = tk.StringVar(value="Not authenticated")
        ttk.Label(gdrive_frame, text="Status:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.gdrive_status_label = ttk.Label(gdrive_frame, textvariable=self.gdrive_status_var, 
                                           foreground="red")
        self.gdrive_status_label.grid(row=0, column=1, sticky=tk.W)
        
        # Google Drive buttons
        gdrive_buttons = ttk.Frame(gdrive_frame)
        gdrive_buttons.grid(row=1, column=0, columnspan=2, pady=(10, 0))
        
        ttk.Button(gdrive_buttons, text="Sign In to Google Drive", 
                  command=self.authenticate_google_drive).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(gdrive_buttons, text="Upload File to Google Drive", 
                  command=self.upload_to_google_drive).pack(side=tk.LEFT, padx=(0, 10))
        
        # Action buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=9, column=0, columnspan=3, pady=20)
        
        ttk.Button(button_frame, text="Hide Data", command=self.hide_data, 
                  style="Accent.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Extract Data", command=self.extract_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Generate Keys", command=self.generate_keys).pack(side=tk.LEFT, padx=5)
        
        # Status and log area
        log_frame = ttk.LabelFrame(main_frame, text="Status & Log", padding="10")
        log_frame.grid(row=10, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(1, weight=1)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(log_frame, textvariable=self.status_var, font=('Arial', 10, 'bold'))
        status_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        # Progress bar
        self.progress = ttk.Progressbar(log_frame, mode='indeterminate')
        self.progress.grid(row=0, column=1, sticky=tk.E, padx=(10, 0))
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(log_frame, height=12, width=100)
        self.log_text.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(5, 0))
        
        # Set default output path
        self.output_image_path = "output/stego_image.png"
        
        # Log initial status
        self.log_message("Steganography GUI initialized successfully")
        self.log_message(f"File size threshold: {self.file_utils._human_readable_size(self.file_utils.SMALL_FILE_THRESHOLD)}")
        
        # Debug: Log cover button status
        if hasattr(self, 'cover_button'):
            self.log_message(f"Cover image button created: {self.cover_button.cget('text')}")
        else:
            self.log_message("WARNING: Cover image button not created!", "WARNING")
            
        self.check_authentication_status()
    
    def log_message(self, message: str, level: str = "INFO"):
        """
        Add a message to the log area.
        
        Args:
            message (str): Message to log
            level (str): Log level (INFO, WARNING, ERROR)
        """
        import datetime
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {message}\n"
        
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        
        # Also log to console
        logger.info(f"{level}: {message}")
    
    def update_status(self, message: str):
        """Update the status bar."""
        self.status_var.set(message)
        self.root.update_idletasks()
    
    def select_file(self):
        """Open file dialog to select a file to hide."""
        file_types = [
            ("All files", "*.*"),
            ("Text files", "*.txt"),
            ("PDF files", "*.pdf"),
            ("Images", "*.png *.jpg *.jpeg *.bmp *.gif"),
            ("Videos", "*.mp4 *.avi *.mov *.mkv"),
            ("Audio", "*.mp3 *.wav *.flac *.aac")
        ]
        
        file_path = filedialog.askopenfilename(
            title="Select file to hide",
            filetypes=file_types
        )
        
        if file_path:
            self.selected_file_path = file_path
            file_name = os.path.basename(file_path)
            
            # Get file info
            file_info = self.file_utils.get_file_info(file_path)
            
            # Update label
            self.file_label.config(
                text=f"{file_name} ({file_info.get('file_size_human', 'Unknown size')})",
                foreground="black"
            )
            
            # Update cloud storage option based on file size
            if file_info.get('should_use_cloud', False):
                self.use_cloud.set(True)
                self.log_message(f"Large file detected: {file_name} - Cloud storage recommended")
            else:
                self.use_cloud.set(False)
                self.log_message(f"File selected: {file_name} - Can be processed directly")
            
            # Clear text input
            self.text_input.delete(1.0, tk.END)
    
    def select_cover_image(self):
        """Open file dialog to select a cover image."""
        file_types = [
            ("PNG files", "*.png"),
            ("JPEG files", "*.jpg *.jpeg"),
            ("BMP files", "*.bmp"),
            ("TIFF files", "*.tiff *.tif"),
            ("All images", "*.png *.jpg *.jpeg *.bmp *.tiff *.tif")
        ]
        
        file_path = filedialog.askopenfilename(
            title="Select cover image",
            filetypes=file_types
        )
        
        if file_path:
            # Validate image
            if self.file_utils.is_supported_image(file_path):
                self.selected_cover_image = file_path
                file_name = os.path.basename(file_path)
                
                # Get image capacity
                capacity = self.stego.get_image_capacity(file_path)
                capacity_human = self.file_utils._human_readable_size(capacity // 8)
                
                self.cover_label.config(
                    text=f"{file_name} (Capacity: {capacity_human})",
                    foreground="black"
                )
                
                self.log_message(f"Cover image selected: {file_name}")
                self.log_message(f"Image capacity: {capacity_human}")
            else:
                messagebox.showerror("Error", "Selected file is not a supported image format.")
                self.log_message("Invalid image format selected", "ERROR")
    
    def select_output_file(self):
        """Select output file path."""
        file_path = filedialog.asksaveasfilename(
            title="Save stego image as",
            defaultextension=".png",
            filetypes=[
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg"),
                ("BMP files", "*.bmp")
            ]
        )
        
        if file_path:
            self.output_image_path = file_path
            file_name = os.path.basename(file_path)
            self.output_label.config(text=file_name, foreground="black")
            self.log_message(f"Output file set: {file_name}")
    
    def check_authentication_status(self):
        """Check and display authentication status."""
        # Check if RSA keys exist
        private_key_path = "keys/private_key.pem"
        public_key_path = "keys/public_key.pem"
        
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            self.log_message("RSA keys found")
        else:
            self.log_message("RSA keys not found - click 'Generate Keys' to create them", "WARNING")
        
        # Check Google Drive authentication
        if self.cloud.is_authenticated():
            self.log_message("Google Drive: Authenticated")
            self.gdrive_status_var.set("Authenticated ✓")
            self.gdrive_status_label.config(foreground="green")
        else:
            self.log_message("Google Drive: Not authenticated - click 'Sign In to Google Drive'", "WARNING")
            self.gdrive_status_var.set("Not authenticated")
            self.gdrive_status_label.config(foreground="red")
    
    def generate_keys(self):
        """Generate RSA key pair."""
        def generate_keys_thread():
            try:
                self.update_status("Generating RSA keys...")
                self.progress.start()
                
                private_key, public_key = self.encryption.generate_rsa_keys()
                self.encryption.save_keys(private_key, public_key, "keys")
                
                self.progress.stop()
                self.update_status("Ready")
                self.log_message("RSA keys generated successfully")
                
            except Exception as e:
                self.progress.stop()
                self.update_status("Ready")
                self.log_message(f"Error generating keys: {str(e)}", "ERROR")
                messagebox.showerror("Error", f"Failed to generate keys: {str(e)}")
        
        threading.Thread(target=generate_keys_thread, daemon=True).start()
    
    def authenticate_google_drive(self):
        """Authenticate with Google Drive."""
        def auth_thread():
            try:
                self.update_status("Signing in to Google Drive...")
                self.progress.start()
                
                if self.cloud.authenticate():
                    self.progress.stop()
                    self.update_status("Ready")
                    self.log_message("Google Drive authentication successful")
                    self.gdrive_status_var.set("Authenticated ✓")
                    self.gdrive_status_label.config(foreground="green")
                    messagebox.showinfo("Success", "Google Drive sign-in successful!\nYou can now upload files to Google Drive.")
                else:
                    self.progress.stop()
                    self.update_status("Ready")
                    self.log_message("Google Drive authentication failed", "ERROR")
                    self.gdrive_status_var.set("Authentication failed")
                    self.gdrive_status_label.config(foreground="red")
                    messagebox.showerror("Error", "Google Drive sign-in failed.\n\nPlease ensure:\n1. You have 'credentials.json' in the project root\n2. Google Drive API is enabled\n3. You have internet connection")
                    
            except Exception as e:
                self.progress.stop()
                self.update_status("Ready")
                self.log_message(f"Authentication error: {str(e)}", "ERROR")
                self.gdrive_status_var.set("Authentication error")
                self.gdrive_status_label.config(foreground="red")
                messagebox.showerror("Error", f"Authentication error: {str(e)}")
        
        threading.Thread(target=auth_thread, daemon=True).start()
    
    def upload_to_google_drive(self):
        """Upload a file to Google Drive and get shareable link."""
        if not self.cloud.is_authenticated():
            messagebox.showerror("Error", "Please sign in to Google Drive first!")
            return
        
        # Select file to upload
        file_types = [
            ("All files", "*.*"),
            ("Images", "*.png *.jpg *.jpeg *.bmp *.gif *.tiff"),
            ("Videos", "*.mp4 *.avi *.mov *.mkv *.webm"),
            ("Audio", "*.mp3 *.wav *.flac *.aac *.ogg"),
            ("Documents", "*.pdf *.docx *.doc *.txt"),
            ("Archives", "*.zip *.rar *.7z *.tar *.gz")
        ]
        
        file_path = filedialog.askopenfilename(
            title="Select file to upload to Google Drive",
            filetypes=file_types
        )
        
        if not file_path:
            return
        
        def upload_thread():
            try:
                file_name = os.path.basename(file_path)
                file_size = os.path.getsize(file_path)
                file_size_human = self.file_utils._human_readable_size(file_size)
                
                self.update_status(f"Uploading {file_name} to Google Drive...")
                self.progress.start()
                self.log_message(f"Starting upload: {file_name} ({file_size_human})")
                
                # Upload to Google Drive
                upload_result = self.cloud.upload_file(file_path)
                
                self.progress.stop()
                
                if upload_result:
                    self.update_status("Ready")
                    shareable_link = upload_result['cloud_url']
                    
                    self.log_message(f"✓ File uploaded successfully: {file_name}")
                    self.log_message(f"✓ Shareable link: {shareable_link}")
                    
                    # Show success dialog with link
                    self.show_upload_success(file_name, shareable_link, upload_result)
                    
                    # Automatically set this link as data to hide
                    self.selected_file_path = None  # Clear file selection
                    self.file_label.config(text="No file selected", foreground="gray")
                    
                    # Set the link in text input
                    self.text_input.delete(1.0, tk.END)
                    self.text_input.insert(1.0, f"Google Drive File: {file_name}\nLink: {shareable_link}")
                    
                    self.log_message("Ready to hide Google Drive link in cover image")
                    
                else:
                    self.update_status("Ready")
                    self.log_message(f"Failed to upload {file_name}", "ERROR")
                    messagebox.showerror("Upload Failed", f"Failed to upload {file_name} to Google Drive")
                    
            except Exception as e:
                self.progress.stop()
                self.update_status("Ready")
                self.log_message(f"Upload error: {str(e)}", "ERROR")
                messagebox.showerror("Upload Error", f"Error uploading file: {str(e)}")
        
        threading.Thread(target=upload_thread, daemon=True).start()
    
    def show_upload_success(self, file_name: str, shareable_link: str, upload_result: dict):
        """Show upload success dialog with file details."""
        success_window = tk.Toplevel(self.root)
        success_window.title("Upload Successful")
        success_window.geometry("600x400")
        success_window.resizable(True, True)
        
        # Title
        ttk.Label(success_window, text="✓ File Uploaded to Google Drive", 
                 font=('Arial', 14, 'bold'), foreground="green").pack(pady=10)
        
        # File details frame
        details_frame = ttk.LabelFrame(success_window, text="File Details", padding="10")
        details_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(details_frame, text=f"File Name: {file_name}", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        ttk.Label(details_frame, text=f"File Size: {upload_result.get('file_size', 'Unknown')} bytes").pack(anchor=tk.W)
        ttk.Label(details_frame, text=f"Upload Status: {upload_result.get('upload_status', 'Success')}").pack(anchor=tk.W)
        
        # Link frame
        link_frame = ttk.LabelFrame(success_window, text="Shareable Link", padding="10")
        link_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Link text area
        link_text = tk.Text(link_frame, height=4, wrap=tk.WORD, font=('Courier', 9))
        link_scrollbar = ttk.Scrollbar(link_frame, orient=tk.VERTICAL, command=link_text.yview)
        link_text.configure(yscrollcommand=link_scrollbar.set)
        
        link_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        link_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        link_text.insert(1.0, shareable_link)
        link_text.config(state=tk.DISABLED)
        
        # Buttons frame
        buttons_frame = ttk.Frame(success_window)
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def copy_link():
            success_window.clipboard_clear()
            success_window.clipboard_append(shareable_link)
            messagebox.showinfo("Copied", "Link copied to clipboard!")
        
        def open_in_browser():
            import webbrowser
            webbrowser.open(shareable_link)
        
        def continue_with_steganography():
            success_window.destroy()
            if not self.selected_cover_image:
                messagebox.showinfo("Next Step", "Please select a cover image to hide the Google Drive link!")
        
        ttk.Button(buttons_frame, text="Copy Link", command=copy_link).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Open in Browser", command=open_in_browser).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Continue with Steganography", command=continue_with_steganography).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Close", command=success_window.destroy).pack(side=tk.RIGHT, padx=5)
    
    def hide_data(self):
        """Hide data in the cover image."""
        def hide_data_thread():
            try:
                # Validate inputs
                if not self.selected_cover_image:
                    messagebox.showerror("Error", "Please select a cover image.")
                    return
                
                # Get data to hide
                data_to_hide = None
                
                if self.selected_file_path:
                    # File selected
                    file_info = self.file_utils.get_file_info(self.selected_file_path)
                    processing_method = file_info['processing_method']
                    
                    if processing_method == 'cloud_upload' or self.use_cloud.get():
                        # Upload to cloud and hide link
                        self.update_status("Uploading file to Google Drive...")
                        self.progress.start()
                        
                        upload_result = self.cloud.upload_file(self.selected_file_path)
                        if not upload_result:
                            raise Exception("Failed to upload file to Google Drive")
                        
                        data_to_hide = upload_result['cloud_url']
                        self.log_message(f"File uploaded to Google Drive: {upload_result['file_name']}")
                        self.log_message(f"Shareable link: {upload_result['cloud_url']}")
                        
                    else:
                        # Read file content for direct hiding
                        with open(self.selected_file_path, 'r', encoding='utf-8') as f:
                            data_to_hide = f.read()
                        
                elif self.text_input.get(1.0, tk.END).strip():
                    # Text input
                    data_to_hide = self.text_input.get(1.0, tk.END).strip()
                else:
                    messagebox.showerror("Error", "Please select a file or enter text to hide.")
                    return
                
                # Get password if needed
                password = None
                if self.use_password.get():
                    from tkinter.simpledialog import askstring
                    password = askstring("Password", "Enter password for encryption:", show='*')
                    if not password:
                        self.log_message("Password required but not provided", "WARNING")
                        return
                
                self.update_status("Encrypting data...")
                
                # Load public key
                public_key_path = "keys/public_key.pem"
                if not os.path.exists(public_key_path):
                    raise Exception("Public key not found. Please generate keys first.")
                
                public_key = self.encryption.load_key(public_key_path)
                
                # Encrypt data
                encrypted_data = self.encryption.dual_encrypt(data_to_hide, public_key, password)
                encrypted_json = json.dumps(encrypted_data)
                
                self.update_status("Embedding data in image...")
                
                # Embed in image
                success = self.stego.embed_data(
                    self.selected_cover_image, 
                    encrypted_json, 
                    self.output_image_path
                )
                
                self.progress.stop()
                
                if success:
                    self.update_status("Ready")
                    self.log_message(f"Data successfully hidden in: {self.output_image_path}")
                    
                    # Show success dialog in main thread to ensure proper responsiveness
                    def show_success():
                        result = messagebox.showinfo(
                            "Success", 
                            f"✅ Data Successfully Hidden!\n\n"
                            f"Output file: {os.path.basename(self.output_image_path)}\n"
                            f"Location: {os.path.dirname(os.path.abspath(self.output_image_path))}\n\n"
                            f"The image looks identical to the original but now contains your hidden data!"
                        )
                        return result
                    
                    # Schedule the dialog to run in the main thread
                    self.root.after(0, show_success)
                else:
                    raise Exception("Failed to embed data in image")
                    
            except Exception as e:
                self.progress.stop()
                self.update_status("Ready")
                self.log_message(f"Error hiding data: {str(e)}", "ERROR")
                
                # Show error dialog in main thread
                def show_error():
                    messagebox.showerror(
                        "Error", 
                        f"❌ Failed to Hide Data\n\n"
                        f"Error: {str(e)}\n\n"
                        f"Please check your inputs and try again."
                    )
                
                self.root.after(0, show_error)
        
        threading.Thread(target=hide_data_thread, daemon=True).start()
    
    def extract_data(self):
        """Extract data from a stego image."""
        def extract_data_thread():
            try:
                # Select stego image
                file_path = filedialog.askopenfilename(
                    title="Select stego image",
                    filetypes=[
                        ("PNG files", "*.png"),
                        ("JPEG files", "*.jpg *.jpeg"),
                        ("BMP files", "*.bmp"),
                        ("All images", "*.png *.jpg *.jpeg *.bmp")
                    ]
                )
                
                if not file_path:
                    return
                
                self.update_status("Extracting data from image...")
                self.progress.start()
                
                # Extract encrypted data
                encrypted_json = self.stego.extract_data(file_path)
                if not encrypted_json:
                    raise Exception("No encrypted data found in image")
                
                try:
                    encrypted_data = json.loads(encrypted_json)
                except json.JSONDecodeError:
                    raise Exception("Invalid encrypted data format")
                
                # Get password if needed
                password = None
                if self.use_password.get():
                    from tkinter.simpledialog import askstring
                    password = askstring("Password", "Enter password for decryption:", show='*')
                
                self.update_status("Decrypting data...")
                
                # Load private key
                private_key_path = "keys/private_key.pem"
                if not os.path.exists(private_key_path):
                    raise Exception("Private key not found. Please generate keys first.")
                
                private_key = self.encryption.load_key(private_key_path)
                
                # Decrypt data
                decrypted_data = self.encryption.dual_decrypt(encrypted_data, private_key, password)
                
                self.progress.stop()
                self.update_status("Ready")
                
                # Display result
                self.show_extracted_data(decrypted_data)
                
            except Exception as e:
                self.progress.stop()
                self.update_status("Ready")
                self.log_message(f"Error extracting data: {str(e)}", "ERROR")
                
                # Show error dialog in main thread
                def show_extract_error():
                    messagebox.showerror(
                        "Error", 
                        f"❌ Failed to Extract Data\n\n"
                        f"Error: {str(e)}\n\n"
                        f"Make sure you selected a valid stego image."
                    )
                
                self.root.after(0, show_extract_error)
        
        threading.Thread(target=extract_data_thread, daemon=True).start()
    
    def show_extracted_data(self, data: str):
        """Show extracted data in a new window."""
        result_window = tk.Toplevel(self.root)
        result_window.title("Extracted Data")
        result_window.geometry("600x400")
        
        # Check if data looks like a URL
        if data.startswith(("http://", "https://")):
            ttk.Label(result_window, text="Extracted Google Drive Link:", 
                     font=('Arial', 12, 'bold')).pack(pady=10)
            
            link_frame = ttk.Frame(result_window)
            link_frame.pack(fill=tk.X, padx=10, pady=5)
            
            link_text = tk.Text(link_frame, height=3, wrap=tk.WORD)
            link_text.pack(fill=tk.X)
            link_text.insert(1.0, data)
            link_text.config(state=tk.DISABLED)
            
            def copy_link():
                result_window.clipboard_clear()
                result_window.clipboard_append(data)
                messagebox.showinfo("Copied", "Link copied to clipboard!")
            
            ttk.Button(result_window, text="Copy Link", command=copy_link).pack(pady=5)
            
        else:
            ttk.Label(result_window, text="Extracted Text:", 
                     font=('Arial', 12, 'bold')).pack(pady=10)
        
        # Text area
        text_frame = ttk.Frame(result_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        text_area = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD)
        text_area.pack(fill=tk.BOTH, expand=True)
        text_area.insert(1.0, data)
        
        # Buttons
        button_frame = ttk.Frame(result_window)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def save_data():
            file_path = filedialog.asksaveasfilename(
                title="Save extracted data",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if file_path:
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(data)
                    messagebox.showinfo("Success", f"Data saved to: {os.path.basename(file_path)}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save data: {str(e)}")
        
        ttk.Button(button_frame, text="Save Data", command=save_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close", command=result_window.destroy).pack(side=tk.RIGHT, padx=5)
        
        self.log_message("Data extracted successfully")


def main():
    """Main function to run the GUI application."""
    root = tk.Tk()
    app = SteganographyGUI(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        logger.info("Application terminated by user")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        messagebox.showerror("Error", f"Unexpected error: {str(e)}")


if __name__ == "__main__":
    main()
