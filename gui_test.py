#!/usr/bin/env python3
"""
GUI Troubleshooting Script

This script helps identify and troubleshoot GUI display issues.
"""

import tkinter as tk
from tkinter import ttk, filedialog
import os
import sys

def test_basic_gui():
    """Test basic GUI functionality."""
    
    def test_file_dialog():
        """Test file dialog functionality."""
        file_path = filedialog.askopenfilename(
            title="Test Cover Image Selection",
            filetypes=[
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg *.jpeg"),
                ("BMP files", "*.bmp"),
                ("All images", "*.png *.jpg *.jpeg *.bmp *.gif"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            result_label.config(text=f"✅ Selected: {os.path.basename(file_path)}", foreground="green")
            log_text.insert(tk.END, f"File selected: {file_path}\n")
        else:
            result_label.config(text="❌ No file selected", foreground="red")
            log_text.insert(tk.END, "No file selected\n")
        
        log_text.see(tk.END)
    
    def test_folder_access():
        """Test if we can access common image folders."""
        common_folders = [
            os.path.expanduser("~/Pictures"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Downloads"),
            "./temp",
            "./examples"
        ]
        
        log_text.insert(tk.END, "\n=== Folder Access Test ===\n")
        
        for folder in common_folders:
            if os.path.exists(folder):
                try:
                    files = os.listdir(folder)
                    image_files = [f for f in files if f.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif'))]
                    log_text.insert(tk.END, f"✅ {folder}: {len(image_files)} images found\n")
                except PermissionError:
                    log_text.insert(tk.END, f"❌ {folder}: Permission denied\n")
                except Exception as e:
                    log_text.insert(tk.END, f"❌ {folder}: Error - {str(e)}\n")
            else:
                log_text.insert(tk.END, f"⚠️  {folder}: Folder not found\n")
        
        log_text.see(tk.END)
    
    def create_test_image():
        """Create a test image for selection."""
        try:
            from PIL import Image
            import numpy as np
            
            # Create a simple test image
            os.makedirs("temp", exist_ok=True)
            
            # Create a colorful test image
            img_array = np.zeros((300, 400, 3), dtype=np.uint8)
            
            # Add some patterns
            img_array[:100, :, 0] = 255  # Red top
            img_array[100:200, :, 1] = 255  # Green middle
            img_array[200:, :, 2] = 255  # Blue bottom
            
            # Add some noise for texture
            noise = np.random.randint(0, 50, (300, 400, 3))
            img_array = np.clip(img_array.astype(int) + noise, 0, 255).astype(np.uint8)
            
            img = Image.fromarray(img_array)
            test_path = "temp/gui_test_image.png"
            img.save(test_path)
            
            log_text.insert(tk.END, f"✅ Test image created: {test_path}\n")
            result_label.config(text=f"Test image created: {test_path}", foreground="blue")
            
            return test_path
            
        except ImportError:
            log_text.insert(tk.END, "❌ PIL not available - cannot create test image\n")
            return None
        except Exception as e:
            log_text.insert(tk.END, f"❌ Error creating test image: {str(e)}\n")
            return None
    
    def show_system_info():
        """Display system information."""
        log_text.insert(tk.END, "\n=== System Information ===\n")
        log_text.insert(tk.END, f"Python version: {sys.version}\n")
        log_text.insert(tk.END, f"Tkinter version: {tk.TkVersion}\n")
        log_text.insert(tk.END, f"TTK version: {ttk.__dict__.get('__version__', 'Unknown')}\n")
        log_text.insert(tk.END, f"Current directory: {os.getcwd()}\n")
        log_text.insert(tk.END, f"Platform: {sys.platform}\n")
        
        # Check if we're in virtual environment
        if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
            log_text.insert(tk.END, "✅ Running in virtual environment\n")
        else:
            log_text.insert(tk.END, "⚠️  Not running in virtual environment\n")
        
        log_text.see(tk.END)
    
    # Create main window
    root = tk.Tk()
    root.title("GUI Troubleshooting Tool")
    root.geometry("700x600")
    
    # Main frame
    main_frame = ttk.Frame(root, padding="20")
    main_frame.pack(fill=tk.BOTH, expand=True)
    
    # Title
    title_label = ttk.Label(main_frame, text="🔧 GUI Troubleshooting Tool", 
                           font=('Arial', 16, 'bold'))
    title_label.pack(pady=(0, 20))
    
    # Instructions
    info_text = (
        "This tool helps troubleshoot GUI display issues.\n"
        "Test the file selection dialog to see if it works correctly."
    )
    ttk.Label(main_frame, text=info_text, justify=tk.CENTER).pack(pady=(0, 20))
    
    # Test buttons frame
    buttons_frame = ttk.Frame(main_frame)
    buttons_frame.pack(fill=tk.X, pady=(0, 20))
    
    ttk.Button(buttons_frame, text="🖼️ Test File Dialog", 
               command=test_file_dialog).pack(side=tk.LEFT, padx=5)
    ttk.Button(buttons_frame, text="📁 Test Folder Access", 
               command=test_folder_access).pack(side=tk.LEFT, padx=5)
    ttk.Button(buttons_frame, text="🎨 Create Test Image", 
               command=create_test_image).pack(side=tk.LEFT, padx=5)
    ttk.Button(buttons_frame, text="ℹ️ System Info", 
               command=show_system_info).pack(side=tk.LEFT, padx=5)
    
    # Result display
    result_frame = ttk.LabelFrame(main_frame, text="Result", padding="10")
    result_frame.pack(fill=tk.X, pady=(0, 20))
    
    result_label = ttk.Label(result_frame, text="No test run yet", foreground="gray")
    result_label.pack(fill=tk.X)
    
    # Log area
    log_frame = ttk.LabelFrame(main_frame, text="Log", padding="10")
    log_frame.pack(fill=tk.BOTH, expand=True)
    
    log_text = tk.Text(log_frame, height=20, wrap=tk.WORD)
    log_scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=log_text.yview)
    log_text.configure(yscrollcommand=log_scrollbar.set)
    
    log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    # Initial log message
    log_text.insert(tk.END, "🔧 GUI Troubleshooting Tool Ready\n")
    log_text.insert(tk.END, "Click the buttons above to run tests\n\n")
    
    # Show system info automatically
    show_system_info()
    
    return root, result_label, log_text

if __name__ == "__main__":
    print("🧪 Starting GUI troubleshooting...")
    
    try:
        root, result_label, log_text = test_basic_gui()
        print("✅ GUI troubleshooting tool started")
        print("🖥️  Window should now be visible")
        
        # Run the GUI
        root.mainloop()
        
        print("✅ Troubleshooting completed")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
