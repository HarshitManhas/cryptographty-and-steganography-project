#!/usr/bin/env python3
"""
Simple GUI Test for Cover Image Selection

This script tests the cover image selection functionality in isolation.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import sys

# Add src directory to path  
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def test_cover_image_selection():
    """Test the cover image selection dialog."""
    
    def select_cover_image():
        """Open file dialog to select a cover image."""
        file_types = [
            ("PNG files", "*.png"),
            ("JPEG files", "*.jpg *.jpeg"),
            ("BMP files", "*.bmp"),
            ("TIFF files", "*.tiff *.tif"),
            ("All images", "*.png *.jpg *.jpeg *.bmp *.tiff *.tif *.gif")
        ]
        
        file_path = filedialog.askopenfilename(
            title="Select cover image",
            filetypes=file_types
        )
        
        if file_path:
            file_name = os.path.basename(file_path)
            cover_label.config(text=f"Selected: {file_name}", foreground="green")
            log_text.insert(tk.END, f"✅ Cover image selected: {file_name}\n")
            log_text.see(tk.END)
            messagebox.showinfo("Success", f"Cover image selected:\n{file_name}")
        else:
            log_text.insert(tk.END, "❌ No image selected\n")
            log_text.see(tk.END)
    
    def test_create_sample_images():
        """Create sample images for testing."""
        try:
            from PIL import Image
            import numpy as np
            
            # Create sample images in temp directory
            os.makedirs("temp", exist_ok=True)
            
            for size, name in [(400, "small"), (800, "medium"), (1200, "large")]:
                # Create random image
                img_array = np.random.randint(0, 256, (size, size, 3), dtype=np.uint8)
                img = Image.fromarray(img_array)
                img_path = f"temp/sample_{name}_{size}x{size}.png"
                img.save(img_path)
                log_text.insert(tk.END, f"✅ Created sample image: {img_path}\n")
            
            log_text.see(tk.END)
            messagebox.showinfo("Success", "Sample images created in temp/ directory!")
            
        except ImportError:
            log_text.insert(tk.END, "❌ PIL not available - cannot create sample images\n")
            log_text.see(tk.END)
            messagebox.showerror("Error", "PIL/Pillow not available")
        except Exception as e:
            log_text.insert(tk.END, f"❌ Error creating samples: {str(e)}\n")
            log_text.see(tk.END)
            messagebox.showerror("Error", f"Failed to create samples: {str(e)}")

    # Create main window
    root = tk.Tk()
    root.title("Cover Image Selection Test")
    root.geometry("600x500")
    
    # Main frame
    main_frame = ttk.Frame(root, padding="20")
    main_frame.pack(fill=tk.BOTH, expand=True)
    
    # Title
    ttk.Label(main_frame, text="Cover Image Selection Test", 
              font=('Arial', 16, 'bold')).pack(pady=(0, 20))
    
    # Instructions
    instructions = ttk.Label(main_frame, text=(
        "This test verifies the cover image selection functionality.\n"
        "Click the button below to select a cover image file."
    ))
    instructions.pack(pady=(0, 20))
    
    # Cover image selection
    select_frame = ttk.Frame(main_frame)
    select_frame.pack(fill=tk.X, pady=(0, 20))
    
    ttk.Button(select_frame, text="🖼️ Select Cover Image", 
               command=select_cover_image).pack(side=tk.LEFT, padx=(0, 10))
    
    cover_label = ttk.Label(select_frame, text="No image selected", foreground="gray")
    cover_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    # Sample creation button
    ttk.Button(main_frame, text="🎨 Create Sample Images", 
               command=test_create_sample_images).pack(pady=(0, 20))
    
    # Log area
    ttk.Label(main_frame, text="Log:", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
    log_text = tk.Text(main_frame, height=15, width=70)
    log_text.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
    
    # Initial log message
    log_text.insert(tk.END, "🔧 Cover Image Selection Test Ready\n")
    log_text.insert(tk.END, "📁 Select an image file or create sample images\n")
    log_text.insert(tk.END, "💡 Supported formats: PNG, JPEG, BMP, TIFF, GIF\n\n")
    
    # Close button
    ttk.Button(main_frame, text="Close", command=root.quit).pack(pady=(10, 0))
    
    return root

if __name__ == "__main__":
    print("🧪 Starting Cover Image Selection Test...")
    
    try:
        root = test_cover_image_selection()
        print("✅ Test GUI initialized successfully")
        print("🖥️  GUI window should now be visible")
        print("📝 Use the 'Select Cover Image' button to test functionality")
        
        # Start the GUI
        root.mainloop()
        
        print("✅ Test completed successfully")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
