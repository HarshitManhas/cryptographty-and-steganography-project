#!/usr/bin/env python3
"""
Test script to verify dialog responsiveness fix
"""

import tkinter as tk
from tkinter import messagebox
import threading
import time

def test_dialogs():
    """Test responsive dialog creation."""
    
    root = tk.Tk()
    root.title("Dialog Responsiveness Test")
    root.geometry("400x300")
    
    # Create main frame
    main_frame = tk.Frame(root, padding=20)
    main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
    
    # Title
    title = tk.Label(main_frame, text="Dialog Responsiveness Test", 
                    font=('Arial', 14, 'bold'))
    title.pack(pady=(0, 20))
    
    # Status
    status_var = tk.StringVar(value="Ready")
    status_label = tk.Label(main_frame, textvariable=status_var)
    status_label.pack(pady=(0, 20))
    
    def test_responsive_success():
        """Test success dialog using main thread scheduling."""
        def show_processing():
            status_var.set("Processing...")
            root.update()
            time.sleep(2)  # Simulate work
            
            # Show success dialog in main thread (FIXED METHOD)
            def show_success():
                result = messagebox.showinfo(
                    "Success", 
                    "✅ Data Successfully Hidden!\\n\\n"
                    "Output file: stego_image.png\\n"
                    "Location: /home/user/output/\\n\\n"
                    "The image looks identical but now contains your hidden data!"
                )
                status_var.set("Ready")
                return result
            
            # Schedule dialog in main thread - this ensures button responsiveness
            root.after(0, show_success)
        
        # Run processing in background thread
        threading.Thread(target=show_processing, daemon=True).start()
    
    def test_old_method():
        """Test old method that might cause unresponsive dialogs."""
        def show_processing_old():
            status_var.set("Processing (old method)...")
            time.sleep(2)  # Simulate work
            
            # This might cause unresponsive dialogs when called from thread
            messagebox.showinfo("Success", "Data hidden successfully!")
            status_var.set("Ready")
        
        threading.Thread(target=show_processing_old, daemon=True).start()
    
    def test_error_dialog():
        """Test error dialog."""
        def show_error():
            messagebox.showerror(
                "Error", 
                "❌ Failed to Hide Data\\n\\n"
                "Error: Cover image not selected\\n\\n"
                "Please check your inputs and try again."
            )
        
        root.after(0, show_error)
    
    # Test buttons
    btn_frame = tk.Frame(main_frame)
    btn_frame.pack(pady=20)
    
    tk.Button(btn_frame, text="Test Fixed Success Dialog", 
              command=test_responsive_success, bg='lightgreen').pack(pady=5, fill=tk.X)
    
    tk.Button(btn_frame, text="Test Old Method (May Not Respond)", 
              command=test_old_method, bg='lightcoral').pack(pady=5, fill=tk.X)
    
    tk.Button(btn_frame, text="Test Error Dialog", 
              command=test_error_dialog, bg='lightblue').pack(pady=5, fill=tk.X)
    
    # Instructions
    instructions = tk.Label(main_frame, 
                           text="Test the dialog buttons. The 'Fixed' version should have\\n"
                                "responsive OK buttons, while the old method might not.",
                           font=('Arial', 9), fg='gray')
    instructions.pack(pady=(20, 0))
    
    return root

if __name__ == "__main__":
    print("🧪 Testing dialog responsiveness fix...")
    
    try:
        root = test_dialogs()
        print("✅ Test GUI launched")
        print("🖱️ Click the buttons to test dialog responsiveness")
        print("💡 The 'Fixed' method should have responsive OK buttons")
        
        root.mainloop()
        
        print("✅ Test completed")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
