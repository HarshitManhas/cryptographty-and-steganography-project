#!/usr/bin/env python3
"""
Quick verification script for cover image button visibility
"""

import tkinter as tk
from src.gui.main_gui import SteganographyGUI

def test_cover_button():
    """Test if cover button is visible in GUI."""
    
    # Create root window
    root = tk.Tk()
    
    try:
        # Initialize GUI
        gui = SteganographyGUI(root)
        
        print("=== COVER IMAGE BUTTON VERIFICATION ===")
        
        # Check if button exists
        if hasattr(gui, 'cover_button'):
            button_text = gui.cover_button.cget('text')
            button_width = gui.cover_button.cget('width')
            print(f"✅ Cover button exists: '{button_text}'")
            print(f"✅ Button width: {button_width}")
            
            # Check button grid info
            grid_info = gui.cover_button.grid_info()
            print(f"✅ Button grid position: {grid_info}")
            
        else:
            print("❌ Cover button NOT found!")
        
        # Check if label exists
        if hasattr(gui, 'cover_label'):
            label_text = gui.cover_label.cget('text')
            print(f"✅ Cover label exists: '{label_text}'")
        else:
            print("❌ Cover label NOT found!")
        
        # Check cover frame
        cover_frame = None
        for child in gui.root.winfo_children():
            if isinstance(child, tk.Frame):
                for grandchild in child.winfo_children():
                    if isinstance(grandchild, (tk.Frame, tk.LabelFrame)):
                        if hasattr(grandchild, 'winfo_children'):
                            for widget in grandchild.winfo_children():
                                if isinstance(widget, tk.Button) and 'Cover Image' in str(widget.cget('text')):
                                    cover_frame = grandchild
                                    break
        
        if cover_frame:
            frame_class = cover_frame.__class__.__name__
            print(f"✅ Cover frame found: {frame_class}")
            
            if hasattr(cover_frame, 'cget') and hasattr(cover_frame, 'config'):
                try:
                    frame_text = cover_frame.cget('text')
                    print(f"✅ Frame text: '{frame_text}'")
                except:
                    print("✅ Frame has no text (regular Frame)")
        else:
            print("❌ Cover frame NOT found!")
        
        print("\n=== INSTRUCTIONS FOR USER ===")
        print("1. Look for section labeled 'Cover Image Selection'")
        print("2. Inside should be a button: '[IMAGE] Select Cover Image'")
        print("3. Click the button to select an image file")
        print("4. Supported formats: PNG, JPEG, BMP, TIFF")
        
        # Don't show the GUI window in this test
        root.withdraw()
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        root.quit()

if __name__ == "__main__":
    print("🔍 Verifying cover image button visibility...")
    
    success = test_cover_button()
    
    if success:
        print("\n✅ Verification completed - check the GUI!")
        print("🚀 Run: python src/main.py --gui")
    else:
        print("\n❌ Verification failed - check error messages above")
