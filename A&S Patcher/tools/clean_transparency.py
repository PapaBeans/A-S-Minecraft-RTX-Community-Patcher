import os
import threading
import numpy as np
from PIL import Image
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import filedialog, Listbox, END

# Clean transparency by setting fully transparent pixels to black
# Returns True if the image was cleaned, False if skipped (no alpha/no transparent pixels)
def clean_transparency(input_path, output_path, threshold=10):
    image = Image.open(input_path)
    if image.mode not in ("RGBA", "LA", "PA"):
        # No alpha channel — nothing to clean
        return False
    image = image.convert("RGBA")
    arr = np.array(image)
    mask = arr[:, :, 3] <= threshold
    if not mask.any():
        return False  # No transparent pixels
    arr[mask] = [0, 0, 0, 0]
    Image.fromarray(arr, "RGBA").save(output_path)
    return True

# Process all TGA/PNG files in folder
def batch_clean_transparency(input_folder, output_folder, log_callback=None):
    os.makedirs(output_folder, exist_ok=True)
    cleaned = 0
    skipped = 0
    failed = 0
    for root, _, files in os.walk(input_folder):
        for filename in files:
            if filename.lower().endswith((".tga", ".png")):
                in_path = os.path.join(root, filename)
                
                # Recreate the exact subfolder structure in the output directory
                rel_path = os.path.relpath(root, input_folder)
                target_dir = os.path.join(output_folder, rel_path) if rel_path != "." else output_folder
                os.makedirs(target_dir, exist_ok=True)
                
                out_path = os.path.join(target_dir, os.path.splitext(filename)[0] + ".png")
                try:
                    if clean_transparency(in_path, out_path):
                        cleaned += 1
                        if log_callback:
                            log_callback(f"✓ Cleaned: {os.path.join(rel_path, filename) if rel_path != '.' else filename}")
                    else:
                        skipped += 1
                except (OSError, SyntaxError):
                    # Not a valid image (raw brarchive data, truncated, etc.) — skip silently
                    skipped += 1
                except Exception as e:
                    failed += 1
                    if log_callback:
                        log_callback(f"❌ Failed: {filename} ({e})")
    if log_callback:
        log_callback(f"✅ Done! {cleaned} cleaned, {skipped} skipped (no alpha), {failed} failed.")

# Select folder using file dialog
def select_folder(entry):
    path = filedialog.askdirectory()
    if path:
        entry.delete(0, END)
        entry.insert(0, path)

# Start button logic
def start_cleaning():
    input_folder = input_entry.get()
    output_folder = output_entry.get()
    log_box.delete(0, END)

    if not os.path.isdir(input_folder):
        log_box.insert(END, "❌ Invalid input folder.")
        return
    if not os.path.isdir(output_folder):
        log_box.insert(END, "❌ Invalid output folder.")
        return

    def log(msg):
        app.after(0, lambda m=msg: (log_box.insert(END, m), log_box.yview_moveto(1.0)))

    threading.Thread(target=batch_clean_transparency, args=(input_folder, output_folder, log), daemon=True).start()

# GUI setup
app = tb.Window(themename="darkly")
app.title("Transparency Cleaner")
app.geometry("600x400")
app.resizable(False, False)

# Input folder
tb.Label(app, text="Input Folder:").pack(pady=5)
input_frame = tb.Frame(app)
input_frame.pack(fill=X, padx=10)
input_entry = tb.Entry(input_frame)
input_entry.pack(side=LEFT, fill=X, expand=True)
tb.Button(input_frame, text="Browse", command=lambda: select_folder(input_entry)).pack(side=RIGHT, padx=5)

# Output folder
tb.Label(app, text="Output Folder:").pack(pady=5)
output_frame = tb.Frame(app)
output_frame.pack(fill=X, padx=10)
output_entry = tb.Entry(output_frame)
output_entry.pack(side=LEFT, fill=X, expand=True)
tb.Button(output_frame, text="Browse", command=lambda: select_folder(output_entry)).pack(side=RIGHT, padx=5)

# Start button
tb.Button(app, text="Clean Transparency", bootstyle=SUCCESS, command=start_cleaning).pack(pady=20)

# Log box
log_box = Listbox(app, height=10, bg="#1e1e1e", fg="white", selectbackground="#444", highlightthickness=0)
log_box.pack(fill=BOTH, expand=True, padx=10, pady=10)

# Run app
app.mainloop()
