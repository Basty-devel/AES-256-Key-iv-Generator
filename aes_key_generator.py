import os
import tkinter as tk
from tkinter import ttk, messagebox

class AESKeyGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-256 Key/IV Generator")
        self.root.geometry("600x400")
        self.root.resizable(False, False)
        
        # Generate initial values
        self.key = os.urandom(32)  # 32 bytes = 256 bits
        self.iv = os.urandom(16)   # 16 bytes = 128 bits
        
        self.create_widgets()
        self.update_display()
        
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="AES-256 Encryption Key & IV Generator", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Key section
        key_header = ttk.Label(main_frame, text="Encryption Key (32 bytes, 256-bit):", 
                              font=("Arial", 10, "bold"))
        key_header.grid(row=1, column=0, sticky=tk.W, pady=(10, 5))
        
        self.key_text = tk.Text(main_frame, height=3, width=60, wrap=tk.WORD)
        self.key_text.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # IV section
        iv_header = ttk.Label(main_frame, text="Initialization Vector (16 bytes):", 
                             font=("Arial", 10, "bold"))
        iv_header.grid(row=3, column=0, sticky=tk.W, pady=(10, 5))
        
        self.iv_text = tk.Text(main_frame, height=2, width=60, wrap=tk.WORD)
        self.iv_text.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Format selection
        format_frame = ttk.Frame(main_frame)
        format_frame.grid(row=5, column=0, sticky=tk.W, pady=(10, 15))
        
        ttk.Label(format_frame, text="Display Format:").grid(row=0, column=0, sticky=tk.W)
        
        self.format_var = tk.StringVar(value="hex")
        formats = [("Hex", "hex"), ("Base64", "base64"), ("Escape Sequences", "escape"), ("Raw Bytes", "bytes")]
        
        for i, (text, value) in enumerate(formats):
            ttk.Radiobutton(format_frame, text=text, variable=self.format_var, 
                           value=value, command=self.update_display).grid(row=0, column=i+1, padx=(10, 0))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, pady=(10, 0))
        
        ttk.Button(button_frame, text="Generate New", command=self.generate_new).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(button_frame, text="Copy Key", command=self.copy_key).grid(row=0, column=1, padx=10)
        ttk.Button(button_frame, text="Copy IV", command=self.copy_iv).grid(row=0, column=2, padx=10)
        ttk.Button(button_frame, text="Copy Both", command=self.copy_both).grid(row=0, column=3, padx=10)
        ttk.Button(button_frame, text="Exit", command=self.root.destroy).grid(row=0, column=4, padx=(10, 0))
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
    def generate_new(self):
        self.key = os.urandom(32)
        self.iv = os.urandom(16)
        self.update_display()
        self.status_var.set("New key and IV generated")
        
    def update_display(self):
        format_type = self.format_var.get()
        
        if format_type == "hex":
            key_str = self.key.hex()
            iv_str = self.iv.hex()
        elif format_type == "base64":
            import base64
            key_str = base64.b64encode(self.key).decode('utf-8')
            iv_str = base64.b64encode(self.iv).decode('utf-8')
        elif format_type == "escape":
            key_str = ''.join(f'\\x{b:02x}' for b in self.key)
            iv_str = ''.join(f'\\x{b:02x}' for b in self.iv)
        else:  # bytes
            key_str = str(self.key)
            iv_str = str(self.iv)
        
        # Update text widgets
        self.key_text.delete(1.0, tk.END)
        self.key_text.insert(1.0, key_str)
        
        self.iv_text.delete(1.0, tk.END)
        self.iv_text.insert(1.0, iv_str)
        
    def copy_key(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.key_text.get(1.0, tk.END).strip())
        self.status_var.set("Key copied to clipboard")
        
    def copy_iv(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.iv_text.get(1.0, tk.END).strip())
        self.status_var.set("IV copied to clipboard")
        
    def copy_both(self):
        self.root.clipboard_clear()
        key_text = self.key_text.get(1.0, tk.END).strip()
        iv_text = self.iv_text.get(1.0, tk.END).strip()
        self.root.clipboard_append(f"Key: {key_text}\nIV: {iv_text}")
        self.status_var.set("Key and IV copied to clipboard")

if __name__ == "__main__":
    root = tk.Tk()
    app = AESKeyGenerator(root)
    root.mainloop()
