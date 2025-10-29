#!/usr/bin/env python3
"""
VCC Bulk Code Signing - GUI

Graphical interface for bulk code signing with:
- Directory selection (browse dialog)
- Key file selection (browse dialog)
- Classification filter (checkboxes)
- Dry-run preview
- Real-time progress tracking
- Statistics display
- Manifest generation
- Visual feedback (colors, progress bars)

Author: VCC Development Team
Date: 2025-10-13
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
from threading import Thread
from queue import Queue
import time

# Add src/ to path
SCRIPT_DIR = Path(__file__).parent.absolute()
SRC_DIR = SCRIPT_DIR.parent / 'src'
sys.path.insert(0, str(SRC_DIR))

# Import VCC tools
try:
    from code_manifest import CodeSigner, CodeVerifier
    from code_header import HeaderExtractor
    from classify_code import CodeClassifier
except ImportError as e:
    print(f"ERROR: Cannot import VCC tools: {e}")
    sys.exit(1)


# ==================== Data Classes ====================

class SigningJob:
    """Represents a signing job configuration."""
    def __init__(self):
        self.directory = ""
        self.private_key = ""
        self.public_key = ""
        self.classifications = []
        self.exclude_patterns = []
        self.recursive = True
        self.force = False
        self.dry_run = False
        self.generate_manifest = False
        self.manifest_output = ""


# ==================== Main GUI ====================

class BulkSigningGUI:
    """Main GUI window for bulk code signing."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("VCC Bulk Code Signing")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Job configuration
        self.job = SigningJob()
        
        # Queue for thread communication
        self.progress_queue = Queue()
        
        # Statistics
        self.stats = {
            'total': 0,
            'signed': 0,
            'skipped': 0,
            'failed': 0,
            'by_classification': {'PUBLIC': 0, 'INTERNAL': 0, 'CONFIDENTIAL': 0, 'SECRET': 0}
        }
        
        # Setup UI
        self._create_widgets()
        
        # Start progress updater
        self._update_progress()
    
    def _create_widgets(self):
        """Create all GUI widgets."""
        
        # Title
        title_frame = ttk.Frame(self.root, padding="10")
        title_frame.pack(fill=tk.X)
        
        title_label = ttk.Label(
            title_frame,
            text="VCC Bulk Code Signing",
            font=('Arial', 16, 'bold')
        )
        title_label.pack()
        
        subtitle_label = ttk.Label(
            title_frame,
            text="Sign Python files with ECDSA signatures",
            font=('Arial', 10)
        )
        subtitle_label.pack()
        
        # Main container
        main_container = ttk.Frame(self.root, padding="10")
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Left panel (configuration)
        left_panel = ttk.Frame(main_container)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Right panel (output)
        right_panel = ttk.Frame(main_container)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # === LEFT PANEL ===
        
        # Directory Selection
        dir_frame = ttk.LabelFrame(left_panel, text="Directory", padding="10")
        dir_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.dir_entry = ttk.Entry(dir_frame, width=40)
        self.dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        dir_browse_btn = ttk.Button(
            dir_frame,
            text="Browse...",
            command=self._browse_directory
        )
        dir_browse_btn.pack(side=tk.LEFT)
        
        # Key Files
        keys_frame = ttk.LabelFrame(left_panel, text="Keys", padding="10")
        keys_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Private Key
        ttk.Label(keys_frame, text="Private Key:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.private_key_entry = ttk.Entry(keys_frame, width=30)
        self.private_key_entry.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        ttk.Button(
            keys_frame,
            text="Browse...",
            command=lambda: self._browse_file('private_key')
        ).grid(row=0, column=2, pady=2)
        
        # Public Key
        ttk.Label(keys_frame, text="Public Key:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.public_key_entry = ttk.Entry(keys_frame, width=30)
        self.public_key_entry.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=2)
        ttk.Button(
            keys_frame,
            text="Browse...",
            command=lambda: self._browse_file('public_key')
        ).grid(row=1, column=2, pady=2)
        
        # Generate Keys Button
        ttk.Button(
            keys_frame,
            text="Generate New Keys",
            command=self._generate_keys
        ).grid(row=2, column=0, columnspan=3, pady=(10, 0))
        
        keys_frame.columnconfigure(1, weight=1)
        
        # Classification Filter
        class_frame = ttk.LabelFrame(left_panel, text="Classifications", padding="10")
        class_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.class_vars = {}
        classifications = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'SECRET']
        
        for i, cls in enumerate(classifications):
            var = tk.BooleanVar(value=True)
            self.class_vars[cls] = var
            cb = ttk.Checkbutton(class_frame, text=cls, variable=var)
            cb.grid(row=i//2, column=i%2, sticky=tk.W, padx=5, pady=2)
        
        # Options
        options_frame = ttk.LabelFrame(left_panel, text="Options", padding="10")
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.recursive_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_frame,
            text="Recursive (scan subdirectories)",
            variable=self.recursive_var
        ).pack(anchor=tk.W)
        
        self.force_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options_frame,
            text="Force (re-sign already signed files)",
            variable=self.force_var
        ).pack(anchor=tk.W)
        
        self.dry_run_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_frame,
            text="Dry Run (preview without signing)",
            variable=self.dry_run_var
        ).pack(anchor=tk.W)
        
        self.generate_manifest_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options_frame,
            text="Generate Manifest Database (JSON)",
            variable=self.generate_manifest_var
        ).pack(anchor=tk.W)
        
        # Action Buttons
        button_frame = ttk.Frame(left_panel)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.sign_button = ttk.Button(
            button_frame,
            text="Start Signing",
            command=self._start_signing,
            style='Accent.TButton'
        )
        self.sign_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.stop_button = ttk.Button(
            button_frame,
            text="Stop",
            command=self._stop_signing,
            state=tk.DISABLED
        )
        self.stop_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
        
        # === RIGHT PANEL ===
        
        # Progress
        progress_frame = ttk.LabelFrame(right_panel, text="Progress", padding="10")
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.progress_label = ttk.Label(progress_frame, text="Ready")
        self.progress_label.pack(anchor=tk.W)
        
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            mode='determinate',
            length=300
        )
        self.progress_bar.pack(fill=tk.X, pady=(5, 0))
        
        # Statistics
        stats_frame = ttk.LabelFrame(right_panel, text="Statistics", padding="10")
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.stats_text = tk.Text(stats_frame, height=6, wrap=tk.WORD, state=tk.DISABLED)
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        
        # Output Log
        log_frame = ttk.LabelFrame(right_panel, text="Output Log", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            height=20,
            state=tk.DISABLED
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure text tags for colored output
        self.log_text.tag_config('info', foreground='black')
        self.log_text.tag_config('success', foreground='green')
        self.log_text.tag_config('warning', foreground='orange')
        self.log_text.tag_config('error', foreground='red')
    
    # ==================== Event Handlers ====================
    
    def _browse_directory(self):
        """Browse for directory."""
        directory = filedialog.askdirectory(
            title="Select Directory to Sign"
        )
        if directory:
            self.dir_entry.delete(0, tk.END)
            self.dir_entry.insert(0, directory)
    
    def _browse_file(self, key_type):
        """Browse for key file."""
        file_path = filedialog.askopenfilename(
            title=f"Select {key_type.replace('_', ' ').title()}",
            filetypes=[
                ("PEM Files", "*.pem"),
                ("All Files", "*.*")
            ]
        )
        if file_path:
            if key_type == 'private_key':
                self.private_key_entry.delete(0, tk.END)
                self.private_key_entry.insert(0, file_path)
            else:
                self.public_key_entry.delete(0, tk.END)
                self.public_key_entry.insert(0, file_path)
    
    def _generate_keys(self):
        """Generate new ECDSA key pair."""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        # Ask for output directory
        output_dir = filedialog.askdirectory(
            title="Select Output Directory for Keys"
        )
        if not output_dir:
            return
        
        try:
            self._log("Generating ECDSA key pair...", 'info')
            
            # Generate private key
            private_key = ec.generate_private_key(
                ec.SECP256R1(),
                default_backend()
            )
            
            # Export keys
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Save keys
            private_key_path = Path(output_dir) / 'private_key.pem'
            public_key_path = Path(output_dir) / 'public_key.pem'
            
            with open(private_key_path, 'wb') as f:
                f.write(private_pem)
            
            with open(public_key_path, 'wb') as f:
                f.write(public_pem)
            
            # Update UI
            self.private_key_entry.delete(0, tk.END)
            self.private_key_entry.insert(0, str(private_key_path))
            
            self.public_key_entry.delete(0, tk.END)
            self.public_key_entry.insert(0, str(public_key_path))
            
            self._log(f"Keys generated successfully!", 'success')
            self._log(f"  Private: {private_key_path}", 'info')
            self._log(f"  Public: {public_key_path}", 'info')
            
            messagebox.showinfo(
                "Keys Generated",
                f"Keys saved to:\n\n"
                f"Private: {private_key_path}\n"
                f"Public: {public_key_path}\n\n"
                f"⚠️ Keep private key secret!"
            )
        
        except Exception as e:
            self._log(f"ERROR generating keys: {e}", 'error')
            messagebox.showerror("Error", f"Failed to generate keys:\n{e}")
    
    def _start_signing(self):
        """Start signing process in background thread."""
        # Validate inputs
        directory = self.dir_entry.get()
        if not directory:
            messagebox.showerror("Error", "Please select a directory")
            return
        
        if not Path(directory).exists():
            messagebox.showerror("Error", f"Directory not found: {directory}")
            return
        
        private_key = self.private_key_entry.get()
        if not private_key and not self.dry_run_var.get():
            messagebox.showerror("Error", "Please select a private key (or enable Dry Run)")
            return
        
        # Build job configuration
        self.job.directory = directory
        self.job.private_key = private_key
        self.job.public_key = self.public_key_entry.get()
        self.job.recursive = self.recursive_var.get()
        self.job.force = self.force_var.get()
        self.job.dry_run = self.dry_run_var.get()
        self.job.generate_manifest = self.generate_manifest_var.get()
        
        # Get selected classifications
        self.job.classifications = [
            cls for cls, var in self.class_vars.items() if var.get()
        ]
        
        if not self.job.classifications:
            messagebox.showerror("Error", "Please select at least one classification")
            return
        
        # Reset stats
        self.stats = {
            'total': 0,
            'signed': 0,
            'skipped': 0,
            'failed': 0,
            'by_classification': {'PUBLIC': 0, 'INTERNAL': 0, 'CONFIDENTIAL': 0, 'SECRET': 0}
        }
        
        # Clear log
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        
        # Update UI
        self.sign_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress_bar['value'] = 0
        
        # Start signing thread
        self.signing_thread = Thread(target=self._signing_worker, daemon=True)
        self.signing_thread.start()
    
    def _stop_signing(self):
        """Stop signing process."""
        self._log("Stopping...", 'warning')
        # TODO: Implement graceful stop
        self.sign_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
    
    def _signing_worker(self):
        """Worker thread for signing files."""
        try:
            # Import bulk signer
            sys.path.insert(0, str(SCRIPT_DIR))
            from bulk_sign_vcc import BulkCodeSigner
            
            # Log start
            self.progress_queue.put({
                'type': 'log',
                'message': f"Starting bulk signing...",
                'level': 'info'
            })
            
            self.progress_queue.put({
                'type': 'log',
                'message': f"Directory: {self.job.directory}",
                'level': 'info'
            })
            
            self.progress_queue.put({
                'type': 'log',
                'message': f"Dry Run: {self.job.dry_run}",
                'level': 'info'
            })
            
            self.progress_queue.put({
                'type': 'log',
                'message': f"Classifications: {', '.join(self.job.classifications)}",
                'level': 'info'
            })
            
            self.progress_queue.put({
                'type': 'log',
                'message': "",
                'level': 'info'
            })
            
            # Create signer
            signer = BulkCodeSigner(
                private_key_path=self.job.private_key if self.job.private_key else None,
                public_key_path=self.job.public_key if self.job.public_key else None,
                dry_run=self.job.dry_run,
                verbose=False
            )
            
            # Find files
            files = signer.find_python_files(self.job.directory, self.job.recursive)
            
            self.progress_queue.put({
                'type': 'log',
                'message': f"Found {len(files)} Python files",
                'level': 'info'
            })
            
            if not files:
                self.progress_queue.put({
                    'type': 'log',
                    'message': "No Python files found!",
                    'level': 'warning'
                })
                return
            
            # Sign files
            for i, file_path in enumerate(files, 1):
                # Classify
                classification, confidence = signer.classify_file(file_path)
                
                # Skip if not in selected classifications
                if classification not in self.job.classifications:
                    continue
                
                # Update progress
                self.progress_queue.put({
                    'type': 'progress',
                    'current': i,
                    'total': len(files),
                    'file': file_path.name,
                    'classification': classification
                })
                
                # Sign file
                result = signer.sign_file(file_path, classification, self.job.force)
                
                # Log result
                if result.skipped:
                    level = 'warning'
                    prefix = "[SKIP]"
                elif result.success:
                    level = 'success'
                    prefix = "[OK]"
                else:
                    level = 'error'
                    prefix = "[ERROR]"
                
                self.progress_queue.put({
                    'type': 'log',
                    'message': f"{prefix} {file_path.name} ({classification})",
                    'level': level
                })
                
                # Update stats
                self.stats['total'] += 1
                if result.success and not result.skipped:
                    self.stats['signed'] += 1
                    self.stats['by_classification'][classification] += 1
                elif result.skipped:
                    self.stats['skipped'] += 1
                else:
                    self.stats['failed'] += 1
                
                self.progress_queue.put({
                    'type': 'stats',
                    'stats': self.stats.copy()
                })
            
            # Generate manifest if requested
            if self.job.generate_manifest:
                self.progress_queue.put({
                    'type': 'log',
                    'message': "",
                    'level': 'info'
                })
                
                manifest_path = signer.generate_manifest_database()
                
                self.progress_queue.put({
                    'type': 'log',
                    'message': f"Manifest generated: {manifest_path}",
                    'level': 'success'
                })
            
            # Done
            self.progress_queue.put({
                'type': 'log',
                'message': "",
                'level': 'info'
            })
            
            self.progress_queue.put({
                'type': 'log',
                'message': "Signing completed!",
                'level': 'success'
            })
            
            self.progress_queue.put({'type': 'done'})
        
        except Exception as e:
            self.progress_queue.put({
                'type': 'log',
                'message': f"ERROR: {e}",
                'level': 'error'
            })
            
            self.progress_queue.put({'type': 'error', 'error': str(e)})
    
    def _update_progress(self):
        """Update UI from progress queue (called periodically)."""
        try:
            while not self.progress_queue.empty():
                msg = self.progress_queue.get_nowait()
                
                if msg['type'] == 'log':
                    self._log(msg['message'], msg['level'])
                
                elif msg['type'] == 'progress':
                    current = msg['current']
                    total = msg['total']
                    file = msg['file']
                    classification = msg['classification']
                    
                    percent = (current / total) * 100
                    self.progress_bar['value'] = percent
                    self.progress_label.config(
                        text=f"Processing {current}/{total}: {file} ({classification})"
                    )
                
                elif msg['type'] == 'stats':
                    self._update_stats(msg['stats'])
                
                elif msg['type'] == 'done':
                    self.sign_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)
                    self.progress_label.config(text="Completed!")
                    
                    messagebox.showinfo(
                        "Signing Complete",
                        f"Signed {self.stats['signed']} files\n"
                        f"Skipped {self.stats['skipped']} files\n"
                        f"Failed {self.stats['failed']} files"
                    )
                
                elif msg['type'] == 'error':
                    self.sign_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)
                    self.progress_label.config(text="Error!")
                    
                    messagebox.showerror("Error", f"Signing failed:\n{msg['error']}")
        
        except:
            pass
        
        # Schedule next update
        self.root.after(100, self._update_progress)
    
    def _log(self, message, level='info'):
        """Add message to log with color coding."""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + '\n', level)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def _update_stats(self, stats):
        """Update statistics display."""
        self.stats_text.config(state=tk.NORMAL)
        self.stats_text.delete(1.0, tk.END)
        
        text = f"Total Files: {stats['total']}\n"
        text += f"  Signed:  {stats['signed']}\n"
        text += f"  Skipped: {stats['skipped']}\n"
        text += f"  Failed:  {stats['failed']}\n\n"
        text += "By Classification:\n"
        for cls, count in stats['by_classification'].items():
            if count > 0:
                text += f"  {cls}: {count}\n"
        
        self.stats_text.insert(1.0, text)
        self.stats_text.config(state=tk.DISABLED)


# ==================== Main ====================

def main():
    """Main entry point."""
    root = tk.Tk()
    
    # Configure style
    style = ttk.Style()
    style.theme_use('clam')
    
    # Create GUI
    app = BulkSigningGUI(root)
    
    # Run
    root.mainloop()


if __name__ == '__main__':
    main()
