# VCC PKI System - Dashboard Launcher
# Simplified launcher with dependency management

import tkinter as tk
from tkinter import ttk, messagebox
import sys
import os
import subprocess
import importlib.util

def check_dependencies():
    """Check and install required dependencies"""
    required_packages = {
        'requests': 'requests',
        'PIL': 'Pillow',
        'matplotlib': 'matplotlib',
        'pandas': 'pandas'
    }
    
    missing_packages = []
    
    for module, package in required_packages.items():
        if importlib.util.find_spec(module) is None:
            missing_packages.append(package)
    
    if missing_packages:
        return missing_packages
    
    return []

def install_packages(packages):
    """Install missing packages"""
    try:
        for package in packages:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to install packages: {e}")
        return False

def show_dependency_dialog():
    """Show dependency installation dialog"""
    root = tk.Tk()
    root.withdraw()  # Hide main window
    
    missing = check_dependencies()
    if not missing:
        root.destroy()
        return True
    
    # Create dependency dialog
    dialog = tk.Toplevel(root)
    dialog.title("VCC PKI Dashboard - Dependencies")
    dialog.geometry("500x300")
    dialog.resizable(False, False)
    
    # Center dialog
    dialog.update_idletasks()
    x = (dialog.winfo_screenwidth() // 2) - (500 // 2)
    y = (dialog.winfo_screenheight() // 2) - (300 // 2)
    dialog.geometry(f'500x300+{x}+{y}')
    
    # Content
    ttk.Label(dialog, text="VCC PKI Dashboard - Dependency Check", 
              font=('Segoe UI', 14, 'bold')).pack(pady=20)
    
    ttk.Label(dialog, text="The following packages need to be installed:").pack(pady=10)
    
    # List missing packages
    for package in missing:
        ttk.Label(dialog, text=f"• {package}").pack()
    
    ttk.Label(dialog, text="\nClick 'Install' to automatically install dependencies.").pack(pady=20)
    
    result = {'install': False}
    
    def on_install():
        dialog.destroy()
        result['install'] = True
    
    def on_cancel():
        dialog.destroy()
        result['install'] = False
    
    button_frame = ttk.Frame(dialog)
    button_frame.pack(pady=20)
    
    ttk.Button(button_frame, text="Install Dependencies", 
               command=on_install).pack(side=tk.LEFT, padx=10)
    ttk.Button(button_frame, text="Cancel", 
               command=on_cancel).pack(side=tk.LEFT, padx=10)
    
    # Wait for dialog
    dialog.transient(root)
    dialog.grab_set()
    dialog.wait_window()
    
    root.destroy()
    return result['install']

def launch_dashboard():
    """Launch the main dashboard"""
    try:
        # Import and run dashboard
        from vcc_pki_dashboard import VCCPKIDashboard
        
        dashboard = VCCPKIDashboard()
        dashboard.run()
        
    except ImportError as e:
        messagebox.showerror("Import Error", 
                           f"Failed to import dashboard modules: {e}")
    except Exception as e:
        messagebox.showerror("Dashboard Error", 
                           f"Failed to start dashboard: {e}")

def main():
    """Main launcher function"""
    print("VCC PKI System - Dashboard Launcher")
    print("=" * 40)
    
    # Check dependencies
    missing = check_dependencies()
    
    if missing:
        print(f"Missing dependencies: {', '.join(missing)}")
        
        if show_dependency_dialog():
            print("Installing dependencies...")
            if install_packages(missing):
                print("✅ Dependencies installed successfully!")
                print("Starting dashboard...")
                launch_dashboard()
            else:
                messagebox.showerror("Installation Failed", 
                                   "Failed to install dependencies. Please install manually:\n\n" +
                                   "\n".join([f"pip install {pkg}" for pkg in missing]))
        else:
            print("❌ Installation cancelled by user.")
    else:
        print("✅ All dependencies satisfied.")
        print("Starting dashboard...")
        launch_dashboard()

if __name__ == "__main__":
    main()