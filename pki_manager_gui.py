#!/usr/bin/env python3
"""
VCC PKI Manager - Tkinter GUI

A modern graphical user interface for managing the VCC PKI infrastructure.

Features:
- Certificate management (issue, renew, revoke, list)
- Service management (register, list, view)
- CA operations (info, initialization)
- CRL operations (generate, view)
- Health monitoring and statistics
- Real-time status updates
- Dark/Light theme support

Usage:
    python pki_manager_gui.py
    python pki_manager_gui.py --server https://pki.vcc.local:8443
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import json
import urllib.request
import urllib.error
import ssl
import threading
from datetime import datetime
from typing import Optional, Dict, List, Any
import sys


class PKIManagerGUI:
    """Main GUI application for PKI management."""
    
    def __init__(self, root: tk.Tk, server_url: str = "https://localhost:8443"):
        """
        Initialize PKI Manager GUI.
        
        Args:
            root: Tkinter root window
            server_url: PKI server URL
        """
        self.root = root
        self.server_url = server_url.rstrip('/')
        self.ssl_context = ssl._create_unverified_context()
        
        # Configure root window
        self.root.title("VCC PKI Manager")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        
        # Color scheme (professional dark theme)
        self.colors = {
            'bg': '#2b2b2b',
            'fg': '#e0e0e0',
            'accent': '#4a90e2',
            'success': '#4caf50',
            'warning': '#ff9800',
            'error': '#f44336',
            'card_bg': '#363636',
            'border': '#4a4a4a',
            'button_bg': '#4a90e2',
            'button_hover': '#357abd'
        }
        
        # Configure styles
        self.setup_styles()
        
        # Create UI
        self.create_widgets()
        
        # Load initial data
        self.refresh_certificates()
        self.refresh_services()
        self.refresh_health()
    
    def setup_styles(self):
        """Configure ttk styles."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('.', 
            background=self.colors['bg'],
            foreground=self.colors['fg'],
            fieldbackground=self.colors['card_bg'],
            bordercolor=self.colors['border'],
            darkcolor=self.colors['bg'],
            lightcolor=self.colors['card_bg'],
            troughcolor=self.colors['bg'],
            selectbackground=self.colors['accent'],
            selectforeground=self.colors['fg']
        )
        
        # Configure specific widgets
        style.configure('TFrame', background=self.colors['bg'])
        style.configure('TLabel', background=self.colors['bg'], foreground=self.colors['fg'])
        style.configure('TButton', background=self.colors['button_bg'], foreground=self.colors['fg'])
        style.map('TButton',
            background=[('active', self.colors['button_hover'])],
            foreground=[('active', self.colors['fg'])]
        )
        
        style.configure('Header.TLabel', font=('Arial', 14, 'bold'))
        style.configure('Title.TLabel', font=('Arial', 18, 'bold'))
        style.configure('Success.TLabel', foreground=self.colors['success'])
        style.configure('Warning.TLabel', foreground=self.colors['warning'])
        style.configure('Error.TLabel', foreground=self.colors['error'])
        
        # Treeview style
        style.configure('Treeview',
            background=self.colors['card_bg'],
            foreground=self.colors['fg'],
            fieldbackground=self.colors['card_bg'],
            borderwidth=1,
            relief='solid'
        )
        style.configure('Treeview.Heading',
            background=self.colors['accent'],
            foreground=self.colors['fg'],
            font=('Arial', 10, 'bold')
        )
        style.map('Treeview',
            background=[('selected', self.colors['accent'])],
            foreground=[('selected', self.colors['fg'])]
        )
    
    def create_widgets(self):
        """Create all GUI widgets."""
        # Configure root background
        self.root.configure(bg=self.colors['bg'])
        
        # Main container
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        self.create_header(main_container)
        
        # Content area with notebook (tabs)
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create tabs
        self.create_certificates_tab()
        self.create_services_tab()
        self.create_ca_tab()
        self.create_crl_tab()
        self.create_health_tab()
        
        # Status bar
        self.create_status_bar(main_container)
    
    def create_header(self, parent):
        """Create header with title and server info."""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Title
        title = ttk.Label(header_frame, text="VCC PKI Manager", style='Title.TLabel')
        title.pack(side=tk.LEFT)
        
        # Server info
        server_frame = ttk.Frame(header_frame)
        server_frame.pack(side=tk.RIGHT)
        
        ttk.Label(server_frame, text="Server:").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(server_frame, text=self.server_url, foreground=self.colors['accent']).pack(side=tk.LEFT)
        
        # Refresh button
        refresh_btn = ttk.Button(server_frame, text="🔄 Refresh All", command=self.refresh_all)
        refresh_btn.pack(side=tk.LEFT, padx=(10, 0))
    
    def create_certificates_tab(self):
        """Create certificates management tab."""
        cert_frame = ttk.Frame(self.notebook)
        self.notebook.add(cert_frame, text="📜 Certificates")
        
        # Toolbar
        toolbar = ttk.Frame(cert_frame)
        toolbar.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(toolbar, text="➕ Issue Certificate", command=self.issue_certificate).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="🔄 Renew Certificate", command=self.renew_certificate).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="🚫 Revoke Certificate", command=self.revoke_certificate).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="ℹ️ Certificate Info", command=self.show_certificate_info).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="🔄 Refresh", command=self.refresh_certificates).pack(side=tk.LEFT, padx=5)
        
        # Filter
        filter_frame = ttk.Frame(cert_frame)
        filter_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        self.cert_filter = ttk.Combobox(filter_frame, values=["All", "Active", "Expired", "Revoked"], state='readonly', width=15)
        self.cert_filter.set("All")
        self.cert_filter.pack(side=tk.LEFT, padx=5)
        self.cert_filter.bind('<<ComboboxSelected>>', lambda e: self.refresh_certificates())
        
        # Certificates tree
        tree_frame = ttk.Frame(cert_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Tree
        columns = ("Service ID", "Common Name", "Status", "Serial", "Expires", "Days Left")
        self.cert_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', 
                                      yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        vsb.config(command=self.cert_tree.yview)
        hsb.config(command=self.cert_tree.xview)
        
        # Configure columns
        self.cert_tree.heading("Service ID", text="Service ID")
        self.cert_tree.heading("Common Name", text="Common Name")
        self.cert_tree.heading("Status", text="Status")
        self.cert_tree.heading("Serial", text="Serial Number")
        self.cert_tree.heading("Expires", text="Expires At")
        self.cert_tree.heading("Days Left", text="Days Left")
        
        self.cert_tree.column("Service ID", width=150)
        self.cert_tree.column("Common Name", width=250)
        self.cert_tree.column("Status", width=100)
        self.cert_tree.column("Serial", width=150)
        self.cert_tree.column("Expires", width=150)
        self.cert_tree.column("Days Left", width=100)
        
        self.cert_tree.pack(fill=tk.BOTH, expand=True)
        
        # Bind double-click
        self.cert_tree.bind('<Double-1>', lambda e: self.show_certificate_info())
    
    def create_services_tab(self):
        """Create services management tab."""
        service_frame = ttk.Frame(self.notebook)
        self.notebook.add(service_frame, text="🔧 Services")
        
        # Toolbar
        toolbar = ttk.Frame(service_frame)
        toolbar.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(toolbar, text="➕ Register Service", command=self.register_service).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="ℹ️ Service Info", command=self.show_service_info).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="🔄 Refresh", command=self.refresh_services).pack(side=tk.LEFT, padx=5)
        
        # Services tree
        tree_frame = ttk.Frame(service_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Tree
        columns = ("Service ID", "Name", "Status", "Endpoints", "Registered")
        self.service_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', 
                                         yscrollcommand=vsb.set)
        
        vsb.config(command=self.service_tree.yview)
        
        # Configure columns
        self.service_tree.heading("Service ID", text="Service ID")
        self.service_tree.heading("Name", text="Service Name")
        self.service_tree.heading("Status", text="Status")
        self.service_tree.heading("Endpoints", text="Endpoints")
        self.service_tree.heading("Registered", text="Registered At")
        
        self.service_tree.column("Service ID", width=150)
        self.service_tree.column("Name", width=250)
        self.service_tree.column("Status", width=100)
        self.service_tree.column("Endpoints", width=100)
        self.service_tree.column("Registered", width=200)
        
        self.service_tree.pack(fill=tk.BOTH, expand=True)
        
        # Bind double-click
        self.service_tree.bind('<Double-1>', lambda e: self.show_service_info())
    
    def create_ca_tab(self):
        """Create CA management tab."""
        ca_frame = ttk.Frame(self.notebook)
        self.notebook.add(ca_frame, text="🔐 Certificate Authority")
        
        # Toolbar
        toolbar = ttk.Frame(ca_frame)
        toolbar.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(toolbar, text="🔄 Refresh CA Info", command=self.refresh_ca_info).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="💾 Download CA Bundle", command=self.download_ca_bundle).pack(side=tk.LEFT, padx=5)
        
        # CA Info display
        info_frame = ttk.Frame(ca_frame)
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        self.ca_text = scrolledtext.ScrolledText(info_frame, 
            wrap=tk.WORD, 
            bg=self.colors['card_bg'], 
            fg=self.colors['fg'],
            font=('Consolas', 10),
            relief='solid',
            borderwidth=1
        )
        self.ca_text.pack(fill=tk.BOTH, expand=True)
        
        # Load CA info
        self.refresh_ca_info()
    
    def create_crl_tab(self):
        """Create CRL management tab."""
        crl_frame = ttk.Frame(self.notebook)
        self.notebook.add(crl_frame, text="📋 CRL")
        
        # Toolbar
        toolbar = ttk.Frame(crl_frame)
        toolbar.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(toolbar, text="🔄 Generate CRL", command=self.generate_crl).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="ℹ️ CRL Info", command=self.refresh_crl_info).pack(side=tk.LEFT, padx=5)
        
        # CRL Info display
        info_frame = ttk.Frame(crl_frame)
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        self.crl_text = scrolledtext.ScrolledText(info_frame,
            wrap=tk.WORD,
            bg=self.colors['card_bg'],
            fg=self.colors['fg'],
            font=('Consolas', 10),
            relief='solid',
            borderwidth=1
        )
        self.crl_text.pack(fill=tk.BOTH, expand=True)
        
        # Load CRL info
        self.refresh_crl_info()
    
    def create_health_tab(self):
        """Create health monitoring tab."""
        health_frame = ttk.Frame(self.notebook)
        self.notebook.add(health_frame, text="💚 Health")
        
        # Toolbar
        toolbar = ttk.Frame(health_frame)
        toolbar.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(toolbar, text="🔄 Refresh Health", command=self.refresh_health).pack(side=tk.LEFT, padx=5)
        
        # Health info display
        info_frame = ttk.Frame(health_frame)
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        self.health_text = scrolledtext.ScrolledText(info_frame,
            wrap=tk.WORD,
            bg=self.colors['card_bg'],
            fg=self.colors['fg'],
            font=('Consolas', 10),
            relief='solid',
            borderwidth=1
        )
        self.health_text.pack(fill=tk.BOTH, expand=True)
        
        # Load health info
        self.refresh_health()
    
    def create_status_bar(self, parent):
        """Create status bar at bottom."""
        self.status_bar = ttk.Label(parent, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, pady=(10, 0))
    
    # ==================== API Methods ====================
    
    def make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Optional[Dict]:
        """
        Make HTTP request to PKI server.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            data: Request data
            
        Returns:
            Response data or None on error
        """
        url = f"{self.server_url}{endpoint}"
        
        try:
            if data:
                json_data = json.dumps(data).encode('utf-8')
                headers = {'Content-Type': 'application/json'}
                req = urllib.request.Request(url, data=json_data, headers=headers, method=method)
            else:
                req = urllib.request.Request(url, method=method)
            
            with urllib.request.urlopen(req, context=self.ssl_context) as response:
                response_data = response.read().decode('utf-8')
                return json.loads(response_data)
        
        except urllib.error.HTTPError as e:
            error_data = e.read().decode('utf-8')
            try:
                error_json = json.loads(error_data)
                error_msg = error_json.get('detail', str(e))
            except:
                error_msg = str(e)
            
            messagebox.showerror("HTTP Error", f"Error {e.code}: {error_msg}")
            return None
        
        except urllib.error.URLError as e:
            messagebox.showerror("Connection Error", 
                f"Cannot connect to PKI server:\n{e.reason}\n\nIs the server running at {self.server_url}?")
            return None
        
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {str(e)}")
            return None
    
    # ==================== Certificate Operations ====================
    
    def refresh_certificates(self):
        """Refresh certificates list."""
        self.set_status("Loading certificates...")
        
        # Get filter
        status_filter = self.cert_filter.get()
        if status_filter != "All":
            endpoint = f"/api/certificates?status={status_filter.lower()}"
        else:
            endpoint = "/api/certificates"
        
        response = self.make_request("GET", endpoint)
        
        if response:
            # Clear tree
            for item in self.cert_tree.get_children():
                self.cert_tree.delete(item)
            
            # Add certificates
            certificates = response.get('certificates', [])
            for cert in certificates:
                # Color code by status
                tags = ()
                if cert['status'] == 'active':
                    tags = ('active',)
                elif cert['status'] == 'expired':
                    tags = ('expired',)
                elif cert['status'] == 'revoked':
                    tags = ('revoked',)
                
                self.cert_tree.insert('', 'end', values=(
                    cert['service_id'],
                    cert['common_name'],
                    cert['status'].upper(),
                    cert['serial_number'][:16] + "...",
                    cert['expires_at'][:10],
                    cert['days_until_expiry']
                ), tags=tags)
            
            # Configure tags
            self.cert_tree.tag_configure('active', foreground=self.colors['success'])
            self.cert_tree.tag_configure('expired', foreground=self.colors['warning'])
            self.cert_tree.tag_configure('revoked', foreground=self.colors['error'])
            
            self.set_status(f"Loaded {len(certificates)} certificate(s)")
        else:
            self.set_status("Failed to load certificates")
    
    def issue_certificate(self):
        """Show dialog to issue new certificate."""
        dialog = IssueDialog(self.root, self)
        self.root.wait_window(dialog.top)
        
        if dialog.result:
            self.refresh_certificates()
    
    def renew_certificate(self):
        """Renew selected certificate."""
        selection = self.cert_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a certificate to renew")
            return
        
        service_id = self.cert_tree.item(selection[0])['values'][0]
        
        if messagebox.askyesno("Confirm Renewal", f"Renew certificate for {service_id}?"):
            data = {"service_id": service_id, "validity_days": 365}
            response = self.make_request("POST", "/api/certificates/renew", data)
            
            if response:
                messagebox.showinfo("Success", f"Certificate renewed successfully!\n\nExpires: {response.get('valid_until')}")
                self.refresh_certificates()
    
    def revoke_certificate(self):
        """Revoke selected certificate."""
        selection = self.cert_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a certificate to revoke")
            return
        
        service_id = self.cert_tree.item(selection[0])['values'][0]
        
        # Show reason dialog
        dialog = RevokeDialog(self.root, service_id)
        self.root.wait_window(dialog.top)
        
        if dialog.result:
            self.refresh_certificates()
            messagebox.showinfo("Success", "Certificate revoked successfully!")
    
    def show_certificate_info(self):
        """Show detailed certificate information."""
        selection = self.cert_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a certificate")
            return
        
        service_id = self.cert_tree.item(selection[0])['values'][0]
        response = self.make_request("GET", f"/api/certificates/{service_id}")
        
        if response:
            CertInfoDialog(self.root, response)
    
    # ==================== Service Operations ====================
    
    def refresh_services(self):
        """Refresh services list."""
        self.set_status("Loading services...")
        
        response = self.make_request("GET", "/api/services")
        
        if response:
            # Clear tree
            for item in self.service_tree.get_children():
                self.service_tree.delete(item)
            
            # Add services
            services = response.get('services', [])
            for svc in services:
                self.service_tree.insert('', 'end', values=(
                    svc['service_id'],
                    svc['service_name'],
                    svc['status'].upper(),
                    len(svc.get('endpoints', [])),
                    svc['registered_at'][:10]
                ))
            
            self.set_status(f"Loaded {len(services)} service(s)")
        else:
            self.set_status("Failed to load services")
    
    def register_service(self):
        """Show dialog to register new service."""
        dialog = RegisterServiceDialog(self.root, self)
        self.root.wait_window(dialog.top)
        
        if dialog.result:
            self.refresh_services()
    
    def show_service_info(self):
        """Show detailed service information."""
        selection = self.service_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a service")
            return
        
        service_id = self.service_tree.item(selection[0])['values'][0]
        response = self.make_request("GET", f"/api/services/{service_id}")
        
        if response:
            ServiceInfoDialog(self.root, response)
    
    # ==================== CA Operations ====================
    
    def refresh_ca_info(self):
        """Refresh CA information."""
        self.set_status("Loading CA info...")
        
        response = self.make_request("GET", "/api/ca/info")
        
        if response:
            self.ca_text.delete(1.0, tk.END)
            
            # Format CA info
            output = "=" * 80 + "\n"
            output += "CERTIFICATE AUTHORITY INFORMATION\n"
            output += "=" * 80 + "\n\n"
            
            if response.get('root_ca'):
                root = response['root_ca']
                output += "ROOT CA:\n"
                output += "-" * 80 + "\n"
                output += f"  Subject:     {root.get('subject', 'N/A')}\n"
                output += f"  Serial:      {root.get('serial_number', 'N/A')}\n"
                output += f"  Valid From:  {root.get('not_before', 'N/A')}\n"
                output += f"  Valid Until: {root.get('not_after', 'N/A')}\n"
                output += f"  Key Size:    {root.get('key_size', 'N/A')} bits\n"
                output += "\n"
            
            if response.get('intermediate_ca'):
                inter = response['intermediate_ca']
                output += "INTERMEDIATE CA:\n"
                output += "-" * 80 + "\n"
                output += f"  Subject:     {inter.get('subject', 'N/A')}\n"
                output += f"  Serial:      {inter.get('serial_number', 'N/A')}\n"
                output += f"  Valid From:  {inter.get('not_before', 'N/A')}\n"
                output += f"  Valid Until: {inter.get('not_after', 'N/A')}\n"
                output += f"  Key Size:    {inter.get('key_size', 'N/A')} bits\n"
                output += f"  Issuer:      {inter.get('issuer', 'N/A')}\n"
            
            self.ca_text.insert(1.0, output)
            self.set_status("CA info loaded")
        else:
            self.set_status("Failed to load CA info")
    
    def download_ca_bundle(self):
        """Download CA bundle."""
        filename = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
            initialfile="ca_chain.pem"
        )
        
        if filename:
            try:
                url = f"{self.server_url}/api/ca/bundle"
                req = urllib.request.Request(url)
                
                with urllib.request.urlopen(req, context=self.ssl_context) as response:
                    content = response.read()
                
                with open(filename, 'wb') as f:
                    f.write(content)
                
                messagebox.showinfo("Success", f"CA bundle saved to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to download CA bundle:\n{str(e)}")
    
    # ==================== CRL Operations ====================
    
    def generate_crl(self):
        """Generate CRL."""
        if messagebox.askyesno("Confirm", "Generate Certificate Revocation List?"):
            self.set_status("Generating CRL...")
            response = self.make_request("POST", "/api/crl/generate", {})
            
            if response:
                messagebox.showinfo("Success", 
                    f"CRL generated successfully!\n\n"
                    f"Revoked Certificates: {response.get('revoked_count', 0)}\n"
                    f"Generated At: {response.get('generated_at', 'N/A')}")
                self.refresh_crl_info()
    
    def refresh_crl_info(self):
        """Refresh CRL information."""
        self.set_status("Loading CRL info...")
        
        response = self.make_request("GET", "/api/crl/info")
        
        if response:
            self.crl_text.delete(1.0, tk.END)
            
            output = "=" * 80 + "\n"
            output += "CERTIFICATE REVOCATION LIST (CRL) INFORMATION\n"
            output += "=" * 80 + "\n\n"
            output += f"Last Update:           {response.get('last_update', 'N/A')}\n"
            output += f"Next Update:           {response.get('next_update', 'N/A')}\n"
            output += f"Revoked Certificates:  {response.get('revoked_count', 0)}\n"
            output += f"CRL Number:            {response.get('crl_number', 'N/A')}\n"
            
            self.crl_text.insert(1.0, output)
            self.set_status("CRL info loaded")
        else:
            self.set_status("Failed to load CRL info")
    
    # ==================== Health Operations ====================
    
    def refresh_health(self):
        """Refresh health information."""
        self.set_status("Loading health info...")
        
        response = self.make_request("GET", "/api/health")
        
        if response:
            self.health_text.delete(1.0, tk.END)
            
            output = "=" * 80 + "\n"
            output += "SYSTEM HEALTH CHECK\n"
            output += "=" * 80 + "\n\n"
            
            status = response.get('status', 'unknown')
            output += f"Overall Status: {status.upper()}\n\n"
            
            output += "COMPONENTS:\n"
            output += "-" * 80 + "\n"
            components = response.get('components', {})
            for name, comp_status in components.items():
                icon = "✓" if comp_status == "healthy" else "✗"
                output += f"  {icon} {name}: {comp_status}\n"
            
            output += "\nSTATISTICS:\n"
            output += "-" * 80 + "\n"
            stats = response.get('statistics', {})
            output += f"  Total Certificates:    {stats.get('total_certificates', 0)}\n"
            output += f"  Active Certificates:   {stats.get('active_certificates', 0)}\n"
            output += f"  Revoked Certificates:  {stats.get('revoked_certificates', 0)}\n"
            output += f"  Registered Services:   {stats.get('registered_services', 0)}\n"
            
            output += "\nSERVER INFO:\n"
            output += "-" * 80 + "\n"
            output += f"  Version: {response.get('version', 'N/A')}\n"
            output += f"  Uptime:  {response.get('uptime', 'N/A')}\n"
            
            self.health_text.insert(1.0, output)
            self.set_status(f"Health check: {status.upper()}")
        else:
            self.set_status("Failed to load health info")
    
    # ==================== Utility Methods ====================
    
    def refresh_all(self):
        """Refresh all data."""
        self.refresh_certificates()
        self.refresh_services()
        self.refresh_ca_info()
        self.refresh_crl_info()
        self.refresh_health()
        self.set_status("All data refreshed")
    
    def set_status(self, message: str):
        """Update status bar."""
        self.status_bar.config(text=f"{datetime.now().strftime('%H:%M:%S')} - {message}")
        self.root.update_idletasks()


# ==================== Dialog Classes ====================

class IssueDialog:
    """Dialog for issuing new certificate."""
    
    def __init__(self, parent, gui):
        self.result = None
        self.gui = gui
        
        self.top = tk.Toplevel(parent)
        self.top.title("Issue Certificate")
        self.top.geometry("500x400")
        self.top.configure(bg=gui.colors['bg'])
        self.top.transient(parent)
        self.top.grab_set()
        
        # Service ID
        ttk.Label(self.top, text="Service ID:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.service_id = ttk.Entry(self.top, width=40)
        self.service_id.grid(row=0, column=1, padx=10, pady=5)
        
        # Common Name
        ttk.Label(self.top, text="Common Name:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.common_name = ttk.Entry(self.top, width=40)
        self.common_name.grid(row=1, column=1, padx=10, pady=5)
        
        # SAN DNS
        ttk.Label(self.top, text="SAN DNS (comma-separated):").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        self.san_dns = ttk.Entry(self.top, width=40)
        self.san_dns.grid(row=2, column=1, padx=10, pady=5)
        
        # SAN IP
        ttk.Label(self.top, text="SAN IP (comma-separated):").grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)
        self.san_ip = ttk.Entry(self.top, width=40)
        self.san_ip.grid(row=3, column=1, padx=10, pady=5)
        
        # Validity Days
        ttk.Label(self.top, text="Validity (days):").grid(row=4, column=0, sticky=tk.W, padx=10, pady=5)
        self.validity_days = ttk.Entry(self.top, width=40)
        self.validity_days.insert(0, "365")
        self.validity_days.grid(row=4, column=1, padx=10, pady=5)
        
        # Buttons
        btn_frame = ttk.Frame(self.top)
        btn_frame.grid(row=5, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="Issue", command=self.issue).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.top.destroy).pack(side=tk.LEFT, padx=5)
    
    def issue(self):
        service_id = self.service_id.get().strip()
        common_name = self.common_name.get().strip()
        
        if not service_id or not common_name:
            messagebox.showwarning("Validation Error", "Service ID and Common Name are required")
            return
        
        data = {
            "service_id": service_id,
            "common_name": common_name,
            "validity_days": int(self.validity_days.get())
        }
        
        san_dns = self.san_dns.get().strip()
        if san_dns:
            data["san_dns"] = [s.strip() for s in san_dns.split(',')]
        
        san_ip = self.san_ip.get().strip()
        if san_ip:
            data["san_ip"] = [s.strip() for s in san_ip.split(',')]
        
        response = self.gui.make_request("POST", "/api/certificates/issue", data)
        
        if response:
            messagebox.showinfo("Success", 
                f"Certificate issued successfully!\n\n"
                f"Certificate ID: {response.get('certificate_id')}\n"
                f"Valid Until: {response.get('valid_until')}")
            self.result = response
            self.top.destroy()


class RevokeDialog:
    """Dialog for revoking certificate."""
    
    def __init__(self, parent, service_id):
        self.result = None
        
        self.top = tk.Toplevel(parent)
        self.top.title("Revoke Certificate")
        self.top.geometry("400x200")
        self.top.transient(parent)
        self.top.grab_set()
        
        ttk.Label(self.top, text=f"Revoke certificate for: {service_id}").pack(pady=10)
        
        ttk.Label(self.top, text="Reason:").pack(pady=5)
        self.reason = ttk.Combobox(self.top, values=[
            "unspecified", "key_compromise", "ca_compromise",
            "affiliation_changed", "superseded", "cessation_of_operation"
        ], state='readonly', width=30)
        self.reason.set("unspecified")
        self.reason.pack(pady=5)
        
        btn_frame = ttk.Frame(self.top)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="Revoke", command=lambda: self.revoke(service_id)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.top.destroy).pack(side=tk.LEFT, padx=5)
    
    def revoke(self, service_id):
        if messagebox.askyesno("Confirm", "Are you sure you want to revoke this certificate?"):
            # Create a temporary reference to gui from parent
            parent_gui = self.top.master.master
            
            data = {"service_id": service_id, "reason": self.reason.get()}
            response = parent_gui.make_request("POST", "/api/certificates/revoke", data)
            
            if response:
                self.result = response
                self.top.destroy()


class RegisterServiceDialog:
    """Dialog for registering service."""
    
    def __init__(self, parent, gui):
        self.result = None
        self.gui = gui
        
        self.top = tk.Toplevel(parent)
        self.top.title("Register Service")
        self.top.geometry("500x300")
        self.top.configure(bg=gui.colors['bg'])
        self.top.transient(parent)
        self.top.grab_set()
        
        # Service ID
        ttk.Label(self.top, text="Service ID:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.service_id = ttk.Entry(self.top, width=40)
        self.service_id.grid(row=0, column=1, padx=10, pady=5)
        
        # Service Name
        ttk.Label(self.top, text="Service Name:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.service_name = ttk.Entry(self.top, width=40)
        self.service_name.grid(row=1, column=1, padx=10, pady=5)
        
        # Endpoints
        ttk.Label(self.top, text="Endpoints (comma-separated):").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        self.endpoints = ttk.Entry(self.top, width=40)
        self.endpoints.grid(row=2, column=1, padx=10, pady=5)
        
        # Health URL
        ttk.Label(self.top, text="Health Check URL:").grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)
        self.health_url = ttk.Entry(self.top, width=40)
        self.health_url.grid(row=3, column=1, padx=10, pady=5)
        
        # Buttons
        btn_frame = ttk.Frame(self.top)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="Register", command=self.register).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.top.destroy).pack(side=tk.LEFT, padx=5)
    
    def register(self):
        service_id = self.service_id.get().strip()
        service_name = self.service_name.get().strip()
        endpoints = self.endpoints.get().strip()
        
        if not service_id or not service_name or not endpoints:
            messagebox.showwarning("Validation Error", "Service ID, Name, and Endpoints are required")
            return
        
        data = {
            "service_id": service_id,
            "service_name": service_name,
            "endpoints": [e.strip() for e in endpoints.split(',')]
        }
        
        health_url = self.health_url.get().strip()
        if health_url:
            data["health_check_url"] = health_url
        
        response = self.gui.make_request("POST", "/api/services/register", data)
        
        if response:
            messagebox.showinfo("Success", "Service registered successfully!")
            self.result = response
            self.top.destroy()


class CertInfoDialog:
    """Dialog for displaying certificate details."""
    
    def __init__(self, parent, cert_data):
        top = tk.Toplevel(parent)
        top.title(f"Certificate Info - {cert_data.get('service_id')}")
        top.geometry("600x500")
        top.transient(parent)
        
        # Create text widget
        text = scrolledtext.ScrolledText(top, wrap=tk.WORD, font=('Consolas', 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Format certificate info
        output = "=" * 80 + "\n"
        output += "CERTIFICATE INFORMATION\n"
        output += "=" * 80 + "\n\n"
        output += f"Certificate ID:     {cert_data.get('certificate_id', 'N/A')}\n"
        output += f"Service ID:         {cert_data.get('service_id', 'N/A')}\n"
        output += f"Common Name:        {cert_data.get('common_name', 'N/A')}\n"
        output += f"Serial Number:      {cert_data.get('serial_number', 'N/A')}\n"
        output += f"Status:             {cert_data.get('status', 'N/A').upper()}\n"
        output += f"Issued At:          {cert_data.get('issued_at', 'N/A')}\n"
        output += f"Expires At:         {cert_data.get('expires_at', 'N/A')}\n"
        output += f"Days Until Expiry:  {cert_data.get('days_until_expiry', 'N/A')}\n"
        
        if cert_data.get('san_dns'):
            output += f"\nSAN DNS:\n"
            for dns in cert_data['san_dns']:
                output += f"  - {dns}\n"
        
        if cert_data.get('san_ip'):
            output += f"\nSAN IP:\n"
            for ip in cert_data['san_ip']:
                output += f"  - {ip}\n"
        
        if cert_data.get('revoked_at'):
            output += f"\n{'=' * 80}\n"
            output += "REVOCATION INFO:\n"
            output += "=" * 80 + "\n"
            output += f"Revoked At: {cert_data['revoked_at']}\n"
            output += f"Reason:     {cert_data.get('revocation_reason', 'N/A')}\n"
        
        text.insert(1.0, output)
        text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(top, text="Close", command=top.destroy).pack(pady=10)


class ServiceInfoDialog:
    """Dialog for displaying service details."""
    
    def __init__(self, parent, service_data):
        top = tk.Toplevel(parent)
        top.title(f"Service Info - {service_data.get('service_id')}")
        top.geometry("600x500")
        top.transient(parent)
        
        # Create text widget
        text = scrolledtext.ScrolledText(top, wrap=tk.WORD, font=('Consolas', 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Format service info
        output = "=" * 80 + "\n"
        output += "SERVICE INFORMATION\n"
        output += "=" * 80 + "\n\n"
        output += f"Service ID:       {service_data.get('service_id', 'N/A')}\n"
        output += f"Service Name:     {service_data.get('service_name', 'N/A')}\n"
        output += f"Status:           {service_data.get('status', 'N/A').upper()}\n"
        output += f"Registered At:    {service_data.get('registered_at', 'N/A')}\n"
        
        if service_data.get('endpoints'):
            output += f"\nEndpoints:\n"
            for ep in service_data['endpoints']:
                output += f"  - {ep}\n"
        
        if service_data.get('health_check_url'):
            output += f"\nHealth Check URL: {service_data['health_check_url']}\n"
        
        if service_data.get('metadata'):
            output += f"\nMetadata:\n"
            for key, value in service_data['metadata'].items():
                output += f"  {key}: {value}\n"
        
        if service_data.get('certificate'):
            cert = service_data['certificate']
            output += f"\n{'=' * 80}\n"
            output += "CERTIFICATE INFO:\n"
            output += "=" * 80 + "\n"
            output += f"Status:         {cert.get('status', 'N/A')}\n"
            output += f"Expires At:     {cert.get('expires_at', 'N/A')}\n"
            output += f"Days Until Expiry: {cert.get('days_until_expiry', 'N/A')}\n"
        
        text.insert(1.0, output)
        text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(top, text="Close", command=top.destroy).pack(pady=10)


# ==================== Main Entry Point ====================

def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='VCC PKI Manager GUI')
    parser.add_argument('--server', default='https://localhost:8443',
                        help='PKI server URL (default: https://localhost:8443)')
    args = parser.parse_args()
    
    root = tk.Tk()
    app = PKIManagerGUI(root, server_url=args.server)
    root.mainloop()


if __name__ == '__main__':
    main()
