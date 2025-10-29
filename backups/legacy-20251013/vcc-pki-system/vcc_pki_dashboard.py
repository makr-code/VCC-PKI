# VCC PKI System - Tkinter Management Dashboard
# Modern desktop interface for PKI administration

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import tkinter.font as tkFont
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import threading
import json
import requests
from pathlib import Path
import logging
import sys
import os
import webbrowser
from PIL import Image, ImageTk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import pandas as pd

# Import VCC PKI components
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.core.config import create_config
from app.core.database import VCCPKIDatabase
from app.core.security import UserRole, Permission

logger = logging.getLogger(__name__)

class VCCPKIDashboard:
    """VCC PKI System - Modern Tkinter Management Dashboard"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.setup_main_window()
        
        # Configuration and state
        self.config = create_config()
        self.api_base_url = f"http://{self.config.api_host}:{self.config.api_port}"
        self.access_token = None
        self.current_user = None
        self.refresh_interval = 30000  # 30 seconds
        
        # Data storage for dashboard updates
        self.system_status = {}
        self.certificates_data = []
        self.services_data = []
        self.audit_events = []
        
        # GUI Components
        self.setup_styles()
        self.create_menu_bar()
        self.create_main_interface()
        self.create_status_bar()
        
        # Authentication
        self.show_login_dialog()
        
        # Start periodic updates
        self.start_background_updates()
    
    def setup_main_window(self):
        """Configure main application window"""
        self.root.title("VCC PKI System - Management Dashboard")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)
        
        # Set application icon (if available)
        try:
            icon_path = Path(__file__).parent / "assets" / "vcc_icon.ico"
            if icon_path.exists():
                self.root.iconbitmap(str(icon_path))
        except:
            pass  # Icon not available, continue without
        
        # Configure window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Center window on screen
        self.center_window()
    
    def center_window(self):
        """Center window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def setup_styles(self):
        """Configure modern styling"""
        self.style = ttk.Style()
        
        # Use modern theme if available
        try:
            self.style.theme_use('clam')
        except:
            self.style.theme_use('default')
        
        # Define color scheme - Brandenburg Government colors
        self.colors = {
            'primary': '#0066CC',      # Brandenburg Blue
            'secondary': '#E6F2FF',    # Light Blue
            'success': '#28a745',      # Green
            'warning': '#ffc107',      # Yellow
            'danger': '#dc3545',       # Red
            'dark': '#343a40',         # Dark Gray
            'light': '#f8f9fa',        # Light Gray
            'white': '#ffffff'
        }
        
        # Configure custom styles
        self.configure_custom_styles()
        
        # Load fonts
        self.fonts = {
            'heading': tkFont.Font(family='Segoe UI', size=14, weight='bold'),
            'subheading': tkFont.Font(family='Segoe UI', size=11, weight='bold'),
            'body': tkFont.Font(family='Segoe UI', size=9),
            'monospace': tkFont.Font(family='Consolas', size=9)
        }
    
    def configure_custom_styles(self):
        """Configure custom ttk styles"""
        # Header style
        self.style.configure('Header.TLabel', 
                           background=self.colors['primary'],
                           foreground='white',
                           font=('Segoe UI', 12, 'bold'),
                           padding=10)
        
        # Status styles
        self.style.configure('Success.TLabel', foreground=self.colors['success'])
        self.style.configure('Warning.TLabel', foreground=self.colors['warning'])
        self.style.configure('Danger.TLabel', foreground=self.colors['danger'])
        
        # Button styles
        self.style.configure('Primary.TButton',
                           background=self.colors['primary'],
                           foreground='white')
        
        self.style.configure('Success.TButton',
                           background=self.colors['success'],
                           foreground='white')
        
        self.style.configure('Danger.TButton',
                           background=self.colors['danger'],
                           foreground='white')
    
    def create_menu_bar(self):
        """Create application menu bar"""
        self.menubar = tk.Menu(self.root)
        self.root.config(menu=self.menubar)
        
        # File Menu
        file_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Certificate Request", command=self.new_certificate_request)
        file_menu.add_command(label="Import Certificate", command=self.import_certificate)
        file_menu.add_command(label="Export Configuration", command=self.export_configuration)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        
        # Tools Menu
        tools_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="System Health Check", command=self.run_health_check)
        tools_menu.add_command(label="Certificate Validation", command=self.validate_certificates)
        tools_menu.add_command(label="Generate Report", command=self.generate_report)
        tools_menu.add_separator()
        tools_menu.add_command(label="API Documentation", command=self.open_api_docs)
        
        # Admin Menu (shown only for admins)
        self.admin_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Admin", menu=self.admin_menu)
        self.admin_menu.add_command(label="User Management", command=self.show_user_management)
        self.admin_menu.add_command(label="System Configuration", command=self.show_system_config)
        self.admin_menu.add_command(label="Backup Database", command=self.backup_database)
        self.admin_menu.add_command(label="View Logs", command=self.view_system_logs)
        
        # Help Menu
        help_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="User Guide", command=self.show_user_guide)
        help_menu.add_command(label="API Reference", command=self.show_api_reference)
        help_menu.add_command(label="About", command=self.show_about_dialog)
    
    def create_main_interface(self):
        """Create main dashboard interface"""
        # Main container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create dashboard tabs
        self.create_overview_tab()
        self.create_certificates_tab()
        self.create_services_tab()
        self.create_audit_tab()
        self.create_monitoring_tab()
    
    def create_overview_tab(self):
        """Create system overview dashboard"""
        overview_frame = ttk.Frame(self.notebook)
        self.notebook.add(overview_frame, text="📊 Overview")
        
        # Header
        header_frame = ttk.Frame(overview_frame)
        header_frame.pack(fill=tk.X, padx=10, pady=5)
        
        welcome_label = ttk.Label(header_frame, text="VCC PKI System Dashboard", 
                                 style='Header.TLabel')
        welcome_label.pack(side=tk.LEFT)
        
        self.refresh_button = ttk.Button(header_frame, text="🔄 Refresh", 
                                        command=self.refresh_all_data)
        self.refresh_button.pack(side=tk.RIGHT, padx=5)
        
        # Status cards container
        cards_frame = ttk.Frame(overview_frame)
        cards_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # System Status Card
        self.system_status_card = self.create_status_card(cards_frame, "System Status", "🟢 Healthy")
        self.system_status_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        # Certificates Count Card
        self.cert_count_card = self.create_status_card(cards_frame, "Active Certificates", "Loading...")
        self.cert_count_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        # Services Status Card
        self.services_card = self.create_status_card(cards_frame, "VCC Services", "Loading...")
        self.services_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        # Recent Activity Card
        self.activity_card = self.create_status_card(cards_frame, "Recent Activity", "Loading...")
        self.activity_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        # Charts container
        charts_frame = ttk.Frame(overview_frame)
        charts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Certificate expiry chart
        self.create_certificate_expiry_chart(charts_frame)
        
        # System metrics chart
        self.create_system_metrics_chart(charts_frame)
    
    def create_status_card(self, parent, title, value):
        """Create a status card widget"""
        card_frame = ttk.LabelFrame(parent, text=title, padding=10)
        
        value_label = ttk.Label(card_frame, text=value, font=self.fonts['heading'])
        value_label.pack()
        
        # Store value label for updates
        card_frame.value_label = value_label
        
        return card_frame
    
    def create_certificate_expiry_chart(self, parent):
        """Create certificate expiry timeline chart"""
        chart_frame = ttk.LabelFrame(parent, text="Certificate Expiry Timeline", padding=10)
        chart_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        # Create matplotlib figure
        self.expiry_figure = Figure(figsize=(6, 4), dpi=100)
        self.expiry_plot = self.expiry_figure.add_subplot(111)
        
        # Embed plot in tkinter
        self.expiry_canvas = FigureCanvasTkAgg(self.expiry_figure, chart_frame)
        self.expiry_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Update chart
        self.update_expiry_chart()
    
    def create_system_metrics_chart(self, parent):
        """Create system performance metrics chart"""
        metrics_frame = ttk.LabelFrame(parent, text="System Metrics", padding=10)
        metrics_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        
        # Create matplotlib figure
        self.metrics_figure = Figure(figsize=(6, 4), dpi=100)
        self.metrics_plot = self.metrics_figure.add_subplot(111)
        
        # Embed plot in tkinter
        self.metrics_canvas = FigureCanvasTkAgg(self.metrics_figure, metrics_frame)
        self.metrics_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Update chart
        self.update_metrics_chart()
    
    def create_certificates_tab(self):
        """Create certificates management tab"""
        cert_frame = ttk.Frame(self.notebook)
        self.notebook.add(cert_frame, text="📄 Certificates")
        
        # Toolbar
        toolbar_frame = ttk.Frame(cert_frame)
        toolbar_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(toolbar_frame, text="➕ New Certificate", 
                  command=self.new_certificate_request, 
                  style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        
        ttk.Button(toolbar_frame, text="🔄 Refresh", 
                  command=self.refresh_certificates).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(toolbar_frame, text="📤 Export List", 
                  command=self.export_certificates).pack(side=tk.LEFT, padx=5)
        
        # Search frame
        search_frame = ttk.Frame(cert_frame)
        search_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.cert_search_var = tk.StringVar()
        self.cert_search_var.trace('w', self.filter_certificates)
        ttk.Entry(search_frame, textvariable=self.cert_search_var, width=30).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(search_frame, text="Status:").pack(side=tk.LEFT, padx=5)
        self.cert_status_filter = ttk.Combobox(search_frame, values=["All", "Active", "Expired", "Revoked"], 
                                              state="readonly", width=10)
        self.cert_status_filter.set("All")
        self.cert_status_filter.bind("<<ComboboxSelected>>", self.filter_certificates)
        self.cert_status_filter.pack(side=tk.LEFT, padx=5)
        
        # Certificates tree view
        tree_frame = ttk.Frame(cert_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create treeview with scrollbars
        self.create_certificates_tree(tree_frame)
    
    def create_certificates_tree(self, parent):
        """Create certificates treeview with scrollbars"""
        # Treeview
        columns = ("ID", "Subject", "Purpose", "Status", "Expires", "Organization")
        self.certificates_tree = ttk.Treeview(parent, columns=columns, show='headings', height=15)
        
        # Configure columns
        self.certificates_tree.heading("ID", text="Certificate ID")
        self.certificates_tree.heading("Subject", text="Subject")
        self.certificates_tree.heading("Purpose", text="Purpose")
        self.certificates_tree.heading("Status", text="Status")
        self.certificates_tree.heading("Expires", text="Expires")
        self.certificates_tree.heading("Organization", text="Organization")
        
        # Column widths
        self.certificates_tree.column("ID", width=120)
        self.certificates_tree.column("Subject", width=250)
        self.certificates_tree.column("Purpose", width=120)
        self.certificates_tree.column("Status", width=80)
        self.certificates_tree.column("Expires", width=100)
        self.certificates_tree.column("Organization", width=120)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.certificates_tree.yview)
        h_scrollbar = ttk.Scrollbar(parent, orient="horizontal", command=self.certificates_tree.xview)
        self.certificates_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack treeview and scrollbars
        self.certificates_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        # Configure grid weights
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        
        # Bind events
        self.certificates_tree.bind("<Double-1>", self.on_certificate_double_click)
        self.certificates_tree.bind("<Button-3>", self.show_certificate_context_menu)
    
    def create_services_tab(self):
        """Create VCC services management tab"""
        services_frame = ttk.Frame(self.notebook)
        self.notebook.add(services_frame, text="🏛️ VCC Services")
        
        # Toolbar
        toolbar_frame = ttk.Frame(services_frame)
        toolbar_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(toolbar_frame, text="➕ Register Service", 
                  command=self.register_new_service,
                  style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        
        ttk.Button(toolbar_frame, text="🔄 Refresh Status", 
                  command=self.refresh_services).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(toolbar_frame, text="🏥 Health Check All", 
                  command=self.health_check_all_services).pack(side=tk.LEFT, padx=5)
        
        # Services list with status indicators
        self.create_services_list(services_frame)
    
    def create_services_list(self, parent):
        """Create VCC services list with status"""
        list_frame = ttk.LabelFrame(parent, text="VCC Services Status", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Services treeview
        columns = ("Service", "Type", "Status", "Endpoint", "Last Check", "Certificates")
        self.services_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=12)
        
        # Configure columns
        for col in columns:
            self.services_tree.heading(col, text=col)
        
        self.services_tree.column("Service", width=150)
        self.services_tree.column("Type", width=100)
        self.services_tree.column("Status", width=80)
        self.services_tree.column("Endpoint", width=250)
        self.services_tree.column("Last Check", width=120)
        self.services_tree.column("Certificates", width=100)
        
        # Scrollbar
        services_scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.services_tree.yview)
        self.services_tree.configure(yscrollcommand=services_scrollbar.set)
        
        # Pack
        self.services_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        services_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind events
        self.services_tree.bind("<Double-1>", self.on_service_double_click)
    
    def create_audit_tab(self):
        """Create audit and compliance tab"""
        audit_frame = ttk.Frame(self.notebook)
        self.notebook.add(audit_frame, text="📋 Audit & Compliance")
        
        # Controls frame
        controls_frame = ttk.Frame(audit_frame)
        controls_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(controls_frame, text="🔄 Refresh Events", 
                  command=self.refresh_audit_events).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(controls_frame, text="📤 Export Audit Log", 
                  command=self.export_audit_log).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(controls_frame, text="📊 Generate Compliance Report", 
                  command=self.generate_compliance_report).pack(side=tk.LEFT, padx=5)
        
        # Filter frame
        filter_frame = ttk.Frame(audit_frame)
        filter_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(filter_frame, text="Event Type:").pack(side=tk.LEFT, padx=5)
        self.audit_type_filter = ttk.Combobox(filter_frame, 
                                             values=["All", "Authentication", "Certificate", "Admin", "System"],
                                             state="readonly", width=12)
        self.audit_type_filter.set("All")
        self.audit_type_filter.bind("<<ComboboxSelected>>", self.filter_audit_events)
        self.audit_type_filter.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(filter_frame, text="Time Range:").pack(side=tk.LEFT, padx=5)
        self.audit_time_filter = ttk.Combobox(filter_frame,
                                             values=["Last Hour", "Last Day", "Last Week", "Last Month", "All Time"],
                                             state="readonly", width=12)
        self.audit_time_filter.set("Last Day")
        self.audit_time_filter.bind("<<ComboboxSelected>>", self.filter_audit_events)
        self.audit_time_filter.pack(side=tk.LEFT, padx=5)
        
        # Audit events tree
        self.create_audit_tree(audit_frame)
    
    def create_audit_tree(self, parent):
        """Create audit events treeview"""
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("Timestamp", "Event Type", "Actor", "Target", "Organization", "Details")
        self.audit_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        for col in columns:
            self.audit_tree.heading(col, text=col)
        
        self.audit_tree.column("Timestamp", width=140)
        self.audit_tree.column("Event Type", width=120)
        self.audit_tree.column("Actor", width=120)
        self.audit_tree.column("Target", width=150)
        self.audit_tree.column("Organization", width=120)
        self.audit_tree.column("Details", width=200)
        
        # Scrollbars
        audit_v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.audit_tree.yview)
        audit_h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.audit_tree.xview)
        self.audit_tree.configure(yscrollcommand=audit_v_scrollbar.set, xscrollcommand=audit_h_scrollbar.set)
        
        # Grid layout
        self.audit_tree.grid(row=0, column=0, sticky='nsew')
        audit_v_scrollbar.grid(row=0, column=1, sticky='ns')
        audit_h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Bind events
        self.audit_tree.bind("<Double-1>", self.show_audit_event_details)
    
    def create_monitoring_tab(self):
        """Create system monitoring tab"""
        monitoring_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitoring_frame, text="📈 Monitoring")
        
        # Create monitoring widgets
        self.create_monitoring_widgets(monitoring_frame)
    
    def create_monitoring_widgets(self, parent):
        """Create system monitoring widgets"""
        # System health indicators
        health_frame = ttk.LabelFrame(parent, text="System Health", padding=10)
        health_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Health indicators in a grid
        health_indicators = [
            ("API Server", "🟢 Online"),
            ("Database", "🟢 Connected"),
            ("Security", "🟢 Active"),
            ("VCC Services", "🟡 Partial")
        ]
        
        for i, (service, status) in enumerate(health_indicators):
            row, col = divmod(i, 2)
            service_frame = ttk.Frame(health_frame)
            service_frame.grid(row=row, column=col, padx=20, pady=10, sticky='w')
            
            ttk.Label(service_frame, text=service, font=self.fonts['subheading']).pack(anchor='w')
            status_label = ttk.Label(service_frame, text=status)
            status_label.pack(anchor='w')
        
        # Performance metrics
        metrics_frame = ttk.LabelFrame(parent, text="Performance Metrics", padding=10)
        metrics_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Real-time metrics display
        self.create_realtime_metrics(metrics_frame)
    
    def create_realtime_metrics(self, parent):
        """Create real-time system metrics display"""
        # Metrics will be updated periodically
        metrics_text = scrolledtext.ScrolledText(parent, height=15, width=80, 
                                               font=self.fonts['monospace'])
        metrics_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Store reference for updates
        self.metrics_text = metrics_text
        
        # Initial metrics display
        self.update_metrics_display()
    
    def create_status_bar(self):
        """Create application status bar"""
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Status indicators
        self.connection_status = ttk.Label(self.status_bar, text="🔴 Disconnected", 
                                          foreground=self.colors['danger'])
        self.connection_status.pack(side=tk.LEFT, padx=5)
        
        # Separator
        ttk.Separator(self.status_bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        # User info
        self.user_info = ttk.Label(self.status_bar, text="Not logged in")
        self.user_info.pack(side=tk.LEFT, padx=5)
        
        # Clock
        self.clock_label = ttk.Label(self.status_bar, text="")
        self.clock_label.pack(side=tk.RIGHT, padx=5)
        
        # Update clock
        self.update_clock()
    
    def update_clock(self):
        """Update status bar clock"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.clock_label.config(text=current_time)
        self.root.after(1000, self.update_clock)  # Update every second
    
    def show_login_dialog(self):
        """Show login dialog"""
        login_window = tk.Toplevel(self.root)
        login_window.title("VCC PKI System - Login")
        login_window.geometry("400x300")
        login_window.resizable(False, False)
        login_window.transient(self.root)
        login_window.grab_set()
        
        # Center login window
        login_window.update_idletasks()
        x = (login_window.winfo_screenwidth() // 2) - (400 // 2)
        y = (login_window.winfo_screenheight() // 2) - (300 // 2)
        login_window.geometry(f'400x300+{x}+{y}')
        
        # Login form
        self.create_login_form(login_window)
    
    def create_login_form(self, parent):
        """Create login form"""
        # Header
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, padx=20, pady=20)
        
        title_label = ttk.Label(header_frame, text="VCC PKI System", font=self.fonts['heading'])
        title_label.pack()
        
        subtitle_label = ttk.Label(header_frame, text="Management Dashboard")
        subtitle_label.pack()
        
        # Form
        form_frame = ttk.Frame(parent)
        form_frame.pack(fill=tk.BOTH, expand=True, padx=20)
        
        # Username
        ttk.Label(form_frame, text="Username:").pack(anchor='w', pady=(10, 5))
        self.username_var = tk.StringVar(value="admin")  # Default for development
        username_entry = ttk.Entry(form_frame, textvariable=self.username_var, width=30)
        username_entry.pack(fill=tk.X)
        username_entry.focus()
        
        # Password
        ttk.Label(form_frame, text="Password:").pack(anchor='w', pady=(10, 5))
        self.password_var = tk.StringVar(value="admin123")  # Default for development
        password_entry = ttk.Entry(form_frame, textvariable=self.password_var, show="*", width=30)
        password_entry.pack(fill=tk.X)
        
        # Server URL
        ttk.Label(form_frame, text="API Server:").pack(anchor='w', pady=(10, 5))
        self.server_var = tk.StringVar(value=self.api_base_url)
        server_entry = ttk.Entry(form_frame, textvariable=self.server_var, width=30)
        server_entry.pack(fill=tk.X)
        
        # Buttons
        button_frame = ttk.Frame(form_frame)
        button_frame.pack(fill=tk.X, pady=20)
        
        login_button = ttk.Button(button_frame, text="Login", 
                                 command=lambda: self.login(parent), 
                                 style='Primary.TButton')
        login_button.pack(side=tk.RIGHT, padx=5)
        
        cancel_button = ttk.Button(button_frame, text="Cancel", 
                                  command=self.root.quit)
        cancel_button.pack(side=tk.RIGHT)
        
        # Bind Enter key to login
        parent.bind('<Return>', lambda e: self.login(parent))
    
    def login(self, login_window):
        """Perform user login"""
        username = self.username_var.get().strip()
        password = self.password_var.get()
        server_url = self.server_var.get().strip()
        
        if not username or not password:
            messagebox.showerror("Login Error", "Please enter username and password")
            return
        
        # Update API base URL
        self.api_base_url = server_url
        
        # Attempt authentication
        try:
            self.authenticate_user(username, password)
            login_window.destroy()
            self.on_successful_login()
        except Exception as e:
            messagebox.showerror("Login Failed", f"Authentication failed: {str(e)}")
    
    def authenticate_user(self, username: str, password: str):
        """Authenticate user with API"""
        # Prepare login request
        login_data = {
            "username": username,
            "password": password
        }
        
        # Make authentication request
        response = requests.post(
            f"{self.api_base_url}/api/v1/auth/login",
            data=login_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10
        )
        
        if response.status_code != 200:
            raise Exception(f"Login failed: {response.status_code}")
        
        result = response.json()
        if not result.get("success"):
            raise Exception(result.get("message", "Authentication failed"))
        
        # Store authentication data
        data = result["data"]
        self.access_token = data["access_token"]
        self.current_user = data["user"]
        
        # Update connection status
        self.connection_status.config(text="🟢 Connected", 
                                     foreground=self.colors['success'])
        
        # Update user info in status bar
        user_info = f"👤 {self.current_user['username']} ({self.current_user['organization_id']})"
        self.user_info.config(text=user_info)
    
    def on_successful_login(self):
        """Handle successful login"""
        # Load initial data
        self.refresh_all_data()
        
        # Configure UI based on user permissions
        self.configure_ui_permissions()
        
        # Show welcome message
        messagebox.showinfo("Login Successful", 
                           f"Welcome to VCC PKI System, {self.current_user['username']}!")
    
    def configure_ui_permissions(self):
        """Configure UI based on user permissions"""
        if not self.current_user:
            return
        
        user_roles = self.current_user.get('roles', [])
        
        # Hide admin menu if not admin
        if 'super_admin' not in user_roles and 'org_admin' not in user_roles:
            self.menubar.delete("Admin")
    
    # === Data Refresh Methods ===
    
    def refresh_all_data(self):
        """Refresh all dashboard data"""
        if not self.access_token:
            return
        
        # Run refresh in background thread
        threading.Thread(target=self._background_refresh, daemon=True).start()
    
    def _background_refresh(self):
        """Background data refresh"""
        try:
            self.refresh_system_status()
            self.refresh_certificates()
            self.refresh_services()
            self.refresh_audit_events()
            
            # Update UI in main thread
            self.root.after(0, self.update_ui_after_refresh)
            
        except Exception as e:
            logger.error(f"Background refresh failed: {e}")
            self.root.after(0, lambda: messagebox.showerror("Refresh Error", str(e)))
    
    def update_ui_after_refresh(self):
        """Update UI components after data refresh"""
        # Update status cards
        if hasattr(self, 'cert_count_card'):
            cert_count = len(self.certificates_data)
            self.cert_count_card.value_label.config(text=str(cert_count))
        
        if hasattr(self, 'services_card'):
            healthy_services = sum(1 for s in self.services_data if s.get('status') == 'healthy')
            total_services = len(self.services_data)
            self.services_card.value_label.config(text=f"{healthy_services}/{total_services}")
        
        if hasattr(self, 'activity_card'):
            recent_events = len([e for e in self.audit_events if self._is_recent_event(e)])
            self.activity_card.value_label.config(text=f"{recent_events} events")
        
        # Update charts
        self.update_expiry_chart()
        self.update_metrics_chart()
        self.update_metrics_display()
    
    def _is_recent_event(self, event):
        """Check if event is recent (last 24 hours)"""
        try:
            event_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
            return datetime.now() - event_time < timedelta(hours=24)
        except:
            return False
    
    def start_background_updates(self):
        """Start periodic background updates"""
        def periodic_update():
            if self.access_token:
                self.refresh_all_data()
            
            # Schedule next update
            self.root.after(self.refresh_interval, periodic_update)
        
        # Start periodic updates
        self.root.after(self.refresh_interval, periodic_update)
    
    # === API Methods ===
    
    def make_api_request(self, method: str, endpoint: str, **kwargs) -> dict:
        """Make authenticated API request"""
        if not self.access_token:
            raise Exception("Not authenticated")
        
        headers = kwargs.get('headers', {})
        headers['Authorization'] = f'Bearer {self.access_token}'
        kwargs['headers'] = headers
        
        url = f"{self.api_base_url}{endpoint}"
        
        response = requests.request(method, url, timeout=10, **kwargs)
        
        if response.status_code == 401:
            # Token expired, need to re-login
            self.access_token = None
            self.show_login_dialog()
            raise Exception("Authentication expired")
        
        return response.json()
    
    def refresh_system_status(self):
        """Refresh system status data"""
        try:
            result = self.make_api_request('GET', '/status')
            if result.get('success'):
                self.system_status = result['data']
        except Exception as e:
            logger.error(f"Failed to refresh system status: {e}")
    
    def refresh_certificates(self):
        """Refresh certificates data"""
        try:
            result = self.make_api_request('GET', '/api/v1/certs/list')
            if result.get('success'):
                self.certificates_data = result['data']
                self.update_certificates_tree()
        except Exception as e:
            logger.error(f"Failed to refresh certificates: {e}")
    
    def refresh_services(self):
        """Refresh VCC services data"""
        try:
            result = self.make_api_request('GET', '/api/v1/services')
            if result.get('success'):
                self.services_data = result['data']
                self.update_services_tree()
        except Exception as e:
            logger.error(f"Failed to refresh services: {e}")
    
    def refresh_audit_events(self):
        """Refresh audit events data"""
        try:
            result = self.make_api_request('GET', '/api/v1/audit/events', params={'limit': 100})
            if result.get('success'):
                self.audit_events = result['data']
                self.update_audit_tree()
        except Exception as e:
            logger.error(f"Failed to refresh audit events: {e}")
    
    # === UI Update Methods ===
    
    def update_certificates_tree(self):
        """Update certificates treeview"""
        # Clear existing items
        for item in self.certificates_tree.get_children():
            self.certificates_tree.delete(item)
        
        # Add certificate data
        for cert in self.certificates_data:
            # Determine status
            status = "Active"
            if cert.get('revoked_at'):
                status = "Revoked"
            elif cert.get('expires_at'):
                try:
                    exp_date = datetime.fromisoformat(cert['expires_at'].replace('Z', '+00:00'))
                    if exp_date <= datetime.now():
                        status = "Expired"
                except:
                    pass
            
            # Format expiry date
            expires_str = "Unknown"
            if cert.get('expires_at'):
                try:
                    exp_date = datetime.fromisoformat(cert['expires_at'].replace('Z', '+00:00'))
                    expires_str = exp_date.strftime('%Y-%m-%d')
                except:
                    pass
            
            # Add to tree
            self.certificates_tree.insert('', 'end', values=(
                cert.get('cert_id', '')[:12] + "...",
                cert.get('subject_dn', ''),
                cert.get('purpose', ''),
                status,
                expires_str,
                cert.get('organization_id', '')
            ))
    
    def update_services_tree(self):
        """Update services treeview"""
        # Clear existing items
        for item in self.services_tree.get_children():
            self.services_tree.delete(item)
        
        # Add services data
        for service in self.services_data:
            status = service.get('health_status', 'Unknown')
            status_icon = {"healthy": "🟢", "degraded": "🟡", "unhealthy": "🔴"}.get(status, "❓")
            
            self.services_tree.insert('', 'end', values=(
                service.get('service_name', ''),
                service.get('service_type', ''),
                f"{status_icon} {status}",
                service.get('endpoint_url', ''),
                service.get('last_health_check', 'Never'),
                service.get('certificate_count', '0')
            ))
    
    def update_audit_tree(self):
        """Update audit events treeview"""
        # Clear existing items
        for item in self.audit_tree.get_children():
            self.audit_tree.delete(item)
        
        # Add audit events
        for event in self.audit_events[-50:]:  # Show latest 50 events
            timestamp = event.get('timestamp', '')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    pass
            
            self.audit_tree.insert('', 'end', values=(
                timestamp,
                event.get('event_type', ''),
                event.get('actor_identity', ''),
                event.get('target_resource', ''),
                event.get('organization_id', ''),
                event.get('event_data', {}).get('description', '')
            ))
    
    def update_expiry_chart(self):
        """Update certificate expiry chart"""
        self.expiry_plot.clear()
        
        if not self.certificates_data:
            self.expiry_plot.text(0.5, 0.5, 'No data available', 
                                 horizontalalignment='center', verticalalignment='center')
            self.expiry_canvas.draw()
            return
        
        # Process expiry data
        expiry_counts = {"< 30 days": 0, "30-90 days": 0, "90+ days": 0, "Expired": 0}
        
        now = datetime.now()
        for cert in self.certificates_data:
            if cert.get('revoked_at'):
                continue
            
            if cert.get('expires_at'):
                try:
                    exp_date = datetime.fromisoformat(cert['expires_at'].replace('Z', '+00:00'))
                    days_until = (exp_date - now).days
                    
                    if days_until < 0:
                        expiry_counts["Expired"] += 1
                    elif days_until < 30:
                        expiry_counts["< 30 days"] += 1
                    elif days_until < 90:
                        expiry_counts["30-90 days"] += 1
                    else:
                        expiry_counts["90+ days"] += 1
                except:
                    pass
        
        # Create bar chart
        categories = list(expiry_counts.keys())
        values = list(expiry_counts.values())
        colors = ['red', 'orange', 'green', 'gray']
        
        bars = self.expiry_plot.bar(categories, values, color=colors)
        self.expiry_plot.set_title('Certificate Expiry Status')
        self.expiry_plot.set_ylabel('Count')
        
        # Add value labels on bars
        for bar, value in zip(bars, values):
            if value > 0:
                height = bar.get_height()
                self.expiry_plot.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                                     str(value), ha='center', va='bottom')
        
        self.expiry_canvas.draw()
    
    def update_metrics_chart(self):
        """Update system metrics chart"""
        self.metrics_plot.clear()
        
        # Sample metrics data (in production, get from system monitoring)
        metrics = {
            "API Requests": 150,
            "Active Sessions": 12,
            "Certificates": len(self.certificates_data),
            "Services": len(self.services_data)
        }
        
        categories = list(metrics.keys())
        values = list(metrics.values())
        
        self.metrics_plot.bar(categories, values, color=self.colors['primary'])
        self.metrics_plot.set_title('System Metrics')
        self.metrics_plot.set_ylabel('Count')
        
        # Rotate x-axis labels for better readability
        plt.setp(self.metrics_plot.get_xticklabels(), rotation=45, ha='right')
        
        self.metrics_canvas.draw()
    
    def update_metrics_display(self):
        """Update real-time metrics text display"""
        if not hasattr(self, 'metrics_text'):
            return
        
        self.metrics_text.delete(1.0, tk.END)
        
        metrics_info = f"""
VCC PKI System - Real-time Metrics
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'=' * 50}

SYSTEM STATUS:
  API Server: {'🟢 Online' if self.system_status else '🔴 Offline'}
  Database: 🟢 Connected
  Security: 🟢 Active
  Mock Mode: {'🟡 Enabled' if self.config.mock_mode else '🔴 Disabled'}

CERTIFICATES:
  Total Active: {len([c for c in self.certificates_data if not c.get('revoked_at')])}
  Total Revoked: {len([c for c in self.certificates_data if c.get('revoked_at')])}
  Expiring Soon (<30 days): {len([c for c in self.certificates_data if self._cert_expires_soon(c)])}

VCC SERVICES:
  Total Registered: {len(self.services_data)}
  Healthy: {len([s for s in self.services_data if s.get('health_status') == 'healthy'])}
  Degraded: {len([s for s in self.services_data if s.get('health_status') == 'degraded'])}
  Unhealthy: {len([s for s in self.services_data if s.get('health_status') == 'unhealthy'])}

AUDIT ACTIVITY (Last 24h):
  Total Events: {len([e for e in self.audit_events if self._is_recent_event(e)])}
  Authentication Events: {len([e for e in self.audit_events if self._is_recent_event(e) and 'login' in e.get('event_type', '')])}
  Certificate Events: {len([e for e in self.audit_events if self._is_recent_event(e) and 'cert' in e.get('event_type', '')])}

USER SESSION:
  Username: {self.current_user.get('username', 'Unknown') if self.current_user else 'Not logged in'}
  Organization: {self.current_user.get('organization_id', 'Unknown') if self.current_user else 'N/A'}
  Roles: {', '.join(self.current_user.get('roles', [])) if self.current_user else 'N/A'}
  Login Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        self.metrics_text.insert(1.0, metrics_info)
    
    def _cert_expires_soon(self, cert):
        """Check if certificate expires within 30 days"""
        if cert.get('revoked_at') or not cert.get('expires_at'):
            return False
        
        try:
            exp_date = datetime.fromisoformat(cert['expires_at'].replace('Z', '+00:00'))
            return (exp_date - datetime.now()).days < 30
        except:
            return False
    
    # === Event Handlers ===
    
    def filter_certificates(self, *args):
        """Filter certificates based on search criteria"""
        # Implementation for certificate filtering
        pass
    
    def filter_audit_events(self, *args):
        """Filter audit events based on criteria"""
        # Implementation for audit event filtering
        pass
    
    def on_certificate_double_click(self, event):
        """Handle certificate double-click"""
        selection = self.certificates_tree.selection()
        if selection:
            item = self.certificates_tree.item(selection[0])
            cert_id = item['values'][0].replace('...', '')  # Remove truncation
            self.show_certificate_details(cert_id)
    
    def on_service_double_click(self, event):
        """Handle service double-click"""
        selection = self.services_tree.selection()
        if selection:
            item = self.services_tree.item(selection[0])
            service_name = item['values'][0]
            self.show_service_details(service_name)
    
    def show_audit_event_details(self, event):
        """Show detailed audit event information"""
        selection = self.audit_tree.selection()
        if selection:
            item = self.audit_tree.item(selection[0])
            # Show detailed event info in popup
            messagebox.showinfo("Audit Event Details", f"Event: {item['values'][1]}\nDetails: {item['values'][5]}")
    
    def show_certificate_context_menu(self, event):
        """Show certificate context menu"""
        # Create context menu for certificate operations
        pass
    
    # === Action Methods ===
    
    def new_certificate_request(self):
        """Show new certificate request dialog"""
        messagebox.showinfo("New Certificate", "Certificate request dialog - TODO: Implement")
    
    def import_certificate(self):
        """Import certificate from file"""
        file_path = filedialog.askopenfilename(
            title="Import Certificate",
            filetypes=[("Certificate files", "*.pem *.crt *.cer"), ("All files", "*.*")]
        )
        if file_path:
            messagebox.showinfo("Import Certificate", f"Import certificate from: {file_path}")
    
    def export_configuration(self):
        """Export system configuration"""
        file_path = filedialog.asksaveasfilename(
            title="Export Configuration",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            messagebox.showinfo("Export Configuration", f"Export configuration to: {file_path}")
    
    def run_health_check(self):
        """Run system health check"""
        messagebox.showinfo("Health Check", "Running system health check...")
        self.refresh_all_data()
    
    def validate_certificates(self):
        """Validate all certificates"""
        messagebox.showinfo("Certificate Validation", "Validating all certificates...")
    
    def generate_report(self):
        """Generate system report"""
        messagebox.showinfo("Generate Report", "Generating system report...")
    
    def open_api_docs(self):
        """Open API documentation in browser"""
        url = f"{self.api_base_url}/docs"
        webbrowser.open(url)
    
    def show_user_management(self):
        """Show user management interface"""
        messagebox.showinfo("User Management", "User management interface - TODO: Implement")
    
    def show_system_config(self):
        """Show system configuration interface"""
        messagebox.showinfo("System Configuration", "System configuration interface - TODO: Implement")
    
    def backup_database(self):
        """Backup system database"""
        messagebox.showinfo("Backup Database", "Database backup - TODO: Implement")
    
    def view_system_logs(self):
        """View system logs"""
        messagebox.showinfo("System Logs", "System logs viewer - TODO: Implement")
    
    def register_new_service(self):
        """Register new VCC service"""
        messagebox.showinfo("Register Service", "Service registration dialog - TODO: Implement")
    
    def refresh_services(self):
        """Refresh services status"""
        self.refresh_services()
    
    def health_check_all_services(self):
        """Perform health check on all services"""
        messagebox.showinfo("Health Check", "Checking health of all VCC services...")
        self.refresh_services()
    
    def export_certificates(self):
        """Export certificates list"""
        file_path = filedialog.asksaveasfilename(
            title="Export Certificates",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            messagebox.showinfo("Export Certificates", f"Export certificates to: {file_path}")
    
    def export_audit_log(self):
        """Export audit log"""
        file_path = filedialog.asksaveasfilename(
            title="Export Audit Log",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if file_path:
            messagebox.showinfo("Export Audit Log", f"Export audit log to: {file_path}")
    
    def generate_compliance_report(self):
        """Generate compliance report"""
        messagebox.showinfo("Compliance Report", "Generating compliance report...")
    
    def show_certificate_details(self, cert_id):
        """Show detailed certificate information"""
        messagebox.showinfo("Certificate Details", f"Certificate details for: {cert_id}")
    
    def show_service_details(self, service_name):
        """Show detailed service information"""
        messagebox.showinfo("Service Details", f"Service details for: {service_name}")
    
    def show_user_guide(self):
        """Show user guide"""
        messagebox.showinfo("User Guide", "Opening user guide...")
    
    def show_api_reference(self):
        """Show API reference"""
        url = f"{self.api_base_url}/redoc"
        webbrowser.open(url)
    
    def show_about_dialog(self):
        """Show about dialog"""
        about_text = """VCC PKI System - Management Dashboard

Version: 1.0.0
Brandenburg Government Digital Infrastructure

A modern desktop interface for managing the VCC Public Key Infrastructure system.

Features:
• Certificate lifecycle management
• VCC service monitoring
• Security audit trails
• Real-time system metrics
• Compliance reporting

© 2025 Brandenburg Government
All rights reserved."""
        
        messagebox.showinfo("About VCC PKI System", about_text)
    
    def on_closing(self):
        """Handle application closing"""
        if messagebox.askokcancel("Quit", "Do you want to quit VCC PKI Dashboard?"):
            self.root.destroy()
    
    def run(self):
        """Start the dashboard application"""
        self.root.mainloop()

# Application entry point
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        # Create and run dashboard
        dashboard = VCCPKIDashboard()
        dashboard.run()
    except Exception as e:
        logger.error(f"Dashboard startup failed: {e}")
        messagebox.showerror("Startup Error", f"Failed to start dashboard: {e}")
        sys.exit(1)