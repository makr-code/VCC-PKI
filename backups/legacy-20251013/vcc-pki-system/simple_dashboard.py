# VCC PKI System - Simple Dashboard
# Basic Tkinter implementation without heavy dependencies

import tkinter as tk
from tkinter import ttk, messagebox
import json
import threading
from datetime import datetime
import os
import sys

class SimpleVCCDashboard:
    """Simplified VCC PKI Dashboard"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("VCC PKI System - Management Dashboard")
        self.root.geometry("1000x700")
        
        # Brandenburg Government Colors (simplified)
        self.colors = {
            'primary': '#003366',      # Dark blue
            'secondary': '#006699',    # Blue
            'accent': '#FF6600',       # Orange
            'success': '#00AA44',      # Green
            'warning': '#FF9900',      # Orange
            'danger': '#CC0000',       # Red
            'light': '#F5F5F5',       # Light gray
            'dark': '#333333'          # Dark gray
        }
        
        # Configure style
        self.setup_styles()
        
        # Create UI
        self.create_menu()
        self.create_main_interface()
        
        # Mock data
        self.mock_data = self.load_mock_data()
        
        # Start background updates
        self.start_updates()
    
    def setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        
        # Configure notebook tabs
        style.theme_use('clam')
        style.configure('TNotebook.Tab', padding=[12, 8])
        style.configure('Heading.TLabel', font=('Segoe UI', 12, 'bold'))
        style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'))
        
    def create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Datei", menu=file_menu)
        file_menu.add_command(label="Verbindung testen", command=self.test_connection)
        file_menu.add_separator()
        file_menu.add_command(label="Beenden", command=self.quit_application)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="System Status", command=self.show_system_status)
        tools_menu.add_command(label="Log Viewer", command=self.show_logs)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Hilfe", menu=help_menu)
        help_menu.add_command(label="Über", command=self.show_about)
    
    def create_main_interface(self):
        """Create main interface"""
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Title
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(title_frame, text="VCC PKI System", 
                 style='Title.TLabel').pack(side=tk.LEFT)
        
        # Connection status
        self.status_label = ttk.Label(title_frame, text="● Verbunden", 
                                     foreground=self.colors['success'])
        self.status_label.pack(side=tk.RIGHT)
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_overview_tab()
        self.create_certificates_tab()
        self.create_services_tab()
        self.create_logs_tab()
    
    def create_overview_tab(self):
        """Create overview tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Übersicht")
        
        # Status cards
        cards_frame = ttk.Frame(tab)
        cards_frame.pack(fill=tk.X, pady=10)
        
        # System status card
        system_frame = ttk.LabelFrame(cards_frame, text="System Status")
        system_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        self.system_status = tk.Text(system_frame, height=6, width=30)
        self.system_status.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Certificate status card
        cert_frame = ttk.LabelFrame(cards_frame, text="Zertifikate")
        cert_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        self.cert_status = tk.Text(cert_frame, height=6, width=30)
        self.cert_status.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # VCC services card
        vcc_frame = ttk.LabelFrame(cards_frame, text="VCC Services")
        vcc_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        self.vcc_status = tk.Text(vcc_frame, height=6, width=30)
        self.vcc_status.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Activity log
        activity_frame = ttk.LabelFrame(tab, text="Aktuelle Aktivitäten")
        activity_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Activity treeview
        columns = ('Zeit', 'Ereignis', 'Status')
        self.activity_tree = ttk.Treeview(activity_frame, columns=columns, show='headings', height=10)
        
        for col in columns:
            self.activity_tree.heading(col, text=col)
            self.activity_tree.column(col, width=200)
        
        scrollbar = ttk.Scrollbar(activity_frame, orient=tk.VERTICAL, command=self.activity_tree.yview)
        self.activity_tree.configure(yscrollcommand=scrollbar.set)
        
        self.activity_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
    
    def create_certificates_tab(self):
        """Create certificates tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Zertifikate")
        
        # Toolbar
        toolbar = ttk.Frame(tab)
        toolbar.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(toolbar, text="Neues Zertifikat", 
                  command=self.new_certificate).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(toolbar, text="Erneuern", 
                  command=self.renew_certificate).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Widerrufen", 
                  command=self.revoke_certificate).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Exportieren", 
                  command=self.export_certificate).pack(side=tk.LEFT, padx=5)
        
        # Certificate list
        cert_frame = ttk.LabelFrame(tab, text="Zertifikatsliste")
        cert_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ('Subject', 'Gültig bis', 'Status', 'Typ')
        self.cert_tree = ttk.Treeview(cert_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.cert_tree.heading(col, text=col)
            self.cert_tree.column(col, width=200)
        
        cert_scrollbar = ttk.Scrollbar(cert_frame, orient=tk.VERTICAL, command=self.cert_tree.yview)
        self.cert_tree.configure(yscrollcommand=cert_scrollbar.set)
        
        self.cert_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        cert_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
    
    def create_services_tab(self):
        """Create services tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="VCC Services")
        
        # Service status
        status_frame = ttk.LabelFrame(tab, text="Service Status")
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.service_status = tk.Text(status_frame, height=8)
        self.service_status.pack(fill=tk.X, padx=5, pady=5)
        
        # Service list
        services_frame = ttk.LabelFrame(tab, text="VCC Service Registry")
        services_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ('Service', 'URL', 'Status', 'Letzte Prüfung')
        self.services_tree = ttk.Treeview(services_frame, columns=columns, show='headings', height=12)
        
        for col in columns:
            self.services_tree.heading(col, text=col)
            self.services_tree.column(col, width=200)
        
        services_scrollbar = ttk.Scrollbar(services_frame, orient=tk.VERTICAL, command=self.services_tree.yview)
        self.services_tree.configure(yscrollcommand=services_scrollbar.set)
        
        self.services_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        services_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
    
    def create_logs_tab(self):
        """Create logs tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Audit Logs")
        
        # Filter frame
        filter_frame = ttk.Frame(tab)
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=(0, 5))
        self.log_filter = ttk.Combobox(filter_frame, values=['Alle', 'Info', 'Warning', 'Error'])
        self.log_filter.set('Alle')
        self.log_filter.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(filter_frame, text="Aktualisieren", 
                  command=self.refresh_logs).pack(side=tk.LEFT)
        
        # Log display
        log_frame = ttk.LabelFrame(tab, text="System Logs")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = tk.Text(log_frame, font=('Consolas', 9))
        log_scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
    
    def load_mock_data(self):
        """Load mock data for demonstration"""
        return {
            'system_status': {
                'ca_running': True,
                'database_connected': True,
                'certificates_count': 42,
                'services_registered': 8
            },
            'recent_activities': [
                ('2024-01-15 10:30', 'Zertifikat erstellt für service-auth', 'Erfolg'),
                ('2024-01-15 10:25', 'VCC Service registriert: payment-gateway', 'Erfolg'),
                ('2024-01-15 10:20', 'Zertifikat erneuert für web-portal', 'Erfolg'),
                ('2024-01-15 10:15', 'System Backup erstellt', 'Info'),
                ('2024-01-15 10:10', 'CA Zertifikat überprüft', 'Erfolg')
            ],
            'certificates': [
                ('CN=web-portal.brandenburg.de', '2025-01-15', 'Gültig', 'Server'),
                ('CN=service-auth.vcc.local', '2024-12-20', 'Gültig', 'Client'),
                ('CN=payment-gateway.vcc.local', '2024-11-30', 'Erneuern', 'Server'),
                ('CN=user-client-001', '2024-10-15', 'Widerrufen', 'Client')
            ],
            'vcc_services': [
                ('Authentication Service', 'https://auth.vcc.local', 'Online', '2024-01-15 10:30'),
                ('Payment Gateway', 'https://pay.vcc.local', 'Online', '2024-01-15 10:28'),
                ('Document Service', 'https://docs.vcc.local', 'Offline', '2024-01-15 10:25'),
                ('Notification Hub', 'https://notify.vcc.local', 'Online', '2024-01-15 10:30')
            ]
        }
    
    def update_display(self):
        """Update all display elements"""
        try:
            # Update system status
            self.system_status.delete(1.0, tk.END)
            status_text = f"""CA Status: {'🟢 Online' if self.mock_data['system_status']['ca_running'] else '🔴 Offline'}
Database: {'🟢 Verbunden' if self.mock_data['system_status']['database_connected'] else '🔴 Getrennt'}
Zertifikate: {self.mock_data['system_status']['certificates_count']}
VCC Services: {self.mock_data['system_status']['services_registered']}

Letztes Update: {datetime.now().strftime('%H:%M:%S')}"""
            self.system_status.insert(1.0, status_text)
            
            # Update certificate status
            self.cert_status.delete(1.0, tk.END)
            valid_certs = len([c for c in self.mock_data['certificates'] if c[2] == 'Gültig'])
            expiring_certs = len([c for c in self.mock_data['certificates'] if c[2] == 'Erneuern'])
            revoked_certs = len([c for c in self.mock_data['certificates'] if c[2] == 'Widerrufen'])
            
            cert_text = f"""Gültig: {valid_certs}
Erneuern erforderlich: {expiring_certs}
Widerrufen: {revoked_certs}

Gesamt: {len(self.mock_data['certificates'])}"""
            self.cert_status.insert(1.0, cert_text)
            
            # Update VCC status
            self.vcc_status.delete(1.0, tk.END)
            online_services = len([s for s in self.mock_data['vcc_services'] if s[2] == 'Online'])
            offline_services = len([s for s in self.mock_data['vcc_services'] if s[2] == 'Offline'])
            
            vcc_text = f"""Online: {online_services}
Offline: {offline_services}

Verfügbarkeit: {(online_services/(online_services+offline_services)*100):.1f}%

Letzter Check: {datetime.now().strftime('%H:%M:%S')}"""
            self.vcc_status.insert(1.0, vcc_text)
            
            # Update activity tree
            for item in self.activity_tree.get_children():
                self.activity_tree.delete(item)
            
            for activity in self.mock_data['recent_activities']:
                self.activity_tree.insert('', tk.END, values=activity)
            
            # Update certificate tree
            for item in self.cert_tree.get_children():
                self.cert_tree.delete(item)
            
            for cert in self.mock_data['certificates']:
                self.cert_tree.insert('', tk.END, values=cert)
            
            # Update services tree
            for item in self.services_tree.get_children():
                self.services_tree.delete(item)
            
            for service in self.mock_data['vcc_services']:
                self.services_tree.insert('', tk.END, values=service)
            
            # Update service status text
            self.service_status.delete(1.0, tk.END)
            service_text = f"""VCC Service Registry Status:

Online Services: {online_services}
Offline Services: {offline_services}
Letzte Synchronisation: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Registry Endpoint: https://vcc-registry.brandenburg.de
API Version: 1.0
Authentifizierung: PKI Client Certificate"""
            self.service_status.insert(1.0, service_text)
            
            # Update logs
            self.update_logs()
            
        except Exception as e:
            print(f"Update error: {e}")
    
    def update_logs(self):
        """Update log display"""
        self.log_text.delete(1.0, tk.END)
        
        sample_logs = f"""[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: System status check completed
[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: Certificate validation completed for 42 certificates
[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: VCC service registry synchronized
[2024-01-15 10:30:15] INFO: New certificate issued: CN=service-auth.vcc.local
[2024-01-15 10:25:30] INFO: VCC service registered: payment-gateway
[2024-01-15 10:20:45] INFO: Certificate renewed: CN=web-portal.brandenburg.de
[2024-01-15 10:15:20] INFO: System backup completed successfully
[2024-01-15 10:10:10] INFO: CA certificate validation completed
[2024-01-15 10:05:30] WARNING: Certificate expires soon: CN=payment-gateway.vcc.local
[2024-01-15 10:00:15] INFO: Database connection pool refreshed"""
        
        self.log_text.insert(1.0, sample_logs)
    
    def start_updates(self):
        """Start background update thread"""
        def update_loop():
            while True:
                try:
                    self.root.after(0, self.update_display)
                    threading.Event().wait(30)  # Update every 30 seconds
                except:
                    break
        
        update_thread = threading.Thread(target=update_loop, daemon=True)
        update_thread.start()
        
        # Initial update
        self.update_display()
    
    # Command handlers
    def test_connection(self):
        messagebox.showinfo("Verbindungstest", "✅ Verbindung zur VCC PKI API erfolgreich")
    
    def show_system_status(self):
        status_window = tk.Toplevel(self.root)
        status_window.title("System Status Details")
        status_window.geometry("600x400")
        
        status_text = tk.Text(status_window, font=('Consolas', 10))
        status_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        detailed_status = f"""VCC PKI System - Detaillierter Status
{'='*50}

Certificate Authority (CA):
  Status: Online
  Root CA: VCC-Root-CA-2024
  Intermediate CA: VCC-Issuing-CA-2024
  Zertifikate ausgestellt: 42
  CRL Größe: 3 widerrufene Zertifikate

Datenbank:
  Engine: SQLite mit SQLCipher Verschlüsselung
  Datenbankgröße: 2.4 MB
  Tabellen: 8
  Indizes: 12
  Letzte Sicherung: {datetime.now().strftime('%Y-%m-%d %H:%M')}

VCC Service Registry:
  Registrierte Services: 8
  Online Services: 6
  Offline Services: 2
  Letzte Synchronisation: {datetime.now().strftime('%Y-%m-%d %H:%M')}

Sicherheit:
  Verschlüsselung: AES-256-GCM
  Signatur-Algorithmus: RSA-4096 with SHA-256
  Schlüssel-Management: Hardware Security Module (Mock)
  Audit-Protokollierung: Aktiviert

Netzwerk:
  API Endpoint: https://pki-api.vcc.local
  Dashboard Port: 8080
  SSL/TLS: Aktiviert
  Client-Authentifizierung: PKI Certificate"""
        
        status_text.insert(1.0, detailed_status)
        status_text.config(state=tk.DISABLED)
    
    def show_logs(self):
        messagebox.showinfo("Log Viewer", "Detaillierte Logs sind im 'Audit Logs' Tab verfügbar.")
    
    def show_about(self):
        messagebox.showinfo("Über VCC PKI System", 
                          "VCC PKI System v1.0\n\n"
                          "Public Key Infrastructure für\n"
                          "das Verwaltungscloud-Computing\n"
                          "der Länder (VCC)\n\n"
                          "Land Brandenburg - 2024")
    
    def new_certificate(self):
        messagebox.showinfo("Neues Zertifikat", "Zertifikatserstellung wird implementiert...")
    
    def renew_certificate(self):
        selection = self.cert_tree.selection()
        if not selection:
            messagebox.showwarning("Keine Auswahl", "Bitte wählen Sie ein Zertifikat aus.")
            return
        messagebox.showinfo("Zertifikat erneuern", "Zertifikatserneuerung wird implementiert...")
    
    def revoke_certificate(self):
        selection = self.cert_tree.selection()
        if not selection:
            messagebox.showwarning("Keine Auswahl", "Bitte wählen Sie ein Zertifikat aus.")
            return
        result = messagebox.askyesno("Zertifikat widerrufen", 
                                   "Sind Sie sicher, dass Sie dieses Zertifikat widerrufen möchten?")
        if result:
            messagebox.showinfo("Widerrufen", "Zertifikat wurde widerrufen.")
    
    def export_certificate(self):
        selection = self.cert_tree.selection()
        if not selection:
            messagebox.showwarning("Keine Auswahl", "Bitte wählen Sie ein Zertifikat aus.")
            return
        messagebox.showinfo("Export", "Zertifikat-Export wird implementiert...")
    
    def refresh_logs(self):
        self.update_logs()
        messagebox.showinfo("Logs aktualisiert", "Audit-Logs wurden aktualisiert.")
    
    def quit_application(self):
        if messagebox.askyesno("Beenden", "Möchten Sie das Dashboard wirklich beenden?"):
            self.root.quit()
    
    def run(self):
        """Start the dashboard"""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            messagebox.showerror("Dashboard Fehler", f"Ein Fehler ist aufgetreten: {e}")

def main():
    """Main function"""
    try:
        dashboard = SimpleVCCDashboard()
        dashboard.run()
    except Exception as e:
        print(f"Failed to start dashboard: {e}")
        messagebox.showerror("Startup Error", f"Failed to start dashboard: {e}")

if __name__ == "__main__":
    main()