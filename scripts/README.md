# VCC PKI - PowerShell Scripts

Management scripts for VCC PKI Server and GUI Frontend.

## 📁 Available Scripts

### Server Management

| Script | Description | Usage |
|--------|-------------|-------|
| `start_server.ps1` | Start PKI Server | `.\start_server.ps1 [-Port 8443] [-InitCA] [-Background]` |
| `stop_server.ps1` | Stop PKI Server | `.\stop_server.ps1 [-Force]` |
| `restart_server.ps1` | Restart PKI Server | `.\restart_server.ps1 [-Port 8443] [-Background]` |
| `status_server.ps1` | Check server status | `.\status_server.ps1 [-Detailed]` |

### Frontend Management

| Script | Description | Usage |
|--------|-------------|-------|
| `start_frontend.ps1` | Start PKI Manager GUI | `.\start_frontend.ps1 [-Server https://localhost:8443]` |
| `stop_frontend.ps1` | Stop PKI Manager GUI | `.\stop_frontend.ps1 [-Force]` |

### Combined Management

| Script | Description | Usage |
|--------|-------------|-------|
| `start_all.ps1` | Start server + GUI | `.\start_all.ps1 [-Port 8443] [-InitCA]` |
| `stop_all.ps1` | Stop server + GUI | `.\stop_all.ps1 [-Force]` |
| `status_all.ps1` | Check all services | `.\status_all.ps1` |

## 🚀 Quick Start

### First Time Setup

```powershell
# Initialize CA and start server
cd C:\VCC\PKI
.\scripts\start_server.ps1 -InitCA -Background

# Wait for server to start (3 seconds)
Start-Sleep -Seconds 3

# Start GUI
.\scripts\start_frontend.ps1
```

### Daily Usage

```powershell
# Start everything
.\scripts\start_all.ps1

# Check status
.\scripts\status_all.ps1

# Stop everything
.\scripts\stop_all.ps1
```

## 📖 Detailed Usage

### Start Server

**Basic start (foreground):**
```powershell
.\scripts\start_server.ps1
# Server runs in terminal, Ctrl+C to stop
```

**Background start:**
```powershell
.\scripts\start_server.ps1 -Background
# Server runs in background, use stop_server.ps1 to stop
```

**Custom port:**
```powershell
.\scripts\start_server.ps1 -Port 9443 -Background
```

**Initialize CA on first start:**
```powershell
.\scripts\start_server.ps1 -InitCA -Background
```

### Stop Server

**Graceful stop:**
```powershell
.\scripts\stop_server.ps1
# Waits up to 10 seconds for graceful shutdown
```

**Force stop:**
```powershell
.\scripts\stop_server.ps1 -Force
# Kills process immediately
```

### Check Status

**Basic status:**
```powershell
.\scripts\status_server.ps1
# Shows process status and HTTP endpoint check
```

**Detailed status:**
```powershell
.\scripts\status_server.ps1 -Detailed
# Shows health, statistics, and server info
```

**All services:**
```powershell
.\scripts\status_all.ps1
# Shows server + GUI status
```

### Restart Server

```powershell
.\scripts\restart_server.ps1 -Background
# Stops server, waits 2 seconds, starts in background
```

### Start Frontend

**Default server:**
```powershell
.\scripts\start_frontend.ps1
# Connects to https://localhost:8443
```

**Custom server:**
```powershell
.\scripts\start_frontend.ps1 -Server https://pki.vcc.local:8443
```

### Stop Frontend

```powershell
.\scripts\stop_frontend.ps1
# Or just close the GUI window
```

## 🛠️ Features

### ✅ Process Management
- PID file tracking (`pki_server.pid`, `pki_frontend.pid`)
- Background process support
- Graceful shutdown with timeout
- Force kill option

### ✅ Health Checks
- Process status monitoring
- HTTP endpoint validation
- Uptime tracking
- Resource usage (CPU, Memory)

### ✅ Logging
- Server logs: `logs/pki_server.log`
- Automatic log directory creation
- Timestamps on all operations

### ✅ Error Handling
- Stale PID file cleanup
- Dependency checking (Python, tkinter)
- Clear error messages
- Color-coded output

### ✅ Auto-Setup
- Creates data directories (`data/ca`, `data/certs`, `data/crl`)
- Creates logs directory
- Checks Python installation
- Validates tkinter availability

## 🎨 Color Output

Scripts use color-coded output for better readability:

- 🟢 **Green (✓)**: Success messages
- 🔴 **Red (✗)**: Error messages
- 🟡 **Yellow (⚠)**: Warning messages
- 🔵 **Cyan (ℹ)**: Info messages

## 📊 Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error (process failed, already running, etc.) |

## 🔧 Troubleshooting

### Server won't start

```powershell
# Check if already running
.\scripts\status_server.ps1

# Check logs
Get-Content logs\pki_server.log -Tail 50

# Remove stale PID file
Remove-Item pki_server.pid -Force
```

### GUI won't start

```powershell
# Check if tkinter is installed
python -c "import tkinter; print('OK')"

# Check server is running
.\scripts\status_server.ps1

# Try with explicit server URL
.\scripts\start_frontend.ps1 -Server https://localhost:8443
```

### Port already in use

```powershell
# Check what's using port 8443
netstat -ano | findstr :8443

# Use different port
.\scripts\start_server.ps1 -Port 9443 -Background
.\scripts\start_frontend.ps1 -Server https://localhost:9443
```

### Server not responding

```powershell
# Check detailed status
.\scripts\status_server.ps1 -Detailed

# Force restart
.\scripts\stop_server.ps1 -Force
.\scripts\start_server.ps1 -Background
```

## 📝 Notes

### Windows Firewall
First time you start the server, Windows Firewall may prompt for network access. Allow access for proper operation.

### Self-Signed Certificates
The GUI and scripts ignore SSL certificate validation for self-signed certificates. This is expected for development environments.

### Background Processes
- **Server**: Should run in background (`-Background`)
- **GUI**: Should run in foreground (default)
- Use `Get-Process python` to see all Python processes

### PID Files
- Location: `C:\VCC\PKI\pki_server.pid` and `pki_frontend.pid`
- Automatically created/removed by scripts
- Manual cleanup if stale: `Remove-Item *.pid -Force`

## 🔗 Related Documentation

- [PKI Server Documentation](../docs/PKI_SERVER.md)
- [PKI Admin CLI](../docs/PKI_ADMIN_CLI.md)
- [Service Integration Guide](../SERVICE_INTEGRATION_TODO.md)

## 📞 Quick Reference

```powershell
# Start everything
.\scripts\start_all.ps1

# Check status
.\scripts\status_all.ps1

# View server logs
Get-Content logs\pki_server.log -Tail 50 -Wait

# Stop everything
.\scripts\stop_all.ps1

# Restart server only
.\scripts\restart_server.ps1 -Background
```

---

**Last Updated:** 2025-10-13  
**Version:** 1.0.0
