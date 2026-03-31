<<<<<<< HEAD
# network-scan-tool
Python-based network scanning tool for port and service detection

## Features
- Port scanning
- Scan history
- Web interface

## Run
pip install -r requirements.txt
python manage.py runserver
=======
# 🔍 NetScan Pro — Network Scanner Tool

> A full-featured network scanning platform built with Python & Django.  
> Port scanning · Service detection · Banner grabbing · PDF/CSV export · Scan history

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)
![Django](https://img.shields.io/badge/Django-4.2-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

---

## ✨ Features

| Feature | Description |
|---|---|
| 🎯 **Port Scanning** | Multi-threaded TCP socket scanning — up to 100 threads |
| 🔎 **Service Detection** | Fingerprints HTTP, SSH, FTP, SMTP, DNS, MySQL, RDP & 15+ more |
| 📡 **Banner Grabbing** | Extracts service banners and version strings from open ports |
| 🗺️ **nmap Integration** | Optional deep scan via nmap `-sV` for OS + version detection |
| 📊 **Scan History** | SQLite-backed persistent history of all scans |
| 📄 **Report Export** | Export full scan reports as PDF (ReportLab) or CSV |
| 🌐 **Web UI** | Responsive dark-mode dashboard with live progress polling |

---

## 🖥️ Screenshots

```
┌─────────────────────────────────────────┐
│  ◈ NetScanPro              [Scanner] [History] │
├─────────────────────────────────────────┤
│                                         │
│   Map Every                             │
│   Open Door  ←── hero headline          │
│                                         │
│  TARGET HOST: [192.168.1.1_________] ⟳ │
│  PORT RANGE:  [Common] [Full] [Custom]  │
│  ENGINE:      ⬡ TCP  ⚡ Fast  ◎ Service │
│                                         │
│        [ ▶  INITIATE SCAN ]             │
└─────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/yourusername/network-scanner-tool.git
cd network-scanner-tool
```

### 2. Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate         # Windows
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run database migrations
```bash
python manage.py makemigrations
python manage.py migrate
```

### 5. Create an admin user (optional)
```bash
python manage.py createsuperuser
```

### 6. Start the development server
```bash
python manage.py runserver
```

Then open **http://127.0.0.1:8000** in your browser.

---

## 🛠️ Optional: Enable nmap Integration

Install nmap on your system:

```bash
# Ubuntu/Debian
sudo apt install nmap

# macOS
brew install nmap

# Windows — download from https://nmap.org/download.html
```

When nmap is detected, the status indicator in the navbar turns green and deep service detection is enabled.

---

## 📁 Project Structure

```
network_scanner_tool/
├── core/                     # Django project config
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── scanner/                  # Main scanning app
│   ├── engine.py             # ← Core scanning engine (socket + nmap)
│   ├── models.py             # ScanJob, PortResult
│   ├── views.py              # Web views + JSON API
│   ├── urls.py
│   ├── admin.py
│   ├── static/scanner/
│   │   ├── css/main.css      # Dark terminal UI
│   │   └── js/app.js         # Scan launcher + polling
│   └── templates/scanner/
│       ├── index.html        # Dashboard / scan panel
│       ├── result.html       # Scan result detail
│       └── history.html      # Scan history table
├── reports/                  # Export module
│   ├── views.py              # PDF (ReportLab) + CSV export
│   └── urls.py
├── manage.py
└── requirements.txt
```

---

## ⚙️ Configuration (core/settings.py)

```python
SCAN_TIMEOUT = 2        # Seconds per port connection attempt
MAX_THREADS  = 100      # Concurrent scanning threads
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/scan/start/` | Launch a new scan job |
| `GET`  | `/scan/<id>/status/` | Poll job status + results |
| `GET`  | `/scan/<id>/result/` | Full HTML result page |
| `GET`  | `/reports/<id>/csv/` | Download CSV report |
| `GET`  | `/reports/<id>/pdf/` | Download PDF report |
| `POST` | `/scan/<id>/delete/` | Delete a scan record |

### POST `/scan/start/` payload
```json
{
  "target":     "192.168.1.1",
  "port_range": "1-1024",
  "scan_type":  "tcp"
}
```

---

## 🧩 Architecture

```
Browser (Web UI)
      │
      ▼
Django Views (scanner/views.py)
      │
      ▼
Scanning Engine (scanner/engine.py)
      │
   ┌──┴──────────────────┐
   │                     │
socket (TCP)          nmap subprocess
   │                     │
   └──────────┬──────────┘
              │
              ▼
         PortResult (SQLite)
              │
              ▼
       Reports (PDF / CSV)
```

---

## ⚠️ Legal Disclaimer

> **This tool is intended for authorized security testing only.**  
> Scanning networks or systems without explicit permission is illegal in most jurisdictions.  
> The authors accept no responsibility for misuse of this software.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.
>>>>>>> bbf8ba2 (Initial commit - Django network scanner tool)
