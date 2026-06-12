# 🛡️ DPI System — Deep Packet Inspection

A real-time network traffic analysis system built with **C++17** and **Python (Flask)** that captures packets from PCAP files, performs deep inspection of TCP/UDP/TLS traffic, and classifies each packet as `NORMAL` or `ATTACK` using a **Random Forest ML model** trained on the UNSW-NB15 cybersecurity dataset.

![Dashboard](https://img.shields.io/badge/Dashboard-Live-brightgreen) ![C++](https://img.shields.io/badge/C++-17-blue) ![Python](https://img.shields.io/badge/Python-3.12-yellow) ![ML](https://img.shields.io/badge/ML-Random%20Forest-orange) ![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)

---

##  Features

- Parses raw `.pcap` files — Ethernet → IP → TCP/UDP layers
- Extracts **TLS SNI** (hostname from encrypted HTTPS traffic)
- Detects **HTTP Host headers** from unencrypted traffic
- Parses **DNS queries** from UDP traffic
- Classifies traffic as `ATTACK` or `NORMAL` via a **live ML API call**
- Blocks traffic matching a configurable **blocked sites list**
- Exports results to `data/packets.json` after every packet
- **Live web dashboard** — opens in browser, updates every 2 seconds

---

##  Architecture

```
.pcap file
    │
    ▼
C++ Capture Engine          Reads raw binary packets
    │
    ▼
Packet Parser (C++)         Parses Ethernet / IP / TCP / UDP / TLS / DNS
    │
    ├──► HTTP  →  Extract Host header  →  Check blocklist
    ├──► HTTPS →  Extract TLS SNI      →  Check blocklist
    └──► DNS   →  Extract domain       →  Check blocklist
    │
    ▼
ML API Call (curl)          POST /predict → Flask (Python)
    │
    ▼
Random Forest Model         Trained on UNSW-NB15 dataset
    │
    ▼
Decision: NORMAL / ATTACK
    │
    ▼
packets.json                Updated live after every packet
    │
    ▼
dashboard.html              Live browser dashboard (polls every 2s)
```

---

##  Tech Stack

| Layer | Technology |
|---|---|
| Packet capture & parsing | C++17, Winsock2 |
| ML model | Python, scikit-learn (Random Forest, 150 trees) |
| ML API server | Flask (REST API) |
| Dataset | UNSW-NB15 (cybersecurity benchmark) |
| Dashboard | HTML, CSS, JavaScript, Chart.js |
| Build | g++ (MinGW/MSYS2) |

---

##  Project Structure

```
Packet_Capture/
├── src/
│   ├── main.cpp             # Entry point, JSON export, menu
│   ├── capture_engine.cpp   # PCAP file reader
│   ├── packet_parser.cpp    # Packet parsing + ML API calls
│   ├── pcap_reader.cpp      # Low-level PCAP binary reader
│   └── exporter.cpp         # Raw packet exporter
├── include/
│   ├── packet_parser.h
│   ├── capture_engine.h
│   ├── packet.h
│   └── ...
├── ml/
│   ├── ids_api.py           # Flask REST API server
│   ├── train_model.py       # Model training script
│   ├── ids_model.pkl        # Trained Random Forest model
│   └── columns.pkl          # Feature columns
├── data/
│   ├── test.pcap            # Sample PCAP file
│   └── packets.json         # Live output (auto-generated)
├── dashboard.html           # Live web dashboard
└── config.json              # Blocked sites + settings
```

---

##  Prerequisites

- Windows 10/11
- [MSYS2](https://www.msys2.org/) with `g++` installed
- Python 3.10+
- `curl` available in PATH (comes with Windows 10+)

---

## 🚀 How to Run

### Step 1 — Add compiler to PATH (run once per session if needed)
```powershell
$env:Path += ";C:\msys64\ucrt64\bin"
```

### Step 2 — Navigate to project folder
```powershell
cd "C:\Users\HP\OneDrive\Desktop\dpi\DPI\Packet_Capture"
```

### Step 3 — Compile
```powershell
g++ -std=c++17 -I include src/main.cpp src/capture_engine.cpp src/pcap_reader.cpp src/packet_parser.cpp src/exporter.cpp -o capture_service.exe -lws2_32
```

### Step 4 — Start the ML API (open a second terminal)
```powershell
cd "C:\Users\HP\OneDrive\Desktop\dpi\DPI\Packet_Capture\ml"
pip install flask pandas scikit-learn joblib
py ids_api.py
```

Wait until you see:
```
* Running on http://127.0.0.1:5000
```

### Step 5 — Run the DPI system
```powershell
cd "C:\Users\HP\OneDrive\Desktop\dpi\DPI\Packet_Capture"
.\capture_service.exe
```

Press `1` to analyze packets.

### Step 6 — Open the live dashboard
Double-click `dashboard.html` in the project folder, or open it in your browser. It updates automatically every 2 seconds.

---

## 📊 Sample Output

```
Packet #4
 | Src IP: 192.168.1.100
 | Dst IP: 142.250.185.206
 | Protocol: TCP
 | Src Port: 54552
 | Dst Port: 443
 | ML Decision: NORMAL
 | Application: HTTPS (TLS)
 | SNI: www.google.com
 ✅ ALLOWED

Packet #8
 | Src IP: 192.168.1.100
 | Dst IP: 142.250.185.110
 | Protocol: TCP
 | Src Port: 58867
 | Dst Port: 443
 | ML Decision: NORMAL
 | Application: HTTPS (TLS)
 | SNI: www.youtube.com
 🚫 BLOCKED (HTTPS)
```

---

##  ML Model Details

| Property | Value |
|---|---|
| Algorithm | Random Forest Classifier |
| Trees | 150 |
| Dataset | UNSW-NB15 |
| Features | proto, sport, dport, sbytes, dbytes |
| Classes | NORMAL, ATTACK |
| API endpoint | `POST /predict` on `http://127.0.0.1:5000` |

---

##  Blocked Sites (configurable in `config.json`)

- facebook.com
- instagram.com
- youtube.com
- twitter.com
- tiktok.com
- snapchat.com

---

##  Future Improvements

- [ ] Live packet capture using Npcap (replace static PCAP)
- [ ] Linux port using libpcap
- [ ] Docker containerization
- [ ] WebSocket-based real-time dashboard updates
- [ ] Alert system for ATTACK detections

---

## Shradzzz

Built as a network security project demonstrating deep packet inspection, TLS analysis, and ML-based intrusion detection.


