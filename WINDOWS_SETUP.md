# Windows Setup Guide (Python)

This guide helps you set up and run the DPI Engine on Windows using Python 3. No C++ compiler is required.

---

## Prerequisites

- **Python 3.9 or newer** (3.11+ recommended)
- No third-party packages required (stdlib only)

---

## Option 1: Quick Start (Recommended)

### Step 1: Install Python

1. Download Python from: https://www.python.org/downloads/
2. Run the installer
3. On the first screen, check **"Add python.exe to PATH"**
4. Click **"Install Now"**

### Step 2: Verify Python

Open **PowerShell** or **Command Prompt**:

```powershell
python --version
```

You should see something like `Python 3.12.x`.

If `python` is not found, try:

```powershell
py --version
```

Use `py` instead of `python` in the commands below if needed.

### Step 3: Open the Project

```powershell
cd C:\Users\YourName\path\to\Packet_analyzer
```

### Step 4: Create Test Data

```powershell
python generate_test_pcap.py
```

This creates `test_dpi.pcap` with sample TLS, HTTP, and DNS traffic.

### Step 5: Run the DPI Engine

**Multi-threaded (default, production):**

```powershell
python -m dpi test_dpi.pcap output.pcap
```

**Single-threaded (learning / debugging):**

```powershell
python -m dpi.dpi_simple test_dpi.pcap output.pcap
```

**With blocking rules:**

```powershell
python -m dpi test_dpi.pcap output.pcap --block-app YouTube --block-ip 192.168.1.50 --block-domain facebook
```

**Custom thread count (multi-threaded only):**

```powershell
python -m dpi test_dpi.pcap output.pcap --lbs 4 --fps 4
```

---

## Option 2: Using a Virtual Environment (Optional)

Useful if you want an isolated Python environment for this project.

```powershell
cd C:\path\to\Packet_analyzer
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python generate_test_pcap.py
python -m dpi test_dpi.pcap output.pcap
```

To deactivate later: `deactivate`

---

## Option 3: Using Visual Studio Code

### Step 1: Install VS Code

Download from: https://code.visualstudio.com/

### Step 2: Install Extensions

1. Open VS Code → Extensions (`Ctrl+Shift+X`)
2. Install **Python** (by Microsoft)

### Step 3: Open the Project

**File → Open Folder** → select the `Packet_analyzer` folder

### Step 4: Select Python Interpreter

1. `Ctrl+Shift+P` → **Python: Select Interpreter**
2. Choose your system Python or `.venv` if you created one

### Step 5: Create Build / Run Tasks (Optional)

Create `.vscode/tasks.json`:

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Generate test PCAP",
            "type": "shell",
            "command": "python",
            "args": ["generate_test_pcap.py"],
            "group": "build"
        },
        {
            "label": "Run DPI Engine",
            "type": "shell",
            "command": "python",
            "args": ["-m", "dpi", "test_dpi.pcap", "output.pcap"],
            "group": {
                "kind": "build",
                "isDefault": true
            }
        }
    ]
}
```

Press `Ctrl+Shift+B` to run the default task.

### Step 6: Run from Terminal

Open the integrated terminal (`Ctrl+``) and run:

```powershell
python -m dpi test_dpi.pcap output.pcap
```

---

## Option 4: Using WSL (Windows Subsystem for Linux)

If you prefer a Linux shell on Windows:

### Step 1: Install WSL

Open **PowerShell as Administrator**:

```powershell
wsl --install
```

Restart when prompted, then set up your Ubuntu username and password.

### Step 2: Install Python (if needed)

```bash
sudo apt update
sudo apt install -y python3 python3-venv
```

### Step 3: Navigate to the Project

Windows drives are under `/mnt/c/`:

```bash
cd /mnt/c/Users/YourName/path/to/Packet_analyzer
```

### Step 4: Run

```bash
python3 generate_test_pcap.py
python3 -m dpi test_dpi.pcap output.pcap
```

---

## Troubleshooting

### Error: `python` is not recognized

**Cause:** Python not installed or not on PATH.

**Fix:**
1. Reinstall Python and check **"Add python.exe to PATH"**
2. Or use the `py` launcher: `py -m dpi test_dpi.pcap output.pcap`
3. Restart your terminal after installing

### Error: `No module named 'dpi'`

**Cause:** Not in the project root directory.

**Fix:**

```powershell
cd C:\full\path\to\Packet_analyzer
dir dpi
```

You should see `__init__.py` and other modules inside the `dpi` folder.

### Error: Cannot open input file / missing `test_dpi.pcap`

**Fix:**

```powershell
python generate_test_pcap.py
dir test_dpi.pcap
```

### Error: Cannot open output file

**Cause:** `output.pcap` is open in Wireshark or another program.

**Fix:** Close the file or use a different name:

```powershell
python -m dpi test_dpi.pcap result.pcap
```

### PowerShell blocks script execution (venv activate)

**Fix:** Run once as Administrator:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Or use Command Prompt instead: `\.venv\Scripts\activate.bat`

### Garbled box-drawing characters in the console

The report uses Unicode box characters. If they look wrong, the program still runs correctly; use Windows Terminal for better Unicode support.

---

## Web UI (Browser Frontend)

```powershell
cd C:\path\to\Packet_analyzer
pip install -r requirements.txt
python web/app.py
```

Open **http://127.0.0.1:5000** in your browser.

- Upload a `.pcap` file (or click **Use sample PCAP**)
- Choose engine mode and blocking rules
- Click **Analyze traffic**
- View stats, app breakdown, detected domains
- Download the filtered PCAP

---

## Quick Reference

### Commands

| Task | Command |
|------|---------|
| **Generate test PCAP** | `python generate_test_pcap.py` |
| **Run (multi-threaded)** | `python -m dpi input.pcap output.pcap` |
| **Run (simple)** | `python -m dpi.dpi_simple input.pcap output.pcap` |
| **Block apps/IPs** | `python -m dpi in.pcap out.pcap --block-app YouTube --block-ip 192.168.1.50` |
| **Thread tuning** | `python -m dpi in.pcap out.pcap --lbs 4 --fps 4` |
| **Web UI** | `pip install -r requirements.txt` then `python web/app.py` |

### CLI Options

| Option | Description |
|--------|-------------|
| `--block-ip <ip>` | Block all traffic from source IP |
| `--block-app <name>` | Block app (`YouTube`, `Facebook`, etc.) |
| `--block-domain <text>` | Block if SNI contains substring |
| `--lbs <n>` | Load balancer threads (default: 2) |
| `--fps <n>` | Fast-path threads per LB (default: 2) |

---

## Getting Wireshark Captures

1. Download Wireshark: https://www.wireshark.org/download.html
2. Install and open Wireshark
3. Select your network interface (Wi-Fi or Ethernet)
4. Browse websites for ~30 seconds
5. Stop capture (red square)
6. **File → Save As** → format **pcap**
7. Run the DPI engine:

```powershell
python -m dpi my_capture.pcap filtered.pcap
```

---

## Project Layout

```
Packet_analyzer/
├── dpi/                    # Python DPI package
│   ├── __main__.py         # Default: multi-threaded engine
│   ├── dpi_engine.py       # Multi-threaded implementation
│   ├── dpi_simple.py       # Single-threaded implementation
│   ├── pcap_reader.py
│   ├── packet_parser.py
│   ├── sni_extractor.py
│   ├── types.py
│   └── rules.py
├── generate_test_pcap.py   # Creates test_dpi.pcap
├── requirements.txt
├── README.md
└── WINDOWS_SETUP.md
```

---

## Need Help?

1. Confirm Python 3.9+ is installed: `python --version`
2. Run from the project root (folder containing `dpi/`)
3. Generate test data before your first run
4. Check the Troubleshooting section above

Good luck!
