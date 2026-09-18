# Network Packet Sniffer

Starter Python project with Scapy packet capture and a FastAPI health endpoint.
Supabase is included for future storage integration.

## Setup (Windows PowerShell)

```powershell
cd network-packet-sniffer
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Run the API

```powershell
python -m uvicorn packet_sniffer.api:app --app-dir src --reload
```

Visit http://127.0.0.1:8000/docs for API documentation.

## Structure

```text
network-packet-sniffer/
├── requirements.txt
├── README.md
├── .gitignore
├── src/
│   └── packet_sniffer/
│       ├── __init__.py
│       ├── api.py
│       └── capture.py
└── tests/
```

Use Python 3.10 or newer. Packet capture is separate from the API and may require
administrator privileges and a platform-specific capture driver.
