# Network Packet Sniffer

A real-time network telemetry pipeline that captures packets with **Scapy**, batch-inserts traffic metadata into **Supabase PostgreSQL**, and serves aggregated analytics through a **FastAPI REST API**.

```text
Network traffic → Scapy capture → Supabase PostgreSQL → FastAPI analytics
```

The capture process collects 10 packets at a time and immediately inserts the IPv4/IPv6 records into the `network_traffic` table. Each record contains the source IP, destination IP, numeric protocol identifier, and payload size in bytes. Non-IP packets are skipped. Payload size measures the IP-layer payload, including transport headers; raw packet contents are not stored.

## Quickstart

Use Python 3.10 or newer and a Supabase project. On Windows, packet capture requires a capture driver such as Npcap and may require an administrator terminal.

### 1. Install dependencies

From the directory containing this project, run in PowerShell:

```powershell
cd network-packet-sniffer
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### 2. Prepare Supabase

Create the table in the Supabase SQL editor:

```sql
create table public.network_traffic (
    id bigint generated always as identity primary key,
    source_ip inet not null,
    destination_ip inet not null,
    protocol integer not null,
    payload_size bigint not null check (payload_size >= 0)
);

alter table public.network_traffic enable row level security;
```

Use a server-side Supabase key with permission to insert and select rows. For a local setup, a service-role key can access this table with RLS enabled. Keep that key private and out of source control. Other key types need appropriate grants and RLS policies.

Set the environment variables in each terminal that runs the capture process or API:

```powershell
$env:SUPABASE_URL = "https://your-project.supabase.co"
$env:SUPABASE_KEY = "your-server-side-key"
```

### 3. Start capture and the API

In the first terminal, with the virtual environment activated and environment variables set:

```powershell
python src/packet_sniffer/capture.py
```

In a second terminal, open the project directory, activate the same virtual environment, set the environment variables, and start the API:

```powershell
.\.venv\Scripts\Activate.ps1
python -m uvicorn packet_sniffer.api:app --app-dir src --host 127.0.0.1 --port 8000
```

Stop either process with `Ctrl+C`.

## REST endpoints

| Endpoint | Response |
| --- | --- |
| `GET /api/stats` | Total packets recorded, the five most frequent source IPs with counts, and total payload bytes |
| `GET /health` | Process liveness: `{"status": "ok"}` |
| `GET /docs` | Interactive API documentation |

Query the analytics endpoint:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/stats
```

Example response:

```json
{
  "total_packets": 120,
  "top_source_ips": [
    {"source_ip": "192.168.1.10", "count": 80},
    {"source_ip": "192.168.1.20", "count": 40}
  ],
  "total_payload_bytes": 24576
}
```

Analytics are calculated on request over all rows visible to the configured Supabase key, using paginated queries. Concurrent writes can affect multi-page results. The health check does not test database connectivity.

## Project structure

```text
network-packet-sniffer/
├── requirements.txt
├── README.md
├── .gitignore
├── src/
│   └── packet_sniffer/
│       ├── __init__.py
│       ├── capture.py
│       └── api.py
└── tests/
    └── test_api.py
```
