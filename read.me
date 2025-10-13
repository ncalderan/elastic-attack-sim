# Elastic Attack Simulation — Click-to-Sim (Local)

Spin up a local UI, enter your Elastic Cloud credentials, pick a use-case, and stream a coherent attack simulation that triggers **prebuilt Elastic Security rules (non-ML)**.

- **UI:** Streamlit
- **Generator:** Python
- **Data Streams:** `logs-*` (Windows Security, Windows PowerShell, Endpoint API, AWS CloudTrail, PAN-OS)

---

## ✨ What You'll Get

- A local web UI that:
  - Securely saves **Elastic Cloud ID** + **API Key** to `.env`
  - Lets you select a **Use-Case Pack** (4 tiles; 1 active now)
  - Runs the generator and streams logs live
- Data lands in your Elastic Cloud cluster and (with the right rules enabled) creates a cohesive alert chain

---

## ✅ Prerequisites

- **Python 3.9+**
- **Elastic Cloud** deployment & credentials:
  - **Cloud ID** (Elastic Cloud console → copy Cloud ID)
  - **API Key** (Stack Management → Security → API Keys → Create)
    - Suggested privileges:
      - **Elasticsearch:** `monitor` and `write` on `logs-*`
      - **Kibana (optional for future auto-rules):** Detection Engine manage rules

---

## 📦 Project Layout

```
attack-sim-ui/
├─ app.py                      # Streamlit UI
├─ script_runner.py            # wraps generator, streams logs to UI
├─ packs.py                    # use-case definitions (1 active, 3 stubs)
├─ generators/
│  └─ elastic_attack_sim_v2.py # bundled generator (non-ML)
├─ .env.example                # sample env; UI writes .env for you
├─ requirements.txt
└─ README.md                   # this file
```

---

## 🚀 Install & Run

### 1. Create a Virtual Environment

```bash
python -m venv .venv
```

### 2. Activate the Virtual Environment

**macOS/Linux:**
```bash
source .venv/bin/activate
```

**Windows:**
```bash
.venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Launch the UI

```bash
streamlit run app.py
```

Your browser will open automatically (or open the printed localhost URL).

---

## 🧭 First-Time Setup in the UI

### 1. Sidebar → Elastic Credentials

- Paste **Elastic Cloud ID**
- Paste **API Key**
- Click **Save** (persists to `.env` and current session)
- Optionally **Test Connection** to verify

### 2. Defaults (Sidebar)

- **Namespace:** `simulation` (use a new one per run if you want a clean stream)
- **Event Count / Rate / Batch Size / Seed:** keep defaults or adjust

### 3. Pick a Use-Case Pack

- Click **Run: Windows Persistence (Task + PS + LSASS)**
- The generator runs; logs appear live in the main panel

### 4. After It Finishes

- Open **Security → Alerts** in Kibana to review fired rules
- Use **Discover** with the provided queries to explore data

---

## 🔔 Expected Alerts & Data (Current Active Pack)

**Enable these exact prebuilt (non-ML) rules in Kibana** if not already enabled:

### Windows Rules

- `A scheduled task was created`
- `Windows Event Logs Cleared`
- `Suspicious Windows Powershell Arguments`
- `PowerShell Suspicious Payload Encoded and Compressed`
- `Suspicious Portable Executable Encoded in Powershell Script`
- `Suspicious Lsass Process Access`

### AWS CloudTrail Rules

- `AWS IAM User Created Access Keys For Another User`
- `AWS IAM AdministratorAccess Policy Attached to User`

### Recommended Rule Settings

- **Indices:** include your data streams, e.g. `logs-windows.security-*`, `logs-windows.powershell-*`, `logs-endpoint.events.api-*`, `logs-aws.cloudtrail-*`
- **Timestamp override:** `@timestamp`
- **Additional look-back time:** `2h`
- After edits, click **Run rule** once

### Quick Discover Queries (Last 2h)

**Scheduled Task:**
```
data_stream.dataset:"windows.security"
AND winlog.event_id:4698
AND event.action:"scheduled-task-created"
```

**Event Logs Cleared:**
```
data_stream.dataset:"windows.security"
AND winlog.event_id:1102
AND (event.action:"audit-log-cleared" OR event.action:"Log clear")
```

**PowerShell Encoded + Compressed:**
```
data_stream.dataset:"windows.powershell"
AND powershell.file.script_block_text:(FromBase64String AND (GzipStream OR DeflateStream))
```

**LSASS API Access:**
```
data_stream.dataset:"endpoint.events.api"
AND process.Ext.api.name:"OpenProcess"
AND Target.process.name:"lsass.exe"
```

**AWS IAM:**
```
data_stream.dataset:"aws.cloudtrail"
AND (event.action:"CreateAccessKey" OR event.action:"AttachUserPolicy")
```

---

## 🔐 Credentials & Environment

On first run the UI creates a local `.env` (from `.env.example`) and stores:

```env
ELASTIC_CLOUD_ID=...
ELASTIC_API_KEY=...

DEFAULT_NAMESPACE=simulation
DEFAULT_COUNT=1000
DEFAULT_RATE=200
DEFAULT_BATCH_SIZE=500
DEFAULT_SEED=42
```

- You can edit `.env` in a text editor
- The UI also keeps credentials in session so they work immediately after **Save**

> **Security tip:** API keys in `.env` live only on your machine. Delete `.env` to remove saved credentials.

---

## 🧰 Troubleshooting

### "Missing credentials…" after Save

- Fixed in the app: Save updates session and `os.environ`, then refreshes. If you edited fields, click **Save** again.

### Generator error: `unrecognized arguments: --batch_size`

- Fixed in the runner: underscores are normalized to hyphens (e.g., `--batch-size`) automatically.

### "Connection failed" on Test Connection

- Verify Cloud ID & API Key are correct and belong to the same deployment
- API key must allow index writes to `logs-*`

### No alerts appear

- Confirm the relevant **rules are enabled** and pointed to your `logs-*` streams
- Set **Timestamp override** to `@timestamp` (or attach an ingest pipeline to stamp `event.ingested`)
- Set **Additional look-back** to `2h` and click **Run rule**
- Verify data exists in Discover using the queries above

### EQL errors like "Unknown column …" or "incompatible types"

- Scope the rule **Indices** to the streams that contain the referenced fields (e.g., only `logs-windows.security-*` for 4698)
- Avoid querying across streams where `winlog.event_id` has mixed types. If you need string matching, consider a runtime twin or apply a surgical template for **new** data.

### Fresh run without mixing prior data

- Change the **Namespace** in the sidebar (e.g., `simulation2`). New data streams will be created automatically.

---

## 🧩 Extending (Coming Soon)

The UI is pack-driven. Add more packs by editing `packs.py`:

- `title`, `description`
- `generator_script` (you can reuse the bundled generator)
- `generator_args` (count/rate/namespace/etc.)
- Optional `discover_queries` and `expected_alerts`

### Future Enhancements

- **Auto enable/patch rules** via Kibana Detection Engine API
- Pack verification (min alert counts)
- One-click "Open Alerts/Discover" links

---

## 🧹 Uninstall / Clean Up

1. Stop Streamlit (`Ctrl+C` in terminal)
2. Deactivate venv: `deactivate`
3. Remove local credentials: delete `.env`
4. Remove venv folder `.venv` if desired

---

## 🙌 Support

If a specific rule isn't firing, copy a **sample document JSON** from **Discover** and compare its fields to the rule conditions. Share the JSON + rule title and we can pinpoint the mismatch quickly.

Happy simulating! 🛡️