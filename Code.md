AI-Powered Log Analyzer. It includes:

parser.py — parse Apache access logs (Common/Combined) and CSV-exported Windows Event logs.

anomaly_detector.py — simple rule-based anomaly detection (IPs with many requests, repeated 4xx/5xx, high request rates).

ai_reporter.py — calls OpenAI to explain anomalies in plain English (set OPENAI_API_KEY in your env).

app.py — a minimal Streamlit UI to upload logs, run parsing → detection → AI report.

requirements.txt and brief run instructions.

I used Python programming language to communicate the 5 coding entries.

**parser.py**
Simple parsers:
- Apache access logs (Common/Combined log format) -> dicts
- Windows Event Log exported as CSV -> dicts
"""

import re
import csv
from datetime import datetime
from typing import List, Dict

# Regex for Common/Combined Apache log format
APACHE_COMBINED_REGEX = re.compile(
r'(?P<remote_host>\S+) ' # IP
r'(?P<ident>\S+) ' # ident
r'(?P<authuser>\S+) ' # authuser
r'\[(?P<time>[^\]]+)\] ' # time
r'"(?P<request>[^"]+)" ' # request line
r'(?P<status>\d{3}) ' # status
r'(?P<bytes>\S+)' # bytes
r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)

APACHE_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z" # e.g., 10/Oct/2000:13:55:36 -0700

def parse_apache_line(line: str) -> Dict:
m = APACHE_COMBINED_REGEX.match(line)
if not m:
return {}
d = m.groupdict()
# parse time
try:
d['time'] = datetime.strptime(d['time'], APACHE_TIME_FORMAT)
except Exception:
try:
d['time'] = datetime.strptime(d['time'].split()[0], "%d/%b/%Y:%H:%M:%S")
except Exception:
d['time'] = None
# split request
req_parts = d.get('request', '').split()
d['method'] = req_parts[0] if len(req_parts) > 0 else None
d['path'] = req_parts[1] if len(req_parts) > 1 else None
d['protocol'] = req_parts[2] if len(req_parts) > 2 else None
# convert numeric
d['status'] = int(d['status']) if d.get('status') and d['status'].isdigit() else None
d['bytes'] = int(d['bytes']) if d.get('bytes') and d['bytes'].isdigit() else 0
return d

def parse_apache_file(path: str) -> List[Dict]:
parsed = []
with open(path, 'r', encoding='utf-8', errors='ignore') as f:
for line in f:
p = parse_apache_line(line.strip())
if p:
parsed.append(p)
return parsed

def parse_windows_event_csv(path: str) -> List[Dict]:
"""
Expects Windows Event exported to CSV (EventTime, ProviderName, Id, Level, Task, Opcode, RecordId, ProcessId, ThreadId, Computer, Message, etc.)
"""
parsed = []
with open(path, newline='', encoding='utf-8', errors='ignore') as csvfile:
reader = csv.DictReader(csvfile)
for row in reader:
# try to normalize timestamp field names
time_field = None
for candidate in ['TimeCreated', 'Time', 'EventTime', 'Date', 'Timestamp']:
if candidate in row and row[candidate]:
time_field = candidate
break
timestamp = None
if time_field:
try:
timestamp = datetime.fromisoformat(row[time_field])
except Exception:
try:
timestamp = datetime.strptime(row[time_field], "%m/%d/%Y %I:%M:%S %p")
except Exception:
timestamp = row[time_field]
row['time'] = timestamp
parsed.append(row)
return parsed

if __name__ == "__main__":
# quick local test
import sys
path = sys.argv[1] if len(sys.argv) > 1 else "examples/apache_access.log"
parsed = parse_apache_file(path)
print(f"Parsed {len(parsed)} lines. Example:")
print(parsed[:2])


**anomaly_detector.py**
Basic rule-based anomaly detection on parsed logs.
Produces a list of anomaly dicts with short descriptions and metadata.
"""
from collections import Counter, defaultdict
from datetime import timedelta
from typing import List, Dict

def detect_apache_anomalies(parsed_logs: List[Dict]) -> List[Dict]:
anomalies = []
if not parsed_logs:
return anomalies

# Count requests per IP
ip_counts = Counter([l.get('remote_host') for l in parsed_logs if l.get('remote_host')])
# flag top IPs
for ip, cnt in ip_counts.most_common(10):
if cnt > 200: # rule: many requests in log file (tweak threshold)
anomalies.append({
"type": "high_request_count",
"ip": ip,
"count": cnt,
"message": f"IP {ip} made {cnt} requests (threshold: 200)."
})

# repeated 4xx/5xx responses by IP
ip_status = defaultdict(Counter)
for l in parsed_logs:
ip = l.get('remote_host')
status = l.get('status') or 0
ip_status[ip][status] += 1
for ip, counter in ip_status.items():
errors = sum(v for k, v in counter.items() if 400 <= k < 600)
if errors > 50:
anomalies.append({
"type": "many_errors",
"ip": ip,
"errors": errors,
"message": f"IP {ip} generated {errors} 4xx/5xx responses."
})

# burst detection: requests per minute
times = sorted([l['time'] for l in parsed_logs if l.get('time')])
if times:
window = timedelta(minutes=1)
i = 0
n = len(times)
while i < n:
j = i + 1
while j < n and (times[j] - times[i]) <= window:
j += 1
if j - i > 100: # >100 requests in one minute
anomalies.append({
"type": "traffic_spike",
"start_time": times[i].isoformat() if hasattr(times[i], 'isoformat') else str(times[i]),
"count": j - i,
"message": f"Traffic spike: {j - i} requests within 1 minute starting {times[i]}."
})
i += 1

# suspicious paths (common probes)
suspicious_paths = ["/wp-login.php", "/xmlrpc.php", "/admin", "/.env", "/phpmyadmin"]
path_counter = Counter([l.get('path') for l in parsed_logs if l.get('path')])
for p in suspicious_paths:
cnt = path_counter.get(p, 0)
if cnt > 0:
anomalies.append({
"type": "suspicious_path_probe",
"path": p,
"count": cnt,
"message": f"Probing of {p} detected {cnt} times."
})
return anomalies

def detect_windows_event_anomalies(parsed_events: List[Dict]) -> List[Dict]:
anomalies = []
# Example rule: many failed login events (EventID 4625 on Windows)
event_id_counts = Counter([row.get('Id') or row.get('EventID') or row.get('Id') for row in parsed_events])
# For CSV they might be strings; attempt to convert:
for key, cnt in event_id_counts.items():
try:
eid = int(key)
except Exception:
continue
if eid == 4625 and cnt > 20: # failed login event
anomalies.append({
"type": "failed_logins",
"event_id": eid,
"count": cnt,
"message": f"Detected {cnt} failed login events (EventID 4625)."
})
return anomalies

if __name__ == "__main__":
# Simple local test harness
from parser import parse_apache_file
p = parse_apache_file("examples/apache_access.log")
a = detect_apache_anomalies(p)
print("Anomalies:", a)



**ai_reporter.py**
Takes anomalies list and asks an LLM to summarize/explain them in plain English.
Requires OPENAI_API_KEY in environment.
"""
import os
import openai
from typing import List, Dict

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
# leave a gentle note; the app will still run but AI calls will fail without a key
pass
openai.api_key = OPENAI_API_KEY

def anomalies_to_prompt(anomalies: List[Dict]) -> str:
if not anomalies:
return "No significant anomalies detected in the provided logs. Provide a short summary confirming that."
prompt = "You are a security analyst. Here are detected anomalies from server logs:\n\n"
for i, a in enumerate(anomalies, 1):
prompt += f"{i}. Type: {a.get('type')}\n"
for k, v in a.items():
if k != 'type':
prompt += f" - {k}: {v}\n"
prompt += "\n"
prompt += (
"Please write a concise human-readable report (3-6 short paragraphs):\n"
"- Summarize what likely happened.\n"
"- Explain severity (low/medium/high) and why.\n"
"- Give 3 recommended next steps an IT admin could take (short actionable items).\n"
"Keep language simple and avoid long technical jargon."
)
return prompt

def generate_ai_report(anomalies: List[Dict], model: str = "gpt-4o-mini") -> str:
"""
Calls OpenAI ChatCompletion API to generate a report.
Change model name as needed. Make sure OPENAI_API_KEY env var is set.
"""
prompt = anomalies_to_prompt(anomalies)
if not OPENAI_API_KEY:
return ("[OpenAI API key not set. Set OPENAI_API_KEY in your environment to enable AI reporting.]\n\n"
+ "Detected anomalies:\n" + "\n".join(a.get('message', str(a)) for a in anomalies))
try:
resp = openai.ChatCompletion.create(
model=model,
messages=[{"role": "user", "content": prompt}],
max_tokens=400,
temperature=0.2,
)
text = resp['choices'][0]['message']['content'].strip()
return text
except Exception as e:
return f"[AI report generation failed: {e}]\n\n" + "Detected anomalies:\n" + "\n".join(a.get('message', str(a)) for a in anomalies)

if __name__ == "__main__":
# quick local run
example = [{"type":"high_request_count","ip":"1.2.3.4","count":300,"message":"..."}]
print(generate_ai_report(example))



**app.py**
Minimal Streamlit app to upload a log, run detection and show AI report.
Run: streamlit run src/app.py
"""
import streamlit as st
from parser import parse_apache_file, parse_windows_event_csv
from anomaly_detector import detect_apache_anomalies, detect_windows_event_anomalies
from ai_reporter import generate_ai_report
import tempfile
import os

st.set_page_config(page_title="AI Log Analyzer", layout="centered")
st.title("AI-Powered Log Analyzer — MVP")

uploaded = st.file_uploader("Upload a log file (Apache access log or Windows Event CSV)", type=["log", "txt", "csv"])
if uploaded:
# save to temp file
with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded.name)[1]) as tmp:
tmp.write(uploaded.getvalue())
tmp_path = tmp.name

st.write(f"Saved uploaded file to `{tmp_path}` (for processing)")

# Try Apache parsing first
parsed = parse_apache_file(tmp_path)
parsed_type = "apache"
if not parsed:
try:
parsed = parse_windows_event_csv(tmp_path)
parsed_type = "windows"
except Exception:
parsed = []

st.write(f"Parsed {len(parsed)} entries (detected type: {parsed_type})")

if parsed_type == "apache":
anomalies = detect_apache_anomalies(parsed)
else:
anomalies = detect_windows_event_anomalies(parsed)

st.subheader("Detected anomalies")
if not anomalies:
st.success("No anomalies detected by the basic rules.")
else:
for a in anomalies:
st.markdown(f"- **{a.get('type')}** — {a.get('message')}")

if st.button("Generate AI Report (may require OPENAI_API_KEY)"):
with st.spinner("Generating AI report..."):
report = generate_ai_report(anomalies)
st.subheader("AI Report")
st.write(report)

# cleanup temp file
try:
os.remove(tmp_path)
except Exception:
pass
else:
st.info("Upload an example Apache access log or Windows Event CSV to get started.")


**Requirements.txt**

openai>=0.27.0
pandas>=1.3.0
streamlit>=1.10.0
python-dateutil
