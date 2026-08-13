import re
from collections import defaultdict

# Simulated authentication log stream
logs = [
    "2026-08-13 10:00:01 IP: 192.168.1.50 STATUS: FAILED_LOGIN User: admin",
    "2026-08-13 10:00:05 IP: 192.168.1.50 STATUS: FAILED_LOGIN User: root",
    "2026-08-13 10:00:10 IP: 192.168.1.50 STATUS: FAILED_LOGIN User: admin",
    "2026-08-13 10:00:15 IP: 192.168.1.50 STATUS: FAILED_LOGIN User: user1",
    "2026-08-13 10:01:00 IP: 10.0.0.12 STATUS: SUCCESS User: alice",
    "2026-08-13 10:02:00 IP: 172.16.0.4 STATUS: FAILED_LOGIN User: test",
]

FAILED_THRESHOLD = 3
failed_attempts = defaultdict(int)

print("--- Running SOC Log Analyzer ---")

for line in logs:
    ip_match = re.search(r'IP:\s*([\d\.]+)', line)
    if ip_match and 'FAILED_LOGIN' in line:
        ip = ip_match.group(1)
        failed_attempts[ip] += 1

print("\n--- Security Alerts ---")
alerts_triggered = False
for ip, count in failed_attempts.items():
    if count >= FAILED_THRESHOLD:
        print(f"[ALERT] Potential Brute-Force Attack detected from IP: {ip} ({count} failed attempts)")
        alerts_triggered = True

if not alerts_triggered:
    print("No brute-force threats detected.")
