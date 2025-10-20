"""
mini_siem.py
================

This script implements a small simulated SIEM/SOAR concept.
It takes in pre-made log data, applies a few detection rules and a simple anomaly
detection routine, and triggers responses when suspicious activity
is identified.  The goal is to demonstrate concepts from security
operations without relying on external services or software.

Features:

- **Log ingestion**: reads log lines from a file or standard input.  Each
  log entry is assumed to be JSON or a delimited format; simple
  heuristics are used to parse raw strings.
  
- **Detection rules**: identifies multiple failed logins from the same
  user within a five‑minute window and flags connections from IP
  addresses on a blocklist.
  
- **Anomaly detection**: uses z‑score on per‑minute event counts to
  identify unusual spikes in activity.
  
- **Response actions**: prints alerts to the console and writes them
  to an alert file.  This could be extended to send webhooks or open
  tickets in a real SOAR platform.

To run the script with the provided sample logs:

    python3 generate_logs.py && python3 mini_siem.py --logfile sample_logs.txt --live

To run the "live mode" for the random log generator:

    while true; do python3 generate_logs.py; sleep 5; done

This will process the logs and output any detected issues to
`alerts.log`.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
import requests


""" send events/alerts to a local splunk page using the HTTP event collector"""
def send_to_splunk(event):
    url = "https://localhost:8088/services/collector"
    token = "YOUR TOKEN HERE"  # local token given by splunk HEC
    headers = {"Authorization": f"Splunk {token}"}
    payload = {"event": event, "sourcetype": "_json", "index": "main"}
    try:
    	"""send json to splunks HEC listener
    	verify = false skips SSL validation (works for local tests)"""
        r = requests.post(url, headers=headers, json=payload, verify=False)
        if r.status_code == 200:
            print("[Splunk] Event forwarded successfully.")
        else:
            print(f"[Splunk] Error {r.status_code}: {r.text}")
    except Exception as e:
        print(f"[!] Failed to send event: {e}")

"""one line from a log file (parsed, structured)"""
class LogRecord:
    def __init__(self, timestamp: datetime, user: str, ip: str, \
                 event: str, raw: str) -> None:
        """each log has timestamp, usernaem, ip, event type, raw string"""
        self.timestamp = timestamp
        self.user = user
        self.ip = ip
        self.event = event
        self.raw = raw

    @classmethod
    def from_line(cls, line: str) -> Optional["LogRecord"]: 
        """Parse a log line into a LogRecord.

        Example - timestamp/user/ip/event format:
        2025-01-01T12:00:00Z|alice|192.0.2.1|login_success

        If the line cannot be parsed, returns None.
        """
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
            ts = datetime.fromisoformat(data.get("timestamp", "").rstrip("Z"))
            return cls(
                timestamp=ts,
                user=data.get("user", "unknown"),
                ip=data.get("ip", "unknown"),
                event=data.get("event", "unknown"),
                raw=line,
            )
        except json.JSONDecodeError:
            # if the json fails it falls back to pipe-delimited parser
            parts = line.split("|")
            if len(parts) >= 4:
                ts_str, user, ip, event = parts[:4]
                try:
                    ts = datetime.fromisoformat(ts_str.rstrip("Z"))
                except ValueError:
                    return None
                return cls(timestamp=ts, user=user, ip=ip, event=event, raw=line)
        return None

""" applies detection logic and forwards events/alerts to splunk"""
class MiniSIEM:
    """simple log processor with detection and response capabilities."""

    def __init__(self, blocklist: Optional[Iterable[str]] = None,
                 alert_file: str = "alerts.log") -> None:
        """ blocklist is a set list of ip addresses to trigger alerts """
        self.blocklist = set(blocklist or [])
        """ path where all alters will be wirtten to """
        self.alert_file_path = Path(alert_file)
        """ dictionary to track login failures (brute-force detection) """
        self.failed_login_window: Dict[str, deque[datetime]] = defaultdict(deque)
        """ dictionary to track how many events happen each time (for anomalies) """
        self.event_counts: Dict[datetime, int] = defaultdict(int)
        
        
    def process_records(self, records: Iterable[LogRecord]) -> None:
        """process logs and apply detection rules."""
        for record in records:
            self.event_counts[record.timestamp.replace(second=0, microsecond=0)] += 1

           
            # rule 1: blocklist ips
            if record.ip in self.blocklist:
                self._respond(
                    f"Blocked IP detected: user={record.user}, ip={record.ip}, event={record.event}",
                    category="blocklist",
                    user=record.user,
                    ip=record.ip,
                )

	    # rule 2: too many failed logins in 5mins
            if record.event.lower() == "login_failure":
                dq = self.failed_login_window[record.user]
                dq.append(record.timestamp)
                """ remove any old failures longer than 5mins ago """
                cutoff = record.timestamp - timedelta(minutes=5)
                while dq and dq[0] < cutoff:
                    dq.popleft()
                """ if 3 or more failures are in the 5min window it triggers an alert """
                if len(dq) >= 3:
                    self._respond(
                        f"Multiple failed logins detected for user {record.user}: {len(dq)} failures in 5 minutes.",
                        category="failed_login",
                        user=record.user,
                        ip=record.ip,
                    )

            # rule 3: successful login after prior failures
            if record.event.lower() == "login_success":
                if record.user in self.failed_login_window and self.failed_login_window[record.user]:
                    self._respond(
                        f"Suspicious login success after failures for user {record.user}",
                        category="suspicious_success",
                        user=record.user,
                        ip=record.ip,
                    )
                    self.failed_login_window[record.user].clear()

        # rule 4: statistical anomaly detection
        self._anomaly_detection()


    """ detect spikes in log volume (z score threshhold) """
    def _anomaly_detection(self) -> None:
        self._respond("anomaly message", "anomaly")

    """ handles alerts: print. log, and forwarding to splunk """
    def _respond(self, message: str, category: str, user: str = "", ip: str = "") -> None:
        """ perform response actions when detections occur """
        timestamp = datetime.utcnow().isoformat() + "Z"
        alert_entry = {
            "timestamp": timestamp,
            "category": category,
            "message": message,
        }

        # print to console for feedback
        print(f"ALERT [{category}] {message}")

        # append alert to a local log file
        with self.alert_file_path.open("a") as f:
            f.write(json.dumps(alert_entry) + "\n")

        # send alert to splunk
        try:
            send_to_splunk(alert_entry)
        except Exception as e:
            print(f"[!] Splunk forwarding failed: {e}")
            
""" open a log file or read from stdin, yields LogREcord objects """
def read_logs(path: Optional[str]) -> Iterable[LogRecord]:

    source: Iterable[str]
    if path:
        source = open(path, encoding="utf-8")
    else:
        source = sys.stdin
    for line in source:
        record = LogRecord.from_line(line)
        if record:
            yield record

""" parse command-line arguments and starts the SIEM process """
def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Run a mini SIEM/SOAR processor on log data.")
    parser.add_argument("--logfile", type=str, default=None, help="Path to the log file (default: stdin)")
    parser.add_argument("--blocklist", type=str, default=None, help="Comma-separated list of blocked IPs")
    parser.add_argument("--alertfile", type=str, default="alerts.log", help="File to write alerts")
    args = parser.parse_args(argv)
    
    """ split the comma seperate list of blocked ips into a python list """
    blocklist = args.blocklist.split(",") if args.blocklist else []
    
    """ create a minisiem object and start processing log entries """
    siem = MiniSIEM(blocklist=blocklist, alert_file=args.alertfile)
    siem.process_records(read_logs(args.logfile))


""" entry point """
if __name__ == "__main__":
    main()