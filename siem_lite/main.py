import re
import json # For JSON config and rules
import argparse # For command-line argument parsing
import csv # For CSV log parsing
import Evtx.Evtx as evtx # For Windows Event Log parsing
from datetime import datetime, timedelta, timezone

#--------------------------- PARSER FUNCTIONS ---------------------------#

# SSH LOG PARSER
def parse_ssh_log(log_file_path):
    parsed_logs = []
    log_pattern = re.compile(r"(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([\w-]+)\s+([\w\d\[\]]+):\s+(.*)")
    current_year = datetime.now().year
    with open(log_file_path, 'r') as f:
        for line in f:
            match = log_pattern.match(line)
            if match:
                naive_timestamp = datetime.strptime(f"{current_year} {match.group(1)}", "%Y %b %d %H:%M:%S")
                aware_timestamp = naive_timestamp.replace(tzinfo=timezone.utc)
                parsed_logs.append({
                    'timestamp': aware_timestamp, 'hostname': match.group(2),
                    'log_source': 'SSH', 'message': match.group(4).strip()
                })
    return parsed_logs

# APACHE LOG PARSER
def parse_apache_log(log_file_path):
    parsed_logs = []
    log_pattern = re.compile(r'([\d\.]+) - - \[(.*?)\] \"(.*?)\" (\d{3}) (\d+)')
    with open(log_file_path, 'r') as f:
        for line in f:
            match = log_pattern.match(line)
            if match:
                timestamp_obj = datetime.strptime(match.group(2), "%d/%b/%Y:%H:%M:%S %z")
                request_parts = match.group(3).split()
                parsed_logs.append({
                    'timestamp': timestamp_obj, 'client_ip': match.group(1), 'log_source': 'Apache',
                    'http_method': request_parts[0] if len(request_parts) > 0 else '',
                    'uri': request_parts[1] if len(request_parts) > 1 else '',
                    'status_code': int(match.group(4)), 'response_size': int(match.group(5))
                })
    return parsed_logs

# CSV EXPORT FUNCTION
def parse_csv_log(log_file_path, timestamp_column):
    parsed_logs = []
    with open(log_file_path, 'r', newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # This assumes an ISO format timestamp for simplicity
            timestamp_obj = datetime.fromisoformat(row[timestamp_column])

            # The rest of the row becomes the event data
            event = {
                'timestamp': timestamp_obj,
                'log_source': 'CSV',
            }
            event.update(row) # Add all other CSV columns to the event
            parsed_logs.append(event)
    return parsed_logs

# WINDOWS EVENT LOG PARSER
def parse_evtx_log(log_file_path):
    parsed_logs = []
    with evtx.Evtx(log_file_path) as log:
        for record in log.records():
            # The timestamp is available directly
            timestamp_obj = record.timestamp()
            # The rest of the data is in complex XML format
            event_data_xml = record.xml()
            # to get things like Event ID, Provider, user, etc.
            parsed_logs.append({
                'timestamp': timestamp_obj,
                'log_source': 'EVTX',
                'xml_data': event_data_xml # Store the raw XML for now
            })
    return parsed_logs

#--------------------------- RULE ENGINE ---------------------------#
def run_rule_engine(events, rules_file):
    with open(rules_file, 'r') as f: rules = json.load(f)['rules']
    alerts, failed_ssh_logins = [], {}
    for event in events:
        for rule in rules:
            if rule['type'] == 'single_event' and event['log_source'] == rule['log_source']:
                field = rule['conditions']['field']
                if field in event and rule['conditions']['contains'] in str(event[field]):
                    alerts.append({
                        "alert_name": rule['rule_name'], "timestamp": event['timestamp'].isoformat(),
                        "details": f"Detected suspicious activity: {rule['description']}", "triggering_event": event
                    })
            elif rule['type'] == 'sequence' and event['log_source'] == rule['log_source']:
                if rule['rule_name'] == "SSH Brute-Force Detected" and "Failed password" in event['message']:
                    ip_match = re.search(r'from ([\d\.]+)', event['message'])
                    if ip_match:
                        ip = ip_match.group(1)
                        if ip not in failed_ssh_logins: failed_ssh_logins[ip] = []
                        failed_ssh_logins[ip].append(event['timestamp'])
                        time_window = timedelta(minutes=rule['conditions']['time_window_minutes'])
                        recent_attempts = [t for t in failed_ssh_logins[ip] if event['timestamp'] - t <= time_window]
                        failed_ssh_logins[ip] = recent_attempts
                        if len(recent_attempts) >= rule['conditions']['threshold']:
                            alerts.append({
                                "alert_name": rule['rule_name'], "timestamp": event['timestamp'].isoformat(),
                                "details": f"Detected {len(recent_attempts)} failed logins from IP {ip}.", "source_ip": ip
                            })
                            failed_ssh_logins[ip] = []
    return alerts

# MAIN EXECUTION
def main():
    parser = argparse.ArgumentParser(description="SIEM-Lite: A simple log analysis and alerting engine.")
    parser.add_argument('--config', default='config.json', help="Path to the configuration file (default: config.json)")
    parser.add_argument('--rules', default='rules.json', help="Path to the rules file (default: rules.json)")
    args = parser.parse_args()
    print(f"[*] Loading configuration from: {args.config}")
    print(f"[*] Loading rules from: {args.rules}")
    try:
        with open(args.config, 'r') as f: config = json.load(f)
    except FileNotFoundError:
        print(f"Error: Configuration file '{args.config}' not found."); return
    all_events = []
    for source in config['log_sources']:
        file_path, log_type = source['file_path'], source['log_type']
        print(f"[*] Processing {file_path} (type: {log_type})...")
        try:
            if log_type == 'ssh': all_events.extend(parse_ssh_log(file_path)) # SSH log
            elif log_type == 'apache': all_events.extend(parse_apache_log(file_path)) # Apache log
            elif log_type == 'csv': all_events.extend(parse_csv_log(file_path, source['timestamp_column'])) # CSV log with specified timestamp column
            elif log_type == 'evtx': all_events.extend(parse_evtx_log(file_path)) # Windows Event Log
        except FileNotFoundError:
            print(f"Warning: Log file '{file_path}' not found. Skipping.")

    all_events.sort(key=lambda x: x['timestamp'])
    alerts = run_rule_engine(all_events, args.rules)
    for event in all_events: event['timestamp'] = event['timestamp'].isoformat()
    print("\n--- MASTER EVENT TIMELINE ---")
    print(json.dumps(all_events, indent=2))
    print("\n--- 🚨 TRIGGERED ALERTS 🚨 ---")
    if not alerts: print("No alerts triggered.")
    else:
        for alert in alerts:
            if 'triggering_event' in alert and isinstance(alert['triggering_event'], dict) and 'timestamp' in alert['triggering_event']:
                 # This check ensures timestamp is a string before trying to modify it
                 if not isinstance(alert['triggering_event']['timestamp'], str):
                    alert['triggering_event']['timestamp'] = alert['triggering_event']['timestamp'].isoformat()
        print(json.dumps(alerts, indent=2))

if __name__ == "__main__":
    main()