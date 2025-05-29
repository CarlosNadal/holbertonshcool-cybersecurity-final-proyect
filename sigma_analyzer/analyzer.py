#!/usr/bin/env python3
"""
Sigma Analyzer (File-based)
- Reads logs from a JSON file
- Applies LogQL pattern matching (keyword contains)
- Supports alerting and output storage
"""

import os
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler
import requests

# Configuration
CONFIG = {
    "LOG_DIR": os.getenv("LOG_DIR", "/var/log/sigma"),
    "COMPILED_RULES_DIR": os.getenv("COMPILED_DIR", "./compiled"),
    "INPUT_FILE": os.getenv("INPUT_FILE", "/app/logs/scanner/mail_scanner.json"),
    "USE_FILE_INPUT": os.getenv("USE_FILE_INPUT", "true").lower() == "true",
    "QUERY_WINDOW": int(os.getenv("QUERY_WINDOW_MINUTES", "60")),
    "SLEEP_INTERVAL": int(os.getenv("SLEEP_SECONDS", "3600")),
    "ALERT_WEBHOOK": os.getenv("ALERT_WEBHOOK", ""),
    "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO").upper()
}

# Setup logger
os.makedirs(CONFIG["LOG_DIR"], exist_ok=True)
logging.basicConfig(
    level=CONFIG["LOG_LEVEL"],
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        RotatingFileHandler(
            os.path.join(CONFIG["LOG_DIR"], "analyzer.log"),
            maxBytes=10 * 1024 * 1024,
            backupCount=5
        ),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Output file pattern
OUTPUT_TEMPLATE = "analyzer_output_{timestamp}.json"

# --- Load Rules ---
def load_compiled_rules():
    rules = {}
    try:
        for filename in os.listdir(CONFIG["COMPILED_RULES_DIR"]):
            if filename.endswith(".logql"):
                path = os.path.join(CONFIG["COMPILED_RULES_DIR"], filename)
                with open(path, "r") as f:
                    rules[filename] = f.read().strip()
                logger.debug(f"Loaded rule: {filename}")
    except Exception as e:
        logger.error(f"Rule loading failed: {e}")
    return rules

# --- Read File-based Logs ---
def read_local_logs():
    logs = []
    try:
        with open(CONFIG["INPUT_FILE"], "r") as f:
            for line in f:
                entry = json.loads(line.strip())
                if "timestamp" in entry:
                    logs.append(entry)
        logger.info(f"Loaded {len(logs)} entries from local file")
    except Exception as e:
        logger.error(f"Failed to read local logs: {e}")
    return logs

# --- Rule Execution ---
def process_rule(rule_name, logql, start_time, end_time):
    logger.info(f"Applying rule: {rule_name}")
    matches = []

    logs = read_local_logs()
    keyword = extract_keyword_from_logql(logql)

    for log_entry in logs:
        try:
            ts = datetime.fromtimestamp(log_entry["timestamp"], tz=timezone.utc)
            if start_time <= ts <= end_time:
                if keyword.lower() in str(log_entry.get("yara_hits", "")).lower():
                    matches.append({
                        "rule": rule_name,
                        "timestamp": ts.isoformat(),
                        # Use "subject" instead of "log":
                        "log": log_entry["subject"],  # Or combine fields: f"{log_entry['sender']}: {log_entry['subject']}"
                        "labels": {
                            "source": CONFIG["INPUT_FILE"],
                            # Use yara_hits to determine severity:
                            "severity": "critical" if isinstance(log_entry["yara_hits"], list) else "info"
                        }
                    })
        except Exception as e:
            logger.warning(f"Log parse error: {e}")
    if matches:
        logger.info(f"Found {len(matches)} match(es) for {rule_name}")
    return matches

def extract_keyword_from_logql(logql):
    """Extract keyword from simple LogQL query (e.g., {job="xyz"} |= "something")"""
    if "|=" in logql:
        return logql.split("|=")[1].strip().strip('"').strip("'")
    return logql.strip()

# --- Alerts ---
def trigger_alerts(matches):
    if not CONFIG["ALERT_WEBHOOK"]:
        return
    critical_matches = [m for m in matches if m["labels"].get("severity") == "critical"]
    for match in critical_matches:
        try:
            requests.post(
                CONFIG["ALERT_WEBHOOK"],
                json={"text": f"🚨 Critical threat detected in {match['rule']}: {match['log']}"}
            )
        except Exception as e:
            logger.error(f"Alert failed: {e}")

# --- Write Output ---
def write_output(matches):
    if not matches:
        return
    try:
        filename = OUTPUT_TEMPLATE.format(
            timestamp=datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        )
        path = os.path.join(CONFIG["LOG_DIR"], filename)
        with open(path, "w") as f:
            for match in matches:
                f.write(json.dumps(match) + "\n")
        logger.info(f"Wrote {len(matches)} matches to {filename}")
    except Exception as e:
        logger.error(f"Output write failed: {e}")

# --- Main Loop ---
def main_loop():
    last_run_time = datetime.now(timezone.utc) - timedelta(minutes=CONFIG["QUERY_WINDOW"])
    rules = load_compiled_rules()
    rules_last_reloaded = time.time()

    while True:
        try:
            if time.time() - rules_last_reloaded > 3600:
                logger.info("Reloading rules...")
                rules = load_compiled_rules()
                rules_last_reloaded = time.time()

            start_time = last_run_time
            end_time = datetime.now(timezone.utc)
            logger.info(f"Analyzing logs from {start_time} to {end_time}")

            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = [
                    executor.submit(process_rule, rule_name, logql, start_time, end_time)
                    for rule_name, logql in rules.items()
                ]
                all_matches = []
                for future in futures:
                    all_matches.extend(future.result())

            trigger_alerts(all_matches)
            write_output(all_matches)

            last_run_time = end_time
            logger.info(f"Sleeping for {CONFIG['SLEEP_INTERVAL']} seconds")
            time.sleep(CONFIG["SLEEP_INTERVAL"])

        except KeyboardInterrupt:
            logger.info("Shutdown requested by user")
            break
        except Exception as e:
            logger.error(f"Fatal error: {e}", exc_info=True)
            logger.info("Restarting in 60 seconds...")
            time.sleep(60)

# --- Entry Point ---
if __name__ == "__main__":
    logger.info("🚀 Starting Sigma Analyzer (File Mode)")
    logger.info(f"Configuration: {json.dumps(CONFIG, indent=2)}")
    main_loop()
    logger.info("Sigma Analyzer stopped")
