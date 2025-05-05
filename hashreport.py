import os
import requests
import json
import time
from datetime import datetime
import subprocess

# Replace YOUR_API_KEY with your VirsuTotal API key
API_KEY = "YOUR_API_KEY"
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/files/'
HASH_STORAGE_FILE = "submitted_hashes.txt"
PAUSE_DURATION = 16  # A 16 second delay for each Virustotal submission

# load submitted hash file on program execution and save each hash submitted to VirusTotal
def load_submitted_hashes():
    if os.path.exists(HASH_STORAGE_FILE):
        with open(HASH_STORAGE_FILE, "r") as file:
            return set(file.read().splitlines())
    return set()

def save_submitted_hash(file_hash):
    with open(HASH_STORAGE_FILE, "a") as file:
        file.write(f"{file_hash}\n")

# Format timestamp for 'First Submission Date' and 'Last Analysis Date'
def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S') if timestamp else "N/A"

# Retrieve creation timestamp for each file hash
def get_file_creation_date(file_path):
    try:
        return datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "Unknown"

def print_analysis_report(file_hash, file_path, attributes):
    # This report can be easily edited and tailored, see submit_hash.py for output
    votes = attributes.get('total_votes', {})
    threat_label = attributes.get('popular_threat_classification', {})
    ids_stats = attributes.get('crowdsourced_ids_stats', {})
    print(f"""
---- BEGINNING OF REPORT ----

File Hash: {file_hash}
File Creation Date: {get_file_creation_date(file_path)}
File Name: {attributes.get('meaningful_name', 'N/A')}
First Submission Date: {format_timestamp(attributes.get('first_submission_date'))}
Last Analysis Date: {format_timestamp(attributes.get('last_analysis_date'))}
Reputation: {attributes.get('reputation', 'N/A')}
Total Votes: Harmless - {votes.get('harmless', 0)}, Malicious - {votes.get('malicious', 0)}
Size: {attributes.get('size', 'N/A')} bytes
Suggested Threat Label: {threat_label.get('suggested_threat_label', 'N/A')}
Crowdsourced IDS Rules: High - {ids_stats.get('high', 0)}, Medium - {ids_stats.get('medium', 0)}, Low - {ids_stats.get('low', 0)}
""")

def query_log_files(file_hash, log_folder):
    for log_file in filter(lambda f: os.path.isfile(os.path.join(log_folder, f)), os.listdir(log_folder)):
        log_file_path = os.path.join(log_folder, log_file)
        try:
            with open(log_file_path, "r") as file:
                if file_hash in file.read():
                    print(f"\nFile Hash {file_hash} found in log file: {log_file_path}")
                    result = subprocess.run(["bash", "./parse_log.sh", file_hash, log_file_path], capture_output=True, text=True)
                    if result.returncode == 0:
                        print(result.stdout)
                    else:
                        print(f"Error running bash script: {result.stderr}")
        except Exception as e:
            print(f"Error reading log file {log_file_path}: {e}")

def submit_hash_to_virustotal(file_hash, file_path, log_folder):
    response = requests.get(f"{VIRUSTOTAL_URL}{file_hash}", headers={'x-apikey': API_KEY})
    try:
        response_data = response.json()
    except json.JSONDecodeError:
        print("Error: Response is not valid JSON.")
        return
    if response.status_code == 200:
        attributes = response_data.get('data', {}).get('attributes', {})
        print_analysis_report(file_hash, file_path, attributes)
        # If hash flags a high threat IDS rule then the hash is queried against the cowrie log files
        if attributes.get('crowdsourced_ids_stats', {}).get('high', 0) > 0:
            query_log_files(file_hash, log_folder)
        save_submitted_hash(file_hash)
    else:
        print(f"Error for hash {file_hash}: {response.status_code}")
        print(json.dumps(response_data, indent=2))

def process_files_in_directory(directory_path, log_folder):
    submitted_hashes = load_submitted_hashes()
    for filename in filter(lambda f: os.path.isfile(os.path.join(directory_path, f)), os.listdir(directory_path)):
        if filename in submitted_hashes:
            continue
        submit_hash_to_virustotal(filename, os.path.join(directory_path, filename), log_folder)
        time.sleep(PAUSE_DURATION)

if __name__ == "__main__":
    # This is typically /srv/cowrie/var/lib/cowrie/downloads/
    directory_path = input("Enter path to cowrie downloads folder: ").strip()
    # It is recommended to back up cowrie log files and point to that location
    log_folder = input("Enter the cowrie log folder path: ").strip()
    if os.path.isdir(directory_path) and os.path.isdir(log_folder):
        process_files_in_directory(directory_path, log_folder)
    else:
        print("Invalid directory or log folder path.")
