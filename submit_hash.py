import requests
import sys
import json
from datetime import datetime

# Store your VirusTotal API key in API_KEY variable
API_KEY = "YOUR_API_KEY"

"""Convert a Unix timestamp to a human-readable date format."""
def format_timestamp(timestamp):
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S') if timestamp else "N/A"

"""Print the VirusTotal report in a structured format."""
def print_report(file_hash, attributes):
    print("\n--- VirusTotal Report ---")
    print(f"\n\nFile Hash: {file_hash}")
    print(f"File Name: {attributes.get('meaningful_name', 'N/A')}")
    print(f"First Submission Date: {format_timestamp(attributes.get('first_submission_date'))}")
    print(f"Last Analysis Date: {format_timestamp(attributes.get('last_analysis_date'))}")
    print(f"Reputation: {attributes.get('reputation', 'N/A')}")
    votes = attributes.get('total_votes', {})
    print(f"Total Votes: Harmless - {votes.get('harmless', 0)}, Malicious - {votes.get('malicious', 0)}")
    print(f"Size: {attributes.get('size', 'N/A')} bytes")
    threat_label = attributes.get('popular_threat_classification', {})
    print(f"Suggested Threat Label: {threat_label.get('suggested_threat_label')}")
    ids_stats = attributes.get('crowdsourced_ids_stats')
    print(f"\nCrowdsourced IDS rules: High - {ids_stats.get('high', 0)}, Medium - {ids_stats.get('medium', 0)}, Low - {ids_stats.get('low', 0)}")

def submit_hash_to_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            response_data = response.json()
            attributes = response_data.get("data", {}).get("attributes", {})
            print_report(file_hash, attributes)
        elif response.status_code == 404:
            print("Hash not found in VirusTotal database.")
        else:
            print(f"Failed to retrieve hash information. HTTP Status Code: {response.status_code}")
            print("Response:", response.text)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <file_hash>")
        sys.exit(1)

    submit_hash_to_virustotal(sys.argv[1])
