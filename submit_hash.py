import requests
import sys
import json

API_KEY = "YOUR_API_KEY"

def submit_hash_vt(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": API_KEY
    }

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            print("Hash successfully submitted to VirusTotal.")
            print("Response:")
            print(json.dumps(response.json(), indent=4))
        elif response.status_code == 404:
            print("Hash not found in VirusTotal database.")
        else:
            print(f"Failed to retrieve hash information. HTTP Status Code: {response.status_code}")
            print("Response:")
            print(response.txt)

    except Exception as e:
        print(f"An error has occured: {e}")

if __name__ == "__main__":
    if len(sys.argv) !=2:
        print("Usage: python hashvtotal.py <file_hash>")
        sys.exit(1)

    file_hash = sys.argv[1]
    submit_hash_vt(file_hash)
