# Cowrie Hash Report
The purpose of this script is to automate the process of submitting file hashes found in the [cowrie](https://github.com/cowrie/cowrie) downloads file of a [DShield](https://github.com/DShield-ISC/dshield) honeypot and generating a tailored report as output.  This offers a more streamlined approach to quickly assess a file hash of malware uploaded to the honeypot from the command line using a VirusTotal API key.

![Screenshot 2025-04-27 195509](https://github.com/user-attachments/assets/5abb623c-2f2a-4531-bac5-4a273bdc960c)

**Prerequisites**

These scripts requires an API key from VirusTotal, this can be obtained be signing up for a [free VirusTotal](https://www.virustotal.com/gui/join-us) account.

**Using hashreport.py**

```
python hashreport.py
```

Once the script has been executed it will request the absolute path to the file containing file hashes as the filename.  This is how cowrie stores malicious uploads to the honeypot and it recommended to point this to /srv/cowrie/var/lib/cowrie/downloads/ in a DShield honeypot.  

To hard code this into the script you will need to replace: 
```
directory_path = input("Enter path to cowrie downloads folder: ").strip()
``` 
with 
```
directory_path = /srv/cowrie/var/lib/cowrie/downloads/
```

The script will then request the absolute path to the cowrie log files to be parsed if a file of interest is identified.  For this script the files of interest are file hashes that are identified by VirusTotal as triggering an open-source high threat IDS rule.  Once a file of interest has been identified the script will parse through the cowrie logs files and print to screen the IP address, timestamp, session ID, URL, and cowrie log file where the download was located.

![Screenshot 2025-04-27 195602](https://github.com/user-attachments/assets/a066ba50-00df-424a-83e5-b48a105b5685)

**Note**  I was unable to figure out how to print the details that I wanted from the cowrie log parsing in Python so ```parse_log.sh``` was created and will need to be downloaded along with ```hashreport.py```.  I hope to return to this later and correct this portion of the script.

**Using submit_hash_vt.py**

```
python submit_hash_vt.py <FILE HASH>
```


This was the first script that was expanded on but still has some utility.  It can be used to print the entire VirusTotal report to the screen in readable format.  This can be used to tailor the hash report to something more relevant to you.
