# Cowrie Hash Report
The purpose of this script is to automate the process of submitting file hashes found in the cowrie downloads file of a DShield honeypot and generating a tailored report as output. This offers a more streamlined approach to quickly assess a file hash of malware downloaded to the honeypot from the command line using a VirusTotal API key.
 
![image](https://github.com/user-attachments/assets/c8914cbb-1b5e-42dd-a12e-b9f8478804ce)


**Prerequisites**

This script requires an API key from VirusTotal, this can be obtained by signing up for a free VirusTotal account.
Currently, ```parse_log.sh``` is required to parse the cowrie log files once a file of interest is located.

**Using hashreport.py**

```python hashreport.py```

Once the script has been executed it will request the absolute path to the file containing file hashes as the filename. This is how cowrie stores malicious downloads to the honeypot and it’s recommended to point this to /srv/cowrie/var/lib/cowrie/downloads/ in a DShield honeypot.

To hard code the cowrie downloads folder location into the script you will need to replace:

```directory_path = input("Enter path to cowrie downloads folder: ").strip()```

with

```directory_path = /srv/cowrie/var/lib/cowrie/downloads/```

The script will then request the absolute path to the cowrie log files. 

![image](https://github.com/user-attachments/assets/584f7c7f-c0ab-4af3-977d-615d4a8ccd00)

For this script the files of interest are file hashes that are identified by VirusTotal as triggering an open-source high threat IDS rule.  Once a file of interest has been identified the script will parse through the cowrie logs files and print to screen the IP address, timestamp, session ID, URL, and cowrie log file where the download was located.

![image](https://github.com/user-attachments/assets/afac14b2-7406-4a69-84be-3a88da6c69fb)

**Note** I had a difficult time using Python to print the details that I wanted from the cowrie log parsing so ```parse_log.sh``` was created and will need to be downloaded along with ```hashreport.py```. I hope to return to this later and correct this portion of the script.

**Data Enrichment**

For every file hash that is submitted to VirusTotal, the report prints to screen the following data:

- File Hash              -->	 File hash submitted to VirusTotal
- File Creation Date	    -->  The date the file was downloaded to the honeypot
- File Name	            -->  File name of the downloaded file
- First Submission Date  -->	 First date the file hash was submitted to VirusTotal
- Last Analysis Date	    -->  Last date the file hash was submitted to VirusTotal
- Reputation	            -->  Community Score from VirusTotal users
- Total Votes	          -->  Total number of voters who ranked the file hash
- Size	                  -->  Size of the malicious download
- Suggested Threat Label -->  Suggested threat class of the download
- Crowdsourced IDS Rules	-->  IDS rule violations ranked from High-Medium-Low

The script iterates through each file hash and submits to VirusTotal in 16 second increments to comply with VirusTotal’s free account API policy, 4 downloads per minute.  Once a file hash is reported as violating a high threat IDS rule the script will then parse through all cowrie logs located in the log folder path to find all reported downloads of the file.  The following data is printed to the screen once the file hash is identified in the cowrie logs:

- File Hash              -->  File hash submitted to VirusTotal
- Log File Location	    -->  The log file that the file hash download was located in
- IP Address	            -->  IP address associated with the malicious download
- Timestamp	            -->  Timestamp the download occurred
- Session ID	            -->  Session ID where the download occurred
- URL	                  -->  URL of the download

The data enrichment provides a quick overview of the file hash submitted allowing the user to quickly assess the file downloaded.  Further details on high threats will offer the user the exact location of the file in the logs for further analysis of the event that led to the download.


**Recommendations**

This tool can be used to report to an open-source threat intelligence community, such as VirusTotal, so that these events are tracked and reported in real time.  Also, automating the script to produce a text file of these reports for analysis as part of a workflow, i.e. log in and review the report of the most recent downloads.

**Using submit_hash_vt.py**

```python submit_hash_vt.py <FILE HASH>```

This was the first script that was expanded on but still has some utility.  It can be used to print the entire VirusTotal report to screen in a readable format.  This can be used to identify fields in the VirusTotal report that can be used to further expand on the script.
