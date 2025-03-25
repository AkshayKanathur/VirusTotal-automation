import hashlib
import requests
import os
import time
from dotenv import load_dotenv

# Load API key securely from .env file
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")

if not API_KEY:
    print("❌ Error: API key not found. Set VT_API_KEY in your environment or .env file.")
    exit(1)

def hash_file(file_path):
    """Generate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

def request_with_retry(url, headers, method="GET", files=None, max_retries=3):
    """Handles request retries in case of temporary errors."""
    for attempt in range(max_retries):
        if method == "GET":
            response = requests.get(url, headers=headers)
        else:
            response = requests.post(url, headers=headers, files=files)

        if response.status_code == 200:
            return response.json()
        
        print(f"⚠️ Request failed (Attempt {attempt+1}/{max_retries}), retrying in 2s...")
        time.sleep(2)
    
    print("❌ Error: Unable to connect after multiple attempts.")
    return None

def check_file_hash(file_hash):
    """Check if file hash exists in VirusTotal database."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}
    return request_with_retry(url, headers)

def upload_file(file_path):
    """Upload file to VirusTotal if hash is not found."""
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": API_KEY}
    files = {"file": (file_path, open(file_path, "rb"))}
    
    return request_with_retry(url, headers, method="POST", files=files)

def get_analysis_results(analysis_id):
    """Fetch the scan results of an uploaded file."""
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": API_KEY}
    
    print("\n⏳ Waiting for scan results...")
    time.sleep(5)  # Wait a few seconds before fetching results

    return request_with_retry(url, headers)

def format_results(result):
    """Format and display results in a clean way."""
    attributes = result["data"]["attributes"]
    
    print("\n📌 **File Details:**")
    print(f"🔹 File Name(s): {', '.join(attributes.get('names', ['Unknown']))}")
    print(f"🔹 File Type: {attributes.get('type_description', 'Unknown')}")
    print(f"🔹 File Size: {attributes.get('size', 0)} bytes")
    
    print("\n🛡️ **VirusTotal Scan Results:**")
    detections = attributes.get("last_analysis_results", {})
    
    detected_count = 0
    for engine, details in detections.items():
        if details["category"] == "malicious":
            print(f"🚨 {engine}: {details['result']}")
            detected_count += 1
    
    if detected_count == 0:
        print("✅ No malware detected by any engine.")

# Main Execution
file_path = input("Enter the path to the file to analyze: ").strip()
file_hash = hash_file(file_path)
print(f"\n🔍 File Hash: {file_hash}")

result = check_file_hash(file_hash)

if result:
    print("\n✅ File already exists in VirusTotal database.")
    format_results(result)
else:
    print("\n❌ File not found in VirusTotal. Uploading now...")
    upload_result = upload_file(file_path)

    if upload_result:
        analysis_id = upload_result["data"]["id"]
        scan_result = get_analysis_results(analysis_id)
        
        if scan_result:
            print("\n✅ Scan Completed!")
            format_results(scan_result)
        else:
            print("❌ Error fetching scan results.")
    else:
        print("❌ Upload failed.")
