---

### **🔍 VirusTotal File Analyzer**  
A simple Python script to **hash, check, and upload files** to [VirusTotal](https://www.virustotal.com) for malware analysis.  
It first checks if the file is already in VirusTotal’s database and uploads it only if needed.  

---

## **🚀 Features**  
✅ **Computes SHA-256 hash** of a file.  
✅ **Checks VirusTotal database** for existing scan results.  
✅ **Uploads file if not found** and waits for analysis.  
✅ **Automatically retrieves scan results** after upload.  
✅ **Handles API request failures with retries.**  
✅ **Formatted output with only relevant scan details.**  

---

## **🛠️ Setup & Installation**  

### **1️⃣ Clone the Repository**  
```bash
git clone https://github.com/yourusername/virustotal-automation.git
cd virustotal-automation
```

### **2️⃣ Create a Virtual Environment (Optional but Recommended)**
```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

### **3️⃣ Install Dependencies**  
```bash
pip install -r requirements.txt
```

### **4️⃣ Get a VirusTotal API Key**  
1. Go to [VirusTotal API](https://www.virustotal.com/gui/join-us).  
2. Sign up for a **free API key**.  
3. Store the key securely using a `.env` file.

---

## **🔑 API Key Setup**  

### **Using `.env` File (Recommended)**
1. Create a `.env` file in the project directory.  
2. Add your API key like this:  
   ```
   VT_API_KEY=your_api_key_here
   ```
3. The script will load it automatically.

### **Using Environment Variables (Alternative)**
Set the API key manually:  

**Linux/macOS:**  
```bash
export VT_API_KEY="your_api_key_here"
```
**Windows CMD:**  
```cmd
set VT_API_KEY=your_api_key_here
```
**Windows PowerShell:**  
```powershell
$env:VT_API_KEY="your_api_key_here"
```

---

## **🖥️ Usage**  
Run the script and provide the file path when prompted:  

```bash
python virustotal_v2.py
```

Example Run:  
```bash
Enter the path to the file to analyze: suspicious.exe
```
**Output:**  
```
🔍 File Hash: d2b7...9f3
✅ File already exists in VirusTotal database.
📌 File Details:
🔹 File Name(s): suspicious.exe, test.exe
🔹 File Type: Executable
🔹 File Size: 2.3 MB
🛡️ VirusTotal Scan Results:
🚨 Kaspersky: Trojan.Win32.Generic
🚨 BitDefender: Malicious
🚨 Avast: Win32:Malware-gen
```

If the file is **not found**, it gets **uploaded and analyzed** automatically.  

---

## **📄 License**  
This project is licensed under the **MIT License**.  

---

## **🤝 Contributing**  
Feel free to **submit issues or pull requests** if you find bugs or want to improve the project!  

---
