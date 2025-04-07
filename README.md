# 🚨 Incident Response: PowerShell Suspicious Web Request Detection

> This project simulates a post-exploitation scenario where PowerShell is used to download and execute a suspicious script via `Invoke-WebRequest`. The goal is to detect, alert, and investigate the activity using Microsoft Defender for Endpoint (MDE) and Microsoft Sentinel.

![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1059%2C%20T1105-orange)
![Tools](https://img.shields.io/badge/Tools-MDE%20%7C%20Sentinel%20%7C%20KQL%20%7C%20PowerShell-blue)
![ChatGPT Image Apr 7, 2025 at 04_11_33 PM](https://github.com/user-attachments/assets/69fd7e8e-315f-4503-87ee-3819814934c6)

---

## 🛡️ **Create Alert Rule (PowerShell Suspicious Web Request)**

### 🔍 **Explanation**
Sometimes, malicious actors gain access to systems and attempt to download payloads or tools directly from the internet. This is often done using legitimate tools like PowerShell to blend in with normal activity. By using commands like `Invoke-WebRequest`, attackers can:

- 📥 Download files or scripts from external servers
- 🚀 Execute them immediately, bypassing traditional defenses
- 📡 Establish communication with Command-and-Control (C2) servers

Detecting such behavior is critical to identifying and disrupting an ongoing attack! 🕵️‍♀️

### **Detection Pipeline Overview**
1. 🖥️ Processes are logged via **Microsoft Defender for Endpoint** under the `DeviceProcessEvents` table.
2. 📊 Logs are forwarded to **Log Analytics Workspace** and integrated into **Microsoft Sentinel (SIEM)**.
3. 🛑 An alert rule is created in **Sentinel** to trigger when PowerShell downloads remote files.

---

### 🔧 **Steps to Create the Alert Rule**

#### 1️⃣ **Query Logs in Microsoft Defender**
1. Open **Microsoft EDR**.
2. Go to the KQL section and enter:
```kql
DeviceFileEvents
| top 20 by Timestamp desc
```
```kql
DeviceNetworkEvents
| top 20 by Timestamp desc
```
```kql
DeviceProcessEvents
| top 20 by Timestamp desc
```
3. Locate suspicious activity, e.g., `powershell.exe` executing `Invoke-WebRequest`.
4. Refine query for target device:
   ```kql
   let TargetDevice = "sa-mde-test-2";
   DeviceProcessEvents
   | where DeviceName == TargetDevice
   | where FileName == "powershell.exe"
   | where ProcessCommandLine contains "Invoke-WebRequest"
   ```
<img width="1279" alt="log1" src="https://github.com/user-attachments/assets/d1834298-780f-40d4-ab24-02c636b11a9c" />

5. Verify payload detection. ✅
```kql
let TargetHostname = "sa-mde-test-2";
let ScriptNames = dynamic(["eicar.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
| summarize Count = count() by AccountName, DeviceName, FileName, ProcessCommandLine
```
<img width="1241" alt="log4" src="https://github.com/user-attachments/assets/ca1b58e2-ae63-4dad-b562-ad75a33a6920" />


#### 2️⃣ **Create Alert Rule in Microsoft Sentinel**
1. Open **Sentinel** and navigate to:
   `Analytics → Scheduled Query Rule → Create Alert Rule`
2. Fill in the following details:
   - **Rule Name**: PowerShell Suspicious Web Request 🚩
   - **Description**: Detects PowerShell downloading remote files 📥.
   - **KQL Query**:
     ```kql
     let TargetDevice = "windows-target-1";
     DeviceProcessEvents
     | where DeviceName == TargetDevice
     | where FileName == "powershell.exe"
     | where ProcessCommandLine contains "Invoke-WebRequest"
     ```
   - **Run Frequency**: Every 4 hours 🕒
   - **Lookup Period**: Last 24 hours 📅
   - **Incident Behavior**: Automatically create incidents and group alerts into a single incident per 24 hours.
3. Configure **Entity Mappings**:
   - **Account**: `AccountName`
   - **Host**: `DeviceName`
   - **Process**: `ProcessCommandLine`
4. Enable **Mitre ATT&CK Framework Categories** (Use ChatGPT to assist! 🤖).
5. Save and activate the rule. 🎉

<img width="1440" alt="log2" src="https://github.com/user-attachments/assets/87ebec1c-d18d-4e86-bfb1-c97d90537ef9" />

---

## 🛠️ **Work the Incident**
Follow the **NIST 800-161: Incident Response Lifecycle**:

### 1️⃣ **Preparation** 📂

Before the incident, the security team ensured the environment was fully instrumented with the necessary detection and response capabilities:

- Microsoft Defender for Endpoint (MDE) was deployed on all endpoints, including the test VM sa-mde-test-2, enabling behavioral telemetry and incident correlation.
- Microsoft Sentinel was integrated with MDE via a Log Analytics Workspace, ensuring DeviceProcessEvents logs were available for custom KQL detection.
- An analytics rule using KQL was pre-configured to detect PowerShell usage of Invoke-WebRequest, a known tactic for downloading payloads.

- SOC personnel were trained on the use of:
  - Sentinel's incident management interface
  - Entity mapping
  - nvestigation graphing tools in MDE and Sentinel

### 2️⃣ **Detection and Analysis** 🕵️‍♀️
1. **Validate Incident**:
   - Assign it to yourself and set the status to **Active** ✅.

<img width="399" alt="log3" src="https://github.com/user-attachments/assets/b0bef048-55fa-44e9-b09a-c519868f5334" />

2. **Investigate**:
   - Review logs and entity mappings 🗒️.
   - Check PowerShell commands:
     ```plaintext
     powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri <URL> -OutFile <Path>
     ```
   - Identify downloaded script:
   
   <img width="1440" alt="log5" src="https://github.com/user-attachments/assets/1c891f02-835d-49f3-bf0f-355b45b5b2a3" />

3. Gather evidence:
   - Scripts downloaded and executed 🧪.
   - User admitted to downloading free software during the events.

### 3️⃣ **Containment, Eradication, and Recovery** 🛡️
1. Isolate affected systems:
   - Use **Defender for Endpoint** to isolate the machine 🔒.
   - Run anti-malware scans.
2. Analyze downloaded scripts:

3. Remove threats and restore systems:
   - Confirm scripts executed.
   - Clean up affected files and verify machine integrity 🧹.

### 4️⃣ **Post-Incident Activities** 📝
1. Document findings and lessons learned 🖊️.
   - Script executed: `eicar.ps1`
   - Account involved: `cyberSentinel_92`
2. Update policies:
   - Started the implementation of a policy that restricts PowerShell for non-essential user accounts 🚫
   - Implemented a cybersecurity awareness training for employees by KnowBe4 📚
3. Finalize reporting and close the case:
   - Marked incident as **True Positive** ✅

---

## 🎯 **Incident Summary**
| **Metric**                     | **Value**                        |
|---------------------------------|-----------------------------------|
| **Affected Device**            | `sa-mde-test-2`               |
| **Suspicious Commands**        | 1                                |
| **Script Downloaded**         | `eicar.ps1`  |
| **Incident Status**            | Resolved                         |

---
