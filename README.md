# threat-hunting-scenario-tor
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/gonsalvesray/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- TOR Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- Check **`DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events as evidence of TOR files on the workstation.
- Check **`DeviceProcessEvents`** for any signs of installation of the TOR browser.
- Check **`DeviceProcessEvents`** for any indication of TOR browser usage.
- Check **`DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.
- Check **`DeviceFileEvents`** to verify the creation of the file "tor-shopping-list.txt".

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` table for TOR file evidence

Searched the **DeviceFileEvents** table for ANY file that had the string `tor` in its name and discovered that Account Name `gonsalvr` downloaded and ran a TOR installer file `tor-browser-windows-x86_64-portable-14.0.7.exe` on their Windows workstation. This installation resulted in many TOR related files being copied to their C: drive. They also created a file named `tor-shopping-list.txt` on their desktop. These events began at: `2025-03-16T21:09:23.600874Z` via the file download to: `C:\Users\GONSALVR\Downloads` using the browser Microsoft Edge `msedge.exe`. This analysis is confirmed by the following KQL query:

**Query used to locate events:**

```kql
// TOR browser was downloaded
let VMName = "gonsalvr-mde";
DeviceProcessEvents
| where DeviceName == VMName 
and TimeGenerated between (todatetime('2025-03-16T21:16:05.0220793Z') .. todatetime('2025-03-16T21:16:05.0740793Z'))
and ProcessCommandLine has_any("tor.exe","firefox.exe", "tor-browser.exe")
| project TimeGenerated, DeviceName, AccountName, ActionType, ProcessCommandLine, SHA256
```

![image](https://github.com/user-attachments/assets/c110bc85-1eb5-4c3e-b288-9d63ca70e87c)

---

### 2. Searched the `DeviceProcessEvents` table for installation evidence

The next step was to look for evidence of the user installing the TOR Browser on the desktop. The following KQL query searched the **ProcessCommandLine** field in the  **DeviceProcessEvents** table looking for the string `tor-browser-windows-x86_64-portable-14.0.7.exe  /S`

The **/S** option indicates that this command was run using the silent install option at `2025-03-16T21:13:16.2610691Z`


**Query used to locate event:**

```kql

// TOR Browser being silently installed
let VMName = "gonsalvr-mde";
DeviceProcessEvents
| where DeviceName == VMName 
  and  ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.7.exe  /S"
| project TimeGenerated, DeviceName, ActionType, FileName, ProcessCommandLine
```

![image](https://github.com/user-attachments/assets/372541ea-a3cc-48b2-a16a-5f9074aef2b9)

---

### 3. Searched the `DeviceProcessEvents` table for TOR browser execution

Now that I know the user ran the command to install the TOR Browser I checked to see if they actually launched and used the TOR browser by quering the field **FileName** in the **DeviceProcessEvents** table for the following strings `("tor.exe", "firefox.exe", "tor-browser.exe")`  There is evidence that is occurred at `2025-03-16T21:16:05.0740793Z`

**Query used to locate events:**

```kql
// TOR Browser or service was launched
let VMName = "gonsalvr-mde";
DeviceProcessEvents
| where DeviceName == VMName 
and TimeGenerated between (todatetime('2025-03-16T21:16:05.0220793Z') .. todatetime('2025-03-16T21:16:05.0740793Z'))
and ProcessCommandLine has_any("tor.exe","firefox.exe", "tor-browser.exe")
| project TimeGenerated, DeviceName, AccountName, ActionType, ProcessCommandLine, SHA256
```
![image](https://github.com/user-attachments/assets/bd74a293-dda7-4a83-9a0a-c3f0fc7ae4ec)

---

### 4. Searched the `DeviceNetworkEvents` table for TOR Network Connections

Finally I was able to show that the TOR Browser was used to actually establish 2 connections to remote sites at `2025-03-16T21:16:23.480746Z` to Remote Site  `5.161.60.61` and  at `2025-03-16T21:16:31.1220241Z` to Remote site `88.151.194.12` by querying the field **RemotePort** in the **DeviceNetworkEvents** table looking for typical ports used the TOR browser: `9001, 9030, 9040, 9050, 9051, 9150`. The connections were made by user `gonsalvr` with the process `tor.exe` which was executed from the following path: `c:\users\gonsalvr\desktop\tor browser\browser\torbrowser\tor`
We can show this by running a KQL query:

**Query used to locate events:**

```kql
// TOR Browser or service is being used and is actively creating network connections
let VMName = "gonsalvr-mde";
DeviceNetworkEvents
| where DeviceName  == VMName
  and InitiatingProcessFileName in ("tor.exe", "firefox.exe")
  and RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
  and ActionType == "ConnectionSuccess"
| project TimeGenerated, DeviceName, Account_Name = InitiatingProcessAccountName, File_Name = InitiatingProcessFileName, 
          Init_Process_Path = InitiatingProcessFolderPath, RemoteIP, RemotePort, RemoteUrl, Connection = ActionType
| order by TimeGenerated desc
```
![image](https://github.com/user-attachments/assets/c0455a11-8ae3-4ab2-bb55-3886da98cc9c)

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
