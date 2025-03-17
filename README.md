# threat-hunting-scenario-tor
<img width="400" src="https://github.com/user-attachments/assets/3905f037-bd04-464f-acb1-873070453a65" alt="Tor Logo with the onion and a crosshair on it"/>

[//]: # (This may be the most platform independent comment)

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/gonsalvesray/threat-hunting-scenario-tor-event-creation.md)

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

Searched the **DeviceFileEvents** table for ANY file that had the string `tor` in its name and discovered that User `gonsalvr` downloaded and ran a TOR installer file `tor-browser-windows-x86_64-portable-14.0.7.exe` on their Windows workstation. This installation resulted in many TOR related files being copied to their C: drive. They also created a file named `tor-shopping-list.txt` on their desktop. These events began at: `2025-03-16T21:09:23.600874Z` via the file download to: `C:\Users\GONSALVR\Downloads` using the browser Microsoft Edge `msedge.exe`. This analysis is confirmed by the following KQL query:

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

![image](https://github.com/User-attachments/assets/c110bc85-1eb5-4c3e-b288-9d63ca70e87c)

---

### 2. Searched the `DeviceProcessEvents` table for installation evidence

The next step was to look for evidence of the User installing the TOR Browser on the desktop. The following KQL query searched the **ProcessCommandLine** field in the  **DeviceProcessEvents** table looking for the string `tor-browser-windows-x86_64-portable-14.0.7.exe  /S`

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

![image](https://github.com/User-attachments/assets/372541ea-a3cc-48b2-a16a-5f9074aef2b9)

---

### 3. Searched the `DeviceProcessEvents` table for TOR browser execution

Now that I know the User ran the command to install the TOR Browser I checked to see if they actually launched and used the TOR browser by quering the field **FileName** in the **DeviceProcessEvents** table for the following strings `("tor.exe", "firefox.exe", "tor-browser.exe")`  There is evidence that is occurred at `2025-03-16T21:16:05.0740793Z`

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
![image](https://github.com/User-attachments/assets/bd74a293-dda7-4a83-9a0a-c3f0fc7ae4ec)

---

### 4. Searched the `DeviceNetworkEvents` table for TOR network connections

Finally I was able to show that the TOR Browser was used to actually establish **2** connections:


at `2025-03-16T21:16:23.480746Z` to Remote Site  `5.161.60.61` 

and

at `2025-03-16T21:16:31.1220241Z` to Remote site `88.151.194.12` 


by querying the field **RemotePort** in the **DeviceNetworkEvents** table looking for typical ports used by the TOR browser: `9001, 9030, 9040, 9050, 9051, 9150`. The connections were made by User `gonsalvr` with the process `tor.exe` which was executed from the following path: `c:\Users\gonsalvr\desktop\tor browser\browser\torbrowser\tor`

 This can be evidenced by running a KQL query:

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
![image](https://github.com/User-attachments/assets/c0455a11-8ae3-4ab2-bb55-3886da98cc9c)

---

### 5. Searched the `DeviceFileEvents` table for tor-shopping-list.txt file

I fournd that a file  was created by User `gonsalvr` on the workstation destop in the following path: `C:\Users\GONSALVR\Desktop\tor-shopping-list.txt` at timestamp:`2025-03-16T21:22:26.1592928Z` This can be seen by running the following KQL query and searching the field `FileName` the the `DeviceFileEvents` table for the string “tor-shopping-list.txt”

**Query used to locate events:**

```kql
// User shopping list was created and, changed, or deleted
let VMName = "gonsalvr-mde";
DeviceFileEvents
| where DeviceName == VMName and FileName contains "shopping-list.txt"
| project TimeGenerated, Account_Name = InitiatingProcessAccountName, ActionType, FileName, FolderPath, 
 Command_Line = InitiatingProcessCommandLine
```
![image](https://github.com/User-attachments/assets/109d8077-2c78-496f-880b-4c9eb941fe29)

---


## Chronological Event Timeline 

### 1. File Download - TOR installer

- **Timestamp:** `2025-03-16T21:09:23.600874Z`
- **Event:** The User `gonsalvr` downloaded a file named `tor-browser-windows-x86_64-portable-14.0.7.exe` to the Downloads folder.
- **Action:** File download detected.
- **Folder Path:** `C:\Users\GONSALVR\Downloads\tor-browser-windows-x86_64-portable-14.0.7.exe`

### 2. Process Execution - TOR browser installation

- **Timestamp:** `2025-03-16T21:13:16.2610691Z`
- **Event:** The User `gonsalvr' executed the file `tor-browser-windows-x86_64-portable-14.0.7.exe` in silent mode, initiating a background installation of the TOR browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.7.exe /S`
- **File Path:** `C:\Users\GONSALVR\Downloads\tor-browser-windows-x86_64-portable-14.0.7.exe`

### 3. Process Execution - TOR browser launch

- **Timestamp:** `2025-03-16T21:16:05.0740793Z`
- **Event:** User `gonsalvr`opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\GONSALVR\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR network

- **Timestamps:**
- `2025-03-16T21:16:23.480746Z` Connected to `5.161.60.61` on port `9001`
- `2025-03-16T21:16:31.1220241Z` Connected to `88.151.194.12` on port `9001`
- **Event:** Above network connections on port `9001` by User `gonsalvr` was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\Users\GONSALVR\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. File Creation - TOR shopping list

- **Timestamp:** `2025-03-16T21:42:32.5637425Z`
- **Event:** The User `gonsalvr` created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\GONSALVR\Desktop\tor-shopping-list.txt`

---

## Summary

The User **gonsalr** on the **GONSALVR-MDE** device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named **tor-shopping-list.txt**. This sequence of activities indicates that the User actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint **GONSALVR-MDE** by the User **gonsalvr**. The device was isolated, and the User's direct manager was notified.

---
