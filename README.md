# VBA MACRO MLWARE MONITOR SERVICE

The VBA Macro Malware Monitor Service is a Python-based security tool designed to detect and respond to malicious activities on Windows systems. It monitors files, processes, and network traffic for suspicious behavior, focusing on Office files with VBA macros, executable files, and network payloads. Using libraries like Watchdog, WMI, Scapy, and tools such as Sysinternals, Manalyze, and olevba, it analyzes threats, assigns risk scores, and takes actions like quarantining files, terminating processes, or blocking IPs when threats exceed defined thresholds. The service provides efficient analysis, with typical processing times of 3-5 seconds for files and near-instantaneous for processes and packets to provides real-time protection to user device/endpoint.

## DIR TREE
```
.
├── Logs (auto-generated)/
│   └── Log_xxxxx/
│       └── ...
├── modules/
│   ├── analyzer.py ( main module to analyze and decide to take actions )
│   ├── parser.py ( running tools, exe, cmd and parsing values)
│   ├── threat_response.py 
│   ├── watchlist.py
│   ├── blacklist.py ( contains config blacklist, whitelist)
│   ├── deobfuscator.py ( deofuscate VBA)
│   ├── remove_vba.py
│   ├── scoring.json5 ( contains score for each category - change base on risk apetite)
│   └── exclusions.json5 ( what the tools will ignore)
├── manalyze_x64 ( contains github repo Manalyze)
├── SYSINTERNAL ( folder contains sysinternals exe)/
│   ├── sigcheck.exe
│   └── ...
├── MonitorMalwareService.py (main entrypoint)
├── Stop-RemoveService.ps1
└── Install-StartService.ps1
```
## TESTED ON

- Windows 10 Pro (10.0.19045 Build 19045)
- RAM 6 GB, 2 Cores Ryzen7 8745H 

- Python 3.13.2

## DEPENDENCIES

- watchdog==6.0.0
- scapy==2.6.1
- WMI==1.5.1
- pywin32==310

- [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/)
- [Manalyze](https://github.com/JusticeRage/Manalyze)
- [olevba](https://github.com/decalage2/oletools/wiki/olevba)

- [More here ...](/requirements.txt)
## INSTALL AND DEPLOY

Simply `clone` this repository , install requirements and naming the folders correctly

Then change the path in **Install-StartService.ps1** and **Stop-RemoveService.ps1** then run it.. Done

**If there troubles in stopping service** - simply, go into TaskManager find python-service then terminate it.
#### VARIABLES

- **exclusions** - ignore when run ( ip, folder, process, cmd)

- **suspicious_process** - Current ly tracking cmd.exe, powershell.exe, wscript.exe and other 
non-network connection like: mspaint, notepad, calc, explorer

- **suspicious_ip** - ip found in `urls` of macro analysis or found via `suspicious payload`

- **suspicious_port** - from related with **suspicious_ip** 

- **suspicious_dll** - found in 'dlls' of macro analysis

- **office_file** - just office file, current tracking extensions:

    - word - [`doc`, `docx`, `docm`, `dot`, `dotx`, `docb`, `dotm`]
    - excel - [`xls`, `xlsx`, `xlsm`, `xlt`, `xlm`, `xltx`, `xltm`, `xlsb`, `xla`, `xlw`, `xlam`]
    - ppt - [`ppt`, `pptx`, `pptm`, `pot`, `pps`, `potx`, `potm`, `ppam`, `ppsx`, `sldx`, `sldm`]

- **office_process** - `winword.exe`, `excel.exe`, `powerpnt.exe`

- **threat_score** - main indication if a process, file, connection is malicious/ harmful
- **suspicious_extensions** - `.exe`, `.bat`, `.ps1`, `.sh`, `.cmd`

- **suspicious_cmd** - `cmd`, `powershell`, `net`, `reg`, `taskkill`, `sc`, `wmic`

- **main dictionary/blacklist** - is a json that saved all *suspicious_* above for ease of tracking 

#### SCORE RULES
 
This is a **threat_score** rule

- 0 - 99 (for process 0 - 69) : Benign, safe 
- 100+ (70+ for process) Harmful - action: quarantine, block ip related, terminate process

***ALL MONITORS ARE RUNNING CONCURRENTLY***
## I. FILE MONITORING
Detects Office files and executables..
#### STEPS:
**[Watchdog](https://github.com/gorakhargosh/watchdog)** library will detect newly created files ( download included) then begin analyze below:

- 1 - Check match MIME type with it magic number 
    - Match 0 `( if .exe then 20 )`
    - Not match 20

- 2 - **If executable/PE** Check signature using **sigcheck.exe** from **[Sysinternals](https://learn.microsoft.com/en-us/sysinternals/)**
- 3 - **If executable/PE** Check for suspicious/malicious (combinations of) strings using **[Manalyze](https://github.com/JusticeRage/Manalyze)** 
- 4 - Check for macro using **[olevba](https://github.com/decalage2/oletools/wiki/olevba)**
    - No macro 0
    - Macro exist 10
        - Parsing output of **olevba** for keywords contains

            | Type| Score | Description |
            | ----------- | ----------- | ----------- |
            | IOC | 30 | consist of urls, file name | 
            | AUTOEXEC | 20 | auto execute when open |
            | SUSPICIOUS | 10 |  VBA obfuscation, possible shell, command, exec ...| 

    **For more details please view [scoring.json5](modules/scoring.json5)**

- 5 - **If obfuscatetd macro exist** , attempt to deobfuscated it the back to step 2 to check for suspicious keywords

- 6 - Check for file in **watchlist** - name


- 7 - ***If it is running*** Check **handle** for further information - process using it
    -   More info refer to [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/)

- 8 - ***If it is running*** Check for dlls that the file use , using **listdlls** from **Sysinternals**

- 9 - Take actions if **threat_score** >= 100

---

\*To check ***If it is running*** simply find the **office_process** , and if that proccess is running the current checking file


## II. PROCESS MONITORING

Run a separate thread to monitor process creating, running,...

#### STEPS
**[WMI](https://github.com/tjguk/wmi/tree/master)** library help  detect newly created process 

- 1 - Check if process in **suspicious_process** list 

- 2 - Check for process in **watchlist** - cmdline, name

- 3 - Analyse process dlls for **suspicious_dll** 

- 5 - Take actions if **threat_score** >= 70

## III. NETWORK MONITOR

Run a separate thread to monitor network sniffing...

#### STEPS
**[Scapy](https://github.com/secdev/scapy)** library to sniff packets
- 1 - Sniff packet

- 2 - Analyze packet for possible C2 payload/ suspicious payload (base64, unprintable char)

- 3 - Check for info in **watchlist** - ip, urls

- 4 - Take actions if detected C2 ( in watchlist + encode payload)

## IV. THREAT RESPONSE
- 1 - Export reports of findings as json
- 2 - Do the follows:
    - For I :
        - **Quaratine** file will be moved to separate folder and change extension name to prevent open 
        - **If have VBA macros, Remove VBA** replace the file in location with a clean, no macros office
    - For II: **Terminate** process using taskkill
    - For III : **Block IP** with firewall rule 

## V. LOGGING
- All detection, activities will be logged 

## VI. NUMBERS
- Office files analysis: 3 - 5s (4.8s)
- Executables analysis: 3 - 5s (4.8s)
- Process analysis: 0.3 - 0.5s (max 1.2s)
- Packet analysis: (0 - 0.2s) (0.12s)

***FUTURES:***

- Draw a graph for the whole timeline (based off CyberKillChain if possible) related information, spawned process, etc ... for further analysis, saved it hash to `main dictionary/blacklist`

