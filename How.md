# MONITOR SERVICE

## DIR
```
.
├── Logs (auto-generated)
├── modules /
│   ├── macro_analyzer
│   ├── threat_response
│   └── deobfuscator
└── MonitorMalwareService

```

#### VARS

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

- 0 - 70 : Benign, safe
- 70 - 150 : Potential harmful - action: more monitor 
- 150+ : Harmful - action: quarantine, block ip related, terminate process

## I. SCAN DIRECTORY

#### STEPS:

- 1 - Scan whole directory ( here is set for C:\ ) for  **office_file**

- 2 - Check match MIME type with it magic number 
    - Match 0 `( if .exe then 20 )`
    - Not match 20

- 3 - Check for macro using **[olevba](https://github.com/decalage2/oletools/wiki/olevba)**
    - No macro 0
    - Macro exist 10
        - Parsing output of **olevba** for keywords contains

            | Type| Score | Description |
            | ----------- | ----------- | ----------- |
            | IOC | 40 | consist of urls, file name | 
            | AUTOEXEC | 20 | auto execute when open |
            | SUSPICIOUS | 10 |  VBA obfuscation, possible shell, command, exec ...| 


- 4 - **If obfuscatetd macro exist** , attempt to deobfuscated it

- 5 - ***If it is running*** Check **sysmon** and **handle** for further information/logs 
    -   More info refer to [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/)

- 6 - ***If it is running*** Check for dlls that the file use , using **listdlls** from **Sysinternals**

- 7 - Return `keywords` and `threat score` for further analyzing

---

\*To check ***If it is running*** simply find the **office_process** , and if that proccess is running the current checking file



## II. SCAN PROCESS

Run a separate thread to monitor process creating, running,...

#### STEPS

- 1 - Check if process in **suspicious_process** list

- 2 - Analyse process dlls for **suspicious_dll**


## III. SCAN NETWORK

Run a separate thread to monitor network sniffing...

#### STEPS

- 1 - Sniff packet

- 2 - Analyze packet for C2 payload/ suspicious payload (base64, unprintable char)


## IV. THREAT RESPONSE

- For I and II : terminate process and quaratine file
    - Quaratined file will be moved to separate folder and change extension name to prevent open 
- For III : block IP 


***TODO:***

- Need a way to combine all outputs from I, II and III into ***Singular point of information*** it's timeline , actions, suspicious potential danger payloads, keywords, process , it total threat_score then the verdict to terminate it, quarantine it or simply block ip or all of them

- Draw a graph for the whole timeline (based off CyberKillChain if possible) related information, spawned process, etc ... for further analysis, saved it hash to `main dictionary/blacklist`

- *For I* Analyzing `keywords`, keep in a `main dictionary/blacklist` for reference , May use for I.6 for further analyzing dlls

- *For I* The `sysmon` and `handle` currently not used, try attempt to find a solution

- *For II* Keep track of each running process for ***timeline, linkage, pids, spawned/child process, related files, marked as suspicious file*** - combine with analysis from I.7 

- *For II*Check for reference in  `main dictionary/blacklist` for suspicious process/executables/dlls

- *For III*Check for reference in  `main dictionary/blacklist` for suspicious urls

- *For III* Tracking **suspicious_port** reference in  `main dictionary/blacklist`, **threat_score** if a packet/connection using it

- *For IV* To prevent access denied due to opening process in quarantining process - attempt to kill all process that related/using it them begin to quarantine