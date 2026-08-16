# MINDSET + KNOWLEDGE AFTER CLEARING VERY EASY + EASY HTB #

## 1. EXECUTION SINK ##
- Basically, in every malicious scripts written in all languages, attackers need to add a signature to make those scripts become executable, which is `Execution Sink`.

-  For example, in `PowerShell` .ps1 file, if the script is highly obfuscated, obviously we can upload it to some deobfuscator online webs, however if the web can't deobfuscate it or you just dont want to do it, just find the command line where attackers call `iex` - `Invoke-Request`. Or in a `JavaScript` file, the function `eval` is a `Sink`, so my first knowledge is: If we need to save time just remove the sink and replace it with the `print` or save file function.
  
- Despite the fact that we still need to know what the function will do, we don't need to always deobfuscate the script.

## 2. ALWAYS LOOK FOR USEFUL TOOLS ##
- This is a point where I still can't prefect. The process of thinking to use a tool will help us to notably reduce the time we need to do something by hands. 

- For instance, we absolutely don't want to read all logs `.evtx` file to find the suspicious activities of the attacker, just use `chainsaw`, `sysmon` and save time to do other works.


## 3. READ MORE AND MORE ##
- After solving challenges after challenges, I find out that Forensics is quite a broad category since the artificial can be anything, from an IoT device, an email, a document, ... There is even a router dump, which if I haven't had a smallest thought about when I first learned.

- Which I want to say here, is we need to read a lot of information from articles, github repositories,... to figure out what's going on. Imagining in a competition, it will be so great if we learnt or read about that piece of information before another competents to save more time.


## 4. MINDSET ##
- If you face up with `.docx`, `.xlsm` files:
  -  Use `oleid` to see what's wrong with the file.
  -  If there's a high chance of malicious VBA macro payloads, use `olevba` to analyze it further
  -  Use `oleobj` to see if attackers attach anything on the document.

- If you face up with `Logs` folder:
  - Use `chainsaw`
  - Common logs to pay attention to:
    - Security: Logon, Logoff, Process Creation event, specially if attacker try to escalate privilege
    - Sysmon: Great if found, provides exactly powershell, cmd command, file's hash downloaded
    - Microsoft-Windows-PowerShell-Operational: Need configuration from user to be able capture exactly commands ran like Sysmon.

- If you face up with a `.pcap` traffic:
  - If it's large: Statistics -> Protocol Hierarchy helps you a lot
  - If it's small: If you want to do it, do it
  - Look for `Export Object` to see is there any weird file and crossed reference with the traffic
  - If `MySQL` appears, there's a chance attacker try to hack into victim's database
  - If `Telnet` protocol appears, there's a chance attacker try to sniff through victim's traffic
  - Look for suspicious IP address, such as an IP appears frequently, or even only a few times. I understand `suspicious` here sound quite broad, but the only thing helps you filter it down is your game sense which can only be developed through challenges and challenges (look like I haven't had any sense yet)

- If you face up with a `memory dump`:
  - Use `windows.psscan` and `windows.pstree` to analyze parent-child relations, look for suspicious relation such as ...
  - Use `windows.filescan` to see if there's any suspicious file in the memory
  - Use `windows.dumpfiles` if you need to dump a file, need `--virtaddr` or `--physaddr`, which can be found in `psscan` or `pstree`
  - Use `windows.memmap` if you need to dump an entire process, need `pid` which can be found in `psscan` or `pstree`
  - Use `windows.cmdline` and `windows.cmdscan` to see if there's any suspicious command line attacker ran. 
  - Volatility 3 is not always better than Volatility 2

- If you face up with a `disc image` (.iso, .vhdk, ...):
  - Use FTK Imager for static analyzing before trying to mount to your virtual computer

- If you face up with an `obfuscated script`:
  - Replace execution sink
  - Deobfuscator online

- If you face up with a `weird string`:
  - CyberChef recipe Magic may help


```bash
file
strings
exiftool
```
is the trinity of file analysing

- If you face up with a `.lnk` shortcut:
  - Use `strings -el` instead of `strings`

- Don't use IDA before using `strings`, `grep`

- Hashcat, johntheripper can be used to bruteforce password

## 5. KNOWLEDGE ##
- **RAID 5:** A data storage virtualization technology that combines multiple physical disks into one logical unit, using block-level striping with distributed parity. 
  - *Forensics Mindset:* Every RAID 5 disk images need to be the same size, so if one disc is smaller you know it's corrupted. However you can easily recover it by XOR the others. Then you can reconstruct the virtual array first by using mdadm before mounting the real disc.


- **OpenWRT:** An open-source, Linux-based operating system targeting embedded devices, primarily routers. 
  - *Forensics Mindset:* Often appears as a router firmware dump. We can use `binwalk -e` to extract the file system, usually `squashfs-root` for the operating system, default configurations, `jffs2-root` for modifiable data such as passwords, redirect, ...


- **User defined function (UDF):** A feature in MySQL that allows users to write custom C/C++ code. 
  - *Forensics Mindset:* Attackers will upload a malicious library `.so` for Linux, `.dll` for Windows into the database plugin folder, create a custom UDF, and use it to execute system commands from SQL queries.


- **MFT:** Master File Table (`$MFT`). The core of NTFS file system, it's a massive database storing metadata for every single file and directory on a Windows drive.
  - *Forensics Mindset:* Using MFTECmd to parse the file to csv format, check the status of every file, look for any hidden Alternate Data Streams.


- **WMI repository:** Windows Management Instrumentation database (located in `C:\Windows\System32\wbem\Repository`). 
  - *Forensics Mindset:* A hiding spot for Fileless Persistence. Attackers link an `__EventFilter` which is a system event trigger, like booting up to an `EventConsumer` - the malicious script so the malware runs secretly without relying on the `Registry Run keys` or Startup folder.


- **.git:** A hidden directory containing the complete version control history, commits, and branches of a repository.
  - *Forensics Mindset:* You can run `git log -p`, `git diff` to dump, to check the modification of the repository and hunt for deleted files, hardcoded passwords, or exposed API keys from previous commits.

- **LDAP:** Lightweight Directory Access Protocol. Used for querying and modifying directory services Windows Active Directory. 
  - *Forensics Mindset:* In `.pcap` files, unencrypted LDAP traffic can leak the domain structure. Attackers can use LDAP queries to enumerate users, groups, and domain admins.