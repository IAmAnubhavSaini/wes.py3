# wes.py3

windows-exploit-suggester but in python3

## convert xlsx file to csv to xls

As of right now, tool is writing .xlsx file, which needs to be converted to .csv and then to .xls for consumption again by the tool

```shell
ssconvert file.xlsx file.csv
ssconvert file.csv file.xls
```

Now you can use the script:

```shell
$ ./updated-wes2.py --database 2021-10-13-mssb.xls --systeminfo ~/htb/granny-2021.10.13/systeminfo.txt
```

Sample output:

```
[*]initiating winsploit version 3.3...
[*]database file detected as xls or xlsx based on extension
[*]attempting to read from the systeminfo input file
[+]systeminfo input file read successfully (utf-8)
[*]querying database file for potential vulnerabilities
[*]comparing the 1 hotfix(es) against the 356 potential bulletins(s) with a database of 137 known exploits
[*]there are now 356 remaining vulns
[+][E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+]windows version identified as 'Windows 2003 SP2 32-bit'
[*]
[M]MS15-051: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (3057191) - Important
[*]  https://github.com/hfiref0x/CVE-2015-1701, Win32k Elevation of Privilege Vulnerability, PoC
[*]  https://www.exploit-db.com/exploits/37367/ -- Windows ClientCopyImage Win32k Exploit, MSF
[*]
[E]MS15-010: Vulnerabilities in Windows Kernel-Mode Driver Could Allow Remote Code Execution (3036220) - Critical
[*]  https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows 8.1 - win32k Local Privilege Escalation (MS15-010), PoC
[*]  https://www.exploit-db.com/exploits/37098/ -- Microsoft Windows - Local Privilege Escalation (MS15-010), PoC
[*]  https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows win32k Local Privilege Escalation (MS15-010), PoC
[*]
[E]MS14-070: Vulnerability in TCP/IP Could Allow Elevation of Privilege (2989935) - Important
[*]  http://www.exploit-db.com/exploits/35936/ -- Microsoft Windows Server 2003 SP2 - Privilege Escalation, PoC
[*]
[E]MS14-068: Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780) - Critical
[*]  http://www.exploit-db.com/exploits/35474/ -- Windows Kerberos - Elevation of Privilege (MS14-068), PoC
[*]
[M]MS14-064: Vulnerabilities in Windows OLE Could Allow Remote Code Execution (3011443) - Critical
[*]  https://www.exploit-db.com/exploits/37800// -- Microsoft Windows HTA (HTML Application) - Remote Code Execution (MS14-064), PoC
[*]  http://www.exploit-db.com/exploits/35308/ -- Internet Explorer OLE Pre-IE11 - Automation Array Remote Code Execution / Powershell VirtualAlloc (MS14-064), PoC
[*]  http://www.exploit-db.com/exploits/35229/ -- Internet Explorer <= 11 - OLE Automation Array Remote Code Execution (#1), PoC
[*]  http://www.exploit-db.com/exploits/35230/ -- Internet Explorer < 11 - OLE Automation Array Remote Code Execution (MSF), MSF
[*]  http://www.exploit-db.com/exploits/35235/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution Through Python, MSF
[*]  http://www.exploit-db.com/exploits/35236/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution, MSF
[*]
[M]MS14-062: Vulnerability in Message Queuing Service Could Allow Elevation of Privilege (2993254) - Important
[*]  http://www.exploit-db.com/exploits/34112/ -- Microsoft Windows XP SP3 MQAC.sys - Arbitrary Write Privilege Escalation, PoC
[*]  http://www.exploit-db.com/exploits/34982/ -- Microsoft Bluetooth Personal Area Networking (BthPan.sys) Privilege Escalation
[*]
[M]MS14-058: Vulnerabilities in Kernel-Mode Driver Could Allow Remote Code Execution (3000061) - Critical
[*]  http://www.exploit-db.com/exploits/35101/ -- Windows TrackPopupMenu Win32k NULL Pointer Dereference, MSF
[*]
[E]MS14-040: Vulnerability in Ancillary Function Driver (AFD) Could Allow Elevation of Privilege (2975684) - Important
[*]  https://www.exploit-db.com/exploits/39525/ -- Microsoft Windows 7 x64 - afd.sys Privilege Escalation (MS14-040), PoC
[*]  https://www.exploit-db.com/exploits/39446/ -- Microsoft Windows - afd.sys Dangling Pointer Privilege Escalation (MS14-040), PoC
[*]
[E]MS14-035: Cumulative Security Update for Internet Explorer (2969262) - Critical
[E]MS14-029: Security Update for Internet Explorer (2962482) - Critical
[*]  http://www.exploit-db.com/exploits/34458/
[*]
[E]MS14-026: Vulnerability in .NET Framework Could Allow Elevation of Privilege (2958732) - Important
[*]  http://www.exploit-db.com/exploits/35280/, -- .NET Remoting Services Remote Command Execution, PoC
[*]
[M]MS14-012: Cumulative Security Update for Internet Explorer (2925418) - Critical
[M]MS14-009: Vulnerabilities in .NET Framework Could Allow Elevation of Privilege (2916607) - Important
[E]MS14-002: Vulnerability in Windows Kernel Could Allow Elevation of Privilege (2914368) - Important
[E]MS13-101: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2880430) - Important
[M]MS13-097: Cumulative Security Update for Internet Explorer (2898785) - Critical
[M]MS13-090: Cumulative Security Update of ActiveX Kill Bits (2900986) - Critical
[M]MS13-080: Cumulative Security Update for Internet Explorer (2879017) - Critical
[M]MS13-071: Vulnerability in Windows Theme File Could Allow Remote Code Execution (2864063) - Important
[M]MS13-069: Cumulative Security Update for Internet Explorer (2870699) - Critical
[M]MS13-059: Cumulative Security Update for Internet Explorer (2862772) - Critical
[M]MS13-055: Cumulative Security Update for Internet Explorer (2846071) - Critical
[M]MS13-053: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Remote Code Execution (2850851) - Critical
[M]MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[E]MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]  http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]  http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*]
[M]MS11-080: Vulnerability in Ancillary Function Driver Could Allow Elevation of Privilege (2592799) - Important
[E]MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M]MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M]MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[M]MS10-015: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (977165) - Important
[M]MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M]MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[M]MS09-065: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Remote Code Execution (969947) - Critical
[M]MS09-053: Vulnerabilities in FTP Service for Internet Information Services Could Allow Remote Code Execution (975254) - Important
[M]MS09-020: Vulnerabilities in Internet Information Services (IIS) Could Allow Elevation of Privilege (970483) - Important
[M]MS09-004: Vulnerability in Microsoft SQL Server Could Allow Remote Code Execution (959420) - Important
[M]MS09-002: Cumulative Security Update for Internet Explorer (961260) (961260) - Critical
[M]MS09-001: Vulnerabilities in SMB Could Allow Remote Code Execution (958687) - Critical
[M]MS08-078: Security Update for Internet Explorer (960714) - Critical
[*]done
```

## Previous work

[https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

## License

GPL 3.0

## References

- [original wes](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [wes introduction blog post](https://blog.gdssecurity.com/labs/2014/7/11/introducing-windows-exploit-suggester.html)
- [les.pl blog post](https://penturalabs.wordpress.com/2013/08/26/linux-exploit-suggester/)
- [les](https://github.com/mzet-/linux-exploit-suggester)
- [les2](https://github.com/jondonas/linux-exploit-suggester-2)
- [MS vulnerability database](https://msrc.microsoft.com/update-guide/vulnerability)
- [cvedetails](https://www.cvedetails.com/vulnerability-list/vendor_id-26/Microsoft.html)
- [cve.mitre](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=microsoft)
