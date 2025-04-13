#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''A simple, hacky python script to automate initial enumeration of hosts,
   for use by OSCP/general infosec students and in CTFs or virtual labs.
   Some component scripts may be a bit loud and intrusive for use in actual pentests. 
   Only use on hosts you own/have permission to test'''

import ipaddress
from ipaddress import ip_address
import shlex
from time import sleep
import re
import random
import subprocess
import sys
import os
__author__ = "phi10s"

#
#
from termcolor import colored, cprint


# Takes a piped process started by subprocess.Popen and directs its
# output both to sys.stdout and to a string variable.
def handle_output(proc):
    output = ""
    # Read line by line, decode bytes to string
    for line_bytes in iter(proc.stdout.readline, b''):
        line_str = line_bytes.decode('utf-8', errors='ignore')
        output += line_str
        sys.stdout.write(line_str)
        sys.stdout.flush()  # Flush after each line
    # Ensure remaining output is read after process finishes
    remaining_output_bytes = proc.stdout.read()
    remaining_output_str = remaining_output_bytes.decode(
        'utf-8', errors='ignore')
    output += remaining_output_str
    sys.stdout.write(remaining_output_str)
    sys.stdout.flush()
    return output


def printred(text):
    cprint(text, 'red', attrs=['bold'])


def printgrey(text):
    cprint(text, 'grey', attrs=['bold'])


# Open /dev/null for writing unwanted shell messages.
devnull = open('/dev/null', 'w')

# Do basic TCP/UDP scan and return a string representation of results.


def do_nmap(ipAddr):
    try:
        printred(" ___         _   ___               "
                 + "\n| _ \___ _ _| |_/ __| __ __ _ _ _  "
                 + "\n|  _/ _ \ '_|  _\__ \/ _/ _` | ' \ "
                 + "\n|_| \___/_|  \__|___/\__\__,_|_||_|")

        printgrey(
            "\n[+] Beginning initial Nmap scan. This may take a few minutes.\n")
        # Using Popen with text mode (universal_newlines=True) might simplify decoding
        # but handle_output expects bytes. Sticking with bytes for now.
        proc = subprocess.Popen(["nmap", "-T5", "-sSU", "-Pn", ipAddr],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        nmapResult = handle_output(proc)
        return nmapResult
    except Exception as e:  # Updated exception syntax
        printgrey(f"\n[-] Nmap scan failed with exception: {e}\n")
        return ""

# Returns tuple of open TCP and UDP ports lists for further scanning.


def getOpenPorts(nmapResult):
    openTCPPorts = []
    openUDPPorts = []
    try:
        for line in re.findall(r'.*open.*', nmapResult):
            if "tcp" in line:
                openTCPPorts.append(line.split("/")[0])
                openTCPPorts = list(set(openTCPPorts))
            if "udp" in line:
                openUDPPorts.append(line.split("/")[0])
                openUDPPorts = list(set(openUDPPorts))
    except Exception as e:  # Updated exception syntax
        printgrey(f"\n[-] Failed with exception: {e}\n")
    return openTCPPorts, openUDPPorts

# Run in depth nmap vuln script scan on open ports, and return a string representation of results.


def do_script_scan(ipAddr, openPorts):
    try:
        printgrey("\n[+] Running Nmap script scans on open ports.\n")
        cmdstr = "nmap -T5 -sSUV -Pn --script default,vuln -p" + \
            ",".join(openPorts) + " " + ipAddr
        args = shlex.split(cmdstr)
        proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        nmapScriptRes = handle_output(proc)
        return nmapScriptRes
    except Exception as e:  # Updated exception syntax
        print(f"[-] Script scan failed with exception: {e}")
        return ""

# Detect Samba version and run Enum4linux, and return a tuple of strings as
# their respective results.


def smb_enum(ipAddr):
    printred(" ___ __  __ ___   ___                "
             + "\n/ __|  \/  | _ ) | __|_ _ _  _ _ __  "
             + "\n\__ \ |\/| | _ \ | _|| ' \ || | '  \ "
             + "\n|___/_|  |_|___/ |___|_||_\_,_|_|_|_|")
    try:
        printgrey(
            "\n[+] Starting Tcpdump and attempting to capture Samba version.\n")
        smbVersion = ""
        cmdstr = "tcpdump host " + ipAddr + " and tcp port 445 or port " \
            + "139 -i tap0 -A -c 14 -l -q > tcpdump.tmp"
        p = subprocess.Popen([cmdstr], shell=True,
                             stderr=devnull, stdout=devnull)
        # smbclientResult = subprocess.check_output(["smbclient","-L",ipAddr,"-N","-d0"]) # Needs decoding if used
        printgrey("\n[+] Running Enum4linux.\n")
        proc = subprocess.Popen(["enum4linux", "-a", ipAddr],
                                stdout=subprocess.PIPE, stderr=devnull)  # Keep stderr redirection for enum4linux
        enum4linuxResult = handle_output(proc)
        p.terminate()  # Ensure process p is terminated
        sleep(5)
        sys.stdout.flush()
        try:
            cmdstr = 'grep -o -P \'(?<=Unix.).*(?=.MYGROUP)\' tcpdump.tmp'
            # Capture output as bytes and decode
            smbVersion_bytes = subprocess.check_output(
                cmdstr, shell=True, stderr=subprocess.STDOUT)
            smbVersion = smbVersion_bytes.decode(
                'utf-8', errors='ignore').strip()
            printgrey("\n[+] Samba Version:\n")
            print(smbVersion + "\n")
        except Exception as e:  # Updated exception syntax
            printgrey(f"[-] Couldn't get Samba version.\n{e}\n")
        if os.path.exists("tcpdump.tmp"):  # Check if file exists before removing
            os.remove("tcpdump.tmp")
        return enum4linuxResult, smbVersion
    except Exception as e:  # Updated exception syntax
        printgrey("\n[-] Couldn't get SMB info.\n")
        print(e)
        return "", ""

# Check for port 161 and do snmpwalk with various MIB values, if available.
# Note: Must have Seclists repo installed to brute force SNMP community string.
# returns dictionary of strings as the results of using different MIB values.


def snmp_enum(ipAddr):
    printred(" ___ _  _ __  __ ___   ___                "
             + "\n/ __| \| |  \/  | _ \ | __|_ _ _  _ _ __  "
             + "\n\__ \ .` | |\/| |  _/ | _|| ' \ || | '  \ "
             + "\n|___/_|\_|_|  |_|_|   |___|_||_\_,_|_|_|_|")
    try:
        printgrey(
            "\n[+] Beginning SNMP enumeration.\n\n[+] Attempting to brute force SNMP community string.\n")
        communityStr = subprocess.check_output("nmap -T5 -sU -p161 --open --script snmp-brute "
                                               + str(ipAddr) + " --script-args"
                                               + " snmp-brute.communitiesdb=/usr/share/seclists/"
                                               + "Miscellaneous/wordlist-common-snmp-community-strings.txt"
                                               + " | grep Valid | cut -d' ' -f3", shell=True, stderr=subprocess.STDOUT).strip()
        communityStr = communityStr_bytes.decode(
            'utf-8', errors='ignore')  # Decode result
        if communityStr != "":
            printgrey("\n[+] Found SNMP community string:\n\n")
            print(communityStr + "\n")
            printgrey("\n[+] Attempting to enumerate system processes:\n")
            proc = subprocess.Popen(f"snmpwalk -c {communityStr} -v1 {ipAddr} 1.3.6.1.2.1.25.1.6.0 | cut -d':' -f2",
                                    shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            sysProc = handle_output(proc)
            printgrey("\n[+] Attempting to enumerate running programs:\n")
            proc = subprocess.Popen(f"snmpwalk -c {communityStr} -v1 {ipAddr} 1.3.6.1.2.1.25.4.2.1.2 | cut -d':' -f2",
                                    shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            runProg = handle_output(proc)
            printgrey("\n[+] Attempting to enumerate installed software:\n")
            proc = subprocess.Popen(f"snmpwalk -c {communityStr} -v1 {ipAddr} 1.3.6.1.2.1.25.6.3.1.2 | cut -d':' -f2",
                                    shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            installedSW = handle_output(proc)
            printgrey("\n[+] Attempting to enumerate user accounts:\n")
            proc = subprocess.Popen(f"snmpwalk -c {communityStr} -v1 {ipAddr} 1.3.6.1.4.1.77.1.2.25 | cut -d':' -f2",
                                    shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            userAccounts = handle_output(proc)
            printgrey("\n[+] Attempting to enumerate local TCP ports:\n")
            proc = subprocess.Popen(f"snmpwalk -c {communityStr} -v1 {ipAddr} 1.3.6.1.2.1.6.13.1.3 | cut -d':' -f2",
                                    shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            tcpPorts = handle_output(proc)
            # Filter out empty strings after split
            portlist = list(set(filter(None, tcpPorts.split("\n"))))
            localPorts = "\n".join(portlist)
            return {"System Processes": sysProc, "Running Programs": runProg,
                    "Installed Software": installedSW, "User Accounts": userAccounts,
                    "Local Ports": localPorts}
        else:
            printgrey(
                "[-] No valid SNMP community string found via brute-force.")
            return {}  # Return empty dict if no community string found
    except Exception as e:  # Updated exception syntax
        printgrey(f"[-] Failed to get SNMP info: {e}")
        return {}

# Gobuster HTTP enum with seclist common web dirs. Returns result as string.


def http_enum(ipAddr, httpPort):
    try:
        printred("\n _  _ _____ _____ ___   ___                "
                 + "\n| || |_   _|_   _| _ \ | __|_ _ _  _ _ __  "
                 + "\n| __ | | |   | | |  _/ | _|| ' \ || | '  \ "
                 + "\n|_||_| |_|   |_| |_|   |___|_||_\_,_|_|_|_|")
        printgrey(
            "\n[+] Enumerating HTTP with Gobuster. This may take a while.\n")
        url = f"http://{ipAddr}:{httpPort}/"
        wordlist = "/usr/share/seclists/Discovery/Web_Content/common.txt"
        # Check if wordlist exists
        if not os.path.exists(wordlist):
            printgrey(f"[-] Wordlist not found: {wordlist}")
            return ""
        # Updated gobuster syntax: gobuster dir -u <url> -w <wordlist>
        proc = subprocess.Popen(["gobuster", "dir", "-u", url, "-w",
                                wordlist], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        httpResult = handle_output(proc)
        return httpResult
    except Exception as e:  # Catch specific exception
        print(f"\n[-] Couldn't get HTTP directory info: {e}\n")
        return ""

# Gobuster HTTPS enum with seclist common web dirs. Returns result as string.


def https_enum(ipAddr, httpPort):
    try:
        printgrey(
            "\n[+] Enumerating HTTPS with Gobuster. This may take a while.\n")
        url = f"https://{ipAddr}:{httpPort}/"
        wordlist = "/usr/share/seclists/Discovery/Web_Content/common.txt"
        # Check if wordlist exists
        if not os.path.exists(wordlist):
            printgrey(f"[-] Wordlist not found: {wordlist}")
            return ""
        # Updated gobuster syntax and added -k for insecure HTTPS
        proc = subprocess.Popen(["gobuster", "dir", "-u", url, "-w", wordlist,
                                "-k"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        httpsResult = handle_output(proc)
        return httpsResult
    except Exception as e:  # Catch specific exception
        print(f"\n[-] Couldn't get HTTPS directory info: {e}\n")
        return ""

# Run Nmap scan on all TCP ports. Returns result as string.


def full_tcp_scan(ipAddr):
    try:
        printred("\n|_   _| |_  ___ _ _ ___ _  _ __ _| |_   / __| __ __ _ _ _  "
                 + "\n  | | | ' \/ _ \ '_/ _ \ || / _` | ' \  \__ \/ _/ _` | ' \ "
                 + "\n  |_| |_||_\___/_| \___/\_,_\__, |_||_| |___/\__\__,_|_||_|"
                 + "\n                            |___/ ")
        printgrey("\n[+] Beginning Nmap scan of all TCP ports.\n")
        proc = subprocess.Popen(["nmap", "-sS", "-v", "-p-", "-T5", "-Pn",
                                ipAddr], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        nmapResult = handle_output(proc)
        return nmapResult
    except Exception as e:  # Updated exception syntax
        printgrey(f"[-] Failed with exception: {e}")
        return ""

# Run Nmap scan on all UDP ports. Returns result as string.


def full_udp_scan(ipAddr):
    try:
        printgrey("\n[+] Beginning Nmap scan of all UDP ports.\n")
        proc = subprocess.Popen(["nmap", "-sU", "-v", "-p-", "-T5", "-Pn",
                                ipAddr], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        nmapResult = handle_output(proc)
        return nmapResult
    except Exception as e:  # Updated exception syntax
        printgrey(f"[-] Failed with exception: {e}")
        return ""


def main():

    print("\n")
    printred(" _____                       ___ _                 ")
    printred("| ____|_ __  _   _ _ __ ___ |_ _| |_   _ __  _   _ ")
    printred("|  _| | '_ \| | | | '_ ` _ \ | || __| | '_ \| | | |")
    printred("| |___| | | | |_| | | | | | || || |_ _| |_) | |_| |")
    printred("|_____|_| |_|\__,_|_| |_| |_|___|\__(_) .__/ \__, |")
    printred("                                      |_|    |___/ ")
    print("                                         By phi10s\n")

    if len(sys.argv) != 2:
        print(f"\n[+] Usage: {sys.argv[0]} <target ip addr>\n")  # Use f-string
        sys.exit(1)
    ipAddr = sys.argv[1]

    # Check whether ip addr is valid:
    try:
        ip_address(ipAddr)  # Removed unicode() call
    except ValueError:  # Catch specific ValueError for invalid IP
        print("\n[-] Not a Valid IP Address.\n")
        print(f"[+] Usage: {sys.argv[0]} <target ip addr>\n")  # Use f-string
        sys.exit(1)

    nmapResult = do_nmap(ipAddr)
    tcpPorts, udpPorts = getOpenPorts(nmapResult)
    openPorts = list(set(tcpPorts + udpPorts))
    scriptScanResult = do_script_scan(ipAddr, openPorts)
    if "139" in openPorts or "445" in openPorts:
        smbResult = smb_enum(ipAddr)
    if "161" in udpPorts:
        snmpEnumDict = snmp_enum(ipAddr)
    if "80" in tcpPorts:
        http80Result = http_enum(ipAddr, 80)
    if "8000" in tcpPorts:
        http8000Result = http_enum(ipAddr, 8000)
    if "8080" in tcpPorts:
        http8080Result = http_enum(ipAddr, 8080)
    if "443" in tcpPorts:
        httpsResult = https_enum(ipAddr, 443)
    fullTCP = full_tcp_scan(ipAddr)
    fullUDP = full_udp_scan(ipAddr)

    printgrey("\n[+] All Done!\n")


if __name__ == '__main__':
    main()
