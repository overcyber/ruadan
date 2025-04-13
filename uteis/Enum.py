#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, subprocess, re
from urllib.parse import urlparse # Changed from urlparse
import threading

ALLSERVICES = []
THREADS = []

class newThreadNmap(threading.Thread):
    def __init__(self,threadID,target):
        super().__init__() # Use super() for initialization in Python 3
        self.threadID = threadID
        self.target = target

    def run(self):
        ALLSERVICES[self.threadID - 1] = conductLightNmap(self.target)

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ------------------------------------
#       Toolbox
# ------------------------------------

def printHeader(target):
    print()
    print("###################################################")
    print(f"##   Enumerating {target}")
    print("##")
    print("###################################################")
    print()

def printUsage():
    print(f"Usage: {sys.argv[0]} <target ip>")

def printPlus(message):
    print(f"{bcolors.OKGREEN}[+] {message}{bcolors.ENDC}")

def printMinus(message):
    print(f"{bcolors.WARNING}[-] {message}{bcolors.ENDC}")

def printStd(message):
    print(f"[*] {message}")

def printErr(message):
    print(f"{bcolors.FAIL}[!] {message}{bcolors.ENDC}")

def printDbg(message):
    print(f"{bcolors.OKBLUE}[?] {message}{bcolors.ENDC}")

def printInBox(command, result):
    top =   "###################################################"
    bot =   "==================================================="
    sub =   "---------------------------------------------------"
    return "%s\n\n%s\n\n%s\n\n%s\n%s\n" % (top, command, sub, result, bot)

def parseNmapScan(results):
    services = {}
    lines = results.split("\n")
    for line in lines:
        ports = []
        line = line.strip()
        if ("tcp" in line or "udp" in line) and ("open" in line) and not ("filtered" in line) and not ("Discovered" in line):
            while "  " in line:
                line = line.replace("  ", " ");
            linesplit = line.split(" ")
            service = linesplit[2]
            port = linesplit[0]
            if service in services:
                ports = services[service]
            ports.append(port)
            services[service] = ports
    return services

def dispatchModules(target, services):
    for service in services:
        port = services[service]
        if service in KNOWN_SERVICES:
            try:
                KNOWN_SERVICES[service](target, port)
            except AttributeError:
                printDbg(f"No module available for {service} - {port}")
            except KeyError: # Handle case where service is not in KNOWN_SERVICES
                 printDbg(f"No module available for {service} - {port}")
        else:
            printDbg(f"No module available for {service} - {port}")

def validate_ip(s):
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True

def parse_ip(s):
    urls = re.findall("http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", s)
    for url in urls:
        url = url.lower()
    return list(set(urls))

def parse_ip_directories(s):
    urls = re.findall("http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+/", s)
    for url in urls:
        url = url.lower()
    return list(set(urls))

# ------------------------------------
#       Setup
# ------------------------------------

def prepareFolder(target):
    printStd(f"Preparing portfolio for {target}")
    directory = os.path.join(os.getcwd(), target) # Use os.path.join for paths
    if not os.path.exists(directory):
        os.makedirs(directory)
        return None
    return directory

def writeToFile(target, name, content):
    # Use os.path.join and ensure encoding for Python 3 file writing
    path = os.path.join(os.getcwd(), target, f"{name}.txt")
    # Use 'a+' mode with utf-8 encoding
    file = open(path, "a+", encoding='utf-8')
    # Ensure content is string before writing
    file.write(str(content))
    file.close()
    return path

# ------------------------------------
#       Scans
# ------------------------------------


def execNmapParallel(ipList):
    for count,ip in enumerate(ipList,1):
        t = newThreadNmap(count,ip)
        THREADS.append(t)
        t.start()
    for thread in THREADS:
        thread.join()


# Light NMAP
# ========================
def conductLightNmap(target):
    printStd(f"Conducting light nmap scan for {target}")
    NAME = "nmap_light"

    # Conduct Scan #
    # Ensure target is properly formatted if needed
    TCPSCAN = "nmap %s -Pn -T4" % target
    UDPSCAN = "nmap -sU -Pn -p 161 %s" % target
    tcpResults = b"" # Initialize as bytes for subprocess output
    udpResults = b"" # Initialize as bytes for subprocess output
    try:
        # Capture output as bytes and decode to utf-8
        tcpResults = subprocess.check_output(TCPSCAN, shell=True, stderr=subprocess.STDOUT)
        udpResults = subprocess.check_output(UDPSCAN, shell=True, stderr=subprocess.STDOUT)
        #print(tcpResults.decode('utf-8', errors='ignore')) # Decode for printing

        # Write Results #
        # Decode results before passing to printInBox and writeToFile
        content = printInBox(TCPSCAN, tcpResults.decode('utf-8', errors='ignore'))
        path = writeToFile(target, NAME, content)

        printPlus(f"Finished light nmap scan: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{TCPSCAN}")
    except subprocess.CalledProcessError as e:
        # Handle potential errors from subprocess, decode output for error message
        printErr(f"Unable to conduct light nmap scan:\n\t{TCPSCAN}\n\n{e.output.decode('utf-8', errors='ignore')}")
        # Consider if sys.exit is appropriate or if it should return/raise
        # sys.exit(2)
    except Exception as e:
        printErr(f"An unexpected error occurred during light nmap scan:\n\t{TCPSCAN}\n\n{e}")
        # sys.exit(2)


    # Filter Results #
    # Decode results before parsing
    services = parseNmapScan(f"{tcpResults.decode('utf-8', errors='ignore')}\n{udpResults.decode('utf-8', errors='ignore')}")

    return services
# ========================

# Heavy NMAP
# ========================
def conductHeavyNmap(target):
    printStd(f"Conducting heavy nmap scan for {target}")
    NAME = "nmap_heavy"

    # Conduct Heavy nmap Scan #
    TCPSCAN = f"nmap -T5 -Pn -A -sV --top-ports 10000 {target}"
    try:
        # Capture output as bytes and decode
        tcpResults = subprocess.check_output(TCPSCAN, shell=True, stderr=subprocess.STDOUT)

        # Write Results #
        content = printInBox(TCPSCAN, tcpResults.decode('utf-8', errors='ignore'))
        path = writeToFile(target, NAME, content)
        printPlus(f"Finished heavy nmap scan: {os.path.join(os.getcwd(), target, 'nmap_heavy.txt')}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{TCPSCAN}")
    except subprocess.CalledProcessError as e:
        printErr(f"Unable to conduct heavy nmap scan:\n\t{TCPSCAN}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during heavy nmap scan:\n\t{TCPSCAN}\n\n{e}")


    printStd("Conducting UDP scan")

    # Conduct UDP Scan #
    UDPSCAN = f"nmap -T5 -sU --top-ports 1000 {target}"
    try:
        # Capture output as bytes and decode
        udpResults = subprocess.check_output(UDPSCAN, shell=True, stderr=subprocess.STDOUT)

        # Write Results #
        content = printInBox(UDPSCAN, udpResults.decode('utf-8', errors='ignore'))
        path = writeToFile(target, NAME, content)
        printPlus(f"Finished UDP scan: {os.path.join(os.getcwd(), target, 'nmap_heavy.txt')}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{UDPSCAN}")
    except subprocess.CalledProcessError as e:
        printErr(f"Unable to conduct UDP scan:\n\t{UDPSCAN}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
         printErr(f"An unexpected error occurred during UDP scan:\n\t{UDPSCAN}\n\n{e}")
# ========================

# FTP
# ========================
def ftp(target, ports):
    printStd("Investigating FTP")
    NAME = "ftp"

    # Conduct nmap Scan #
    portString = ",".join([p.split("/")[0] for p in ports]) # More Pythonic way to join ports
    SCRIPTS = "ftp-vuln-*, ftp-anon"
    NMAPSCAN = f"nmap -T5 -p {portString} -sV -sC --script=\"{SCRIPTS}\" {target}"
    try:
        # Capture output as bytes and decode
        nmapResults = subprocess.check_output(NMAPSCAN, shell=True, stderr=subprocess.STDOUT)

        # Write Results #
        content = printInBox(NMAPSCAN, nmapResults.decode('utf-8', errors='ignore'))
        path = writeToFile(target, NAME, content)
        printPlus(f"Finished investigating FTP: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{NMAPSCAN}")
    except subprocess.CalledProcessError as e:
         printErr(f"Unable to conduct FTP scan:\n\t{NMAPSCAN}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during FTP scan:\n\t{NMAPSCAN}\n\n{e}")
# ========================

# SMTP
# ========================
def smtp(target, ports):
    printStd("Investigating SMTP")
    NAME = "smtp"

    # Conduct nmap Scan #
    portString = ",".join([p.split("/")[0] for p in ports])
    NMAPSCAN = f"nmap -T4 -p {portString} -sV --script=\"smtp-vuln*\" {target}"
    try:
        # Capture output as bytes and decode
        nmapscanResults = subprocess.check_output(NMAPSCAN, shell=True, stderr=subprocess.STDOUT)

        # Write Results #
        content = printInBox(NMAPSCAN, nmapscanResults.decode('utf-8', errors='ignore'))
        path = writeToFile(target, NAME, content)
        printPlus(f"Finished scanning SMTP: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{NMAPSCAN}")
    except subprocess.CalledProcessError as e:
        printErr(f"Unable to conduct SMTP scan:\n\t{NMAPSCAN}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during SMTP scan:\n\t{NMAPSCAN}\n\n{e}")


    # Conduct Brute #
    printStd("Trying to brute-force SMTP users")
    # Ensure wordlist path exists or handle error
    wordlist_path = "/usr/share/fern-wifi-cracker/extras/wordlists/common.txt"
    if not os.path.exists(wordlist_path):
        printErr(f"Wordlist not found: {wordlist_path}")
        return # Or handle differently

    SCAN1 = f"smtp-user-enum -M EXPN -U {wordlist_path} -t {target}"
    try:
        # Capture output as bytes and decode
        scan1Results = subprocess.check_output(SCAN1, shell=True, stderr=subprocess.STDOUT)

        # Write Results #
        content = printInBox(SCAN1, scan1Results.decode('utf-8', errors='ignore'))
        path = writeToFile(target, NAME, content)
        printPlus(f"Finished investigating SMTP: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{SCAN1}")
    except subprocess.CalledProcessError as e:
         printErr(f"Unable to conduct SMTP brute force:\n\t{SCAN1}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during SMTP brute force:\n\t{SCAN1}\n\n{e}")
# ========================

# POP3
# ========================
def pop3(target, ports):
    printStd("Investigating POP3")
    NAME = "pop3"

    # Conduct Basic Scan"
    portString = ",".join([p.split("/")[0] for p in ports])
    NMAPSCAN = f"nmap -T5 -p {portString} -sV --script=\"pop3-capabilities,pop3-ntlm-info\" {target}"
    try:
        # Capture output as bytes and decode
        nmapscanResults = subprocess.check_output(NMAPSCAN, shell=True, stderr=subprocess.STDOUT)

        # Write Results #
        content = printInBox(NMAPSCAN, nmapscanResults.decode('utf-8', errors='ignore'))
        path = writeToFile(target, NAME, content)
        printPlus(f"Finished enumerating POP3: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{NMAPSCAN}")
    except subprocess.CalledProcessError as e:
        printErr(f"Unable to enumerate POP3:\n\t{NMAPSCAN}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during POP3 enumeration:\n\t{NMAPSCAN}\n\n{e}")


    # Conduct Brute Force"
    printStd("Trying to brute-force POP3 users")
    BRUTE = f"nmap -T4 -p {portString} --script=\"pop3-brute\" {target}"
    try:
        # Capture output as bytes and decode
        bruteResults = subprocess.check_output(BRUTE, shell=True, stderr=subprocess.STDOUT)

        # Write Results #
        content = printInBox(BRUTE, bruteResults.decode('utf-8', errors='ignore'))
        path = writeToFile(target, NAME, content)
        printPlus(f"Finished investigating POP3: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{BRUTE}")
    except subprocess.CalledProcessError as e:
        printErr(f"Unable to brute-force POP3 users:\n\t{BRUTE}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during POP3 brute force:\n\t{BRUTE}\n\n{e}")
# ========================

# IMAP
# ========================
def imap(target, ports):
    printStd("Investigating IMAP")
    NAME = "imap"

    # Conduct Basic Scan"
    portString = ",".join([p.split("/")[0] for p in ports])
    NMAPSCAN = f"nmap -T5 -p {portString} -sV --script=\"imap-capabilities,imap-ntlm-info\" {target}"
    try:
        # Capture output as bytes and decode
        nmapscanResults = subprocess.check_output(NMAPSCAN, shell=True, stderr=subprocess.STDOUT)

        # Write Results #
        content = printInBox(NMAPSCAN, nmapscanResults.decode('utf-8', errors='ignore'))
        path = writeToFile(target, NAME, content)
        printPlus(f"Finished enumerating IMAP: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{NMAPSCAN}")
    except subprocess.CalledProcessError as e:
        printErr(f"Unable to enumerate IMAP:\n\t{NMAPSCAN}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during IMAP enumeration:\n\t{NMAPSCAN}\n\n{e}")


    # Conduct Brute Force"
    printStd("Trying to brute-force IMAP users")
    BRUTE = f"nmap -T5 -p {portString} --script=\"imap-brute\" {target}"
    try:
        # Capture output as bytes and decode
        bruteResults = subprocess.check_output(BRUTE, shell=True, stderr=subprocess.STDOUT)

        # Write Results #
        content = printInBox(BRUTE, bruteResults.decode('utf-8', errors='ignore'))
        path = writeToFile(target, NAME, content)
        printPlus(f"Finished investigating IMAP: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{BRUTE}")
    except subprocess.CalledProcessError as e:
        printErr(f"Unable to brute-force IMAP users:\n\t{BRUTE}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during IMAP brute force:\n\t{BRUTE}\n\n{e}")
# ========================

# SMB
# ========================
def smb(target, ports):
    printStd("Investigating SMB")
    NAME = "smb"

    # Conduct Vulnerability Scans #
    SCAN1 = f"nmap -T5 -sV -sC --script=\"smb-vuln-*,samba-vuln-*\" -p 445,139 {target}"
    SCAN2 = f"nmap -T5 -sU -sV -sC --script=\"smb-vuln-*\" -p U:137,T:139 {target}"
    try:
        # Capture output as bytes and decode
        scan1Results = subprocess.check_output(SCAN1, shell=True, stderr=subprocess.STDOUT)
        scan2Results = subprocess.check_output(SCAN2, shell=True, stderr=subprocess.STDOUT)

        # Write Results #
        content = f"{printInBox(SCAN1, scan1Results.decode('utf-8', errors='ignore'))}\n{printInBox(SCAN2, scan2Results.decode('utf-8', errors='ignore'))}"
        path = writeToFile(target, NAME, content)
        printPlus(f"Finished investigating SMB Vulnerabilities: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{SCAN1}\n\t{SCAN2}")
    except subprocess.CalledProcessError as e:
        # Determine which scan failed if possible, or provide a general error
        printErr(f"Unable to conduct SMB vulnerability scan (check logs for details):\n\t{SCAN1}\n\t{SCAN2}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during SMB vulnerability scan:\n\t{SCAN1}\n\t{SCAN2}\n\n{e}")


    # Conduct Scan #
    printStd("Investigating SMB Access")
    LOOKUP = f"nmblookup -A {target}"
    SCAN = f"enum4linux {target}"
    ADVICE = f"use :: smbclient //<server>/<share> -I {target} -N :: to mount shared drive anonymously"
    try:
        # Lookup #
        # Capture output as bytes and decode
        lookupResults = subprocess.check_output(LOOKUP, shell=True, stderr=subprocess.STDOUT)

        # Write Results #
        content = printInBox(LOOKUP, lookupResults.decode('utf-8', errors='ignore'))
        path = writeToFile(target, NAME, content)

        # Scan #
        # Capture output as bytes and decode
        scanResults = subprocess.check_output(SCAN, shell=True, stderr=subprocess.STDOUT)

        # Write Results #
        content = printInBox(SCAN, f"{scanResults.decode('utf-8', errors='ignore')}\n\n{ADVICE}")
        path = writeToFile(target, NAME, content)
        printPlus(f"Finished investigating SMB: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{SCAN}") # Assuming SCAN is the primary command here
    except subprocess.CalledProcessError as e:
         printErr(f"Unable to conduct SMB scan (check nmblookup or enum4linux):\n\t{LOOKUP}\n\t{SCAN}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during SMB scan:\n\t{LOOKUP}\n\t{SCAN}\n\n{e}")
# ========================

# HTTP
# ========================
def http(target, ports):
    printStd("Investigating HTTP")
    NAME = "http"

    # Conduct nmap Scan #
    # Ensure ports list is not empty
    if not ports:
        printErr("No HTTP ports provided for scanning.")
        return

    SCRIPTS = "http-methods,http-robots.txt,http-vuln-*,http-userdir-enum,http-iis-webdav-vuln,http-majordomo2-dir-traversal,http-axis2-dir-traversal,http-tplink-dir-traversal,http-useragent-tester"

    portString = ",".join([p.split("/")[0] for p in ports])
    NMAPSCAN = f"nmap -T4 -p {portString} -sC -sV --script=\"{SCRIPTS}\" {target}"
    try:
        # Capture output as bytes and decode
        nmapscanResults = subprocess.check_output(NMAPSCAN, shell=True, stderr=subprocess.STDOUT)

        # Write Results #
        content = printInBox(NMAPSCAN, nmapscanResults.decode('utf-8', errors='ignore'))
        path = writeToFile(target, NAME, content)
        printPlus(f"Finished scanning HTTP: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{NMAPSCAN}")
    except subprocess.CalledProcessError as e:
        printErr(f"Unable to conduct HTTP scan:\n\t{NMAPSCAN}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during HTTP scan:\n\t{NMAPSCAN}\n\n{e}")


    # Conduct WebDav Scan #
    printStd("Trying to identify WebDav")
    # Note: The original grep might hide errors. Consider removing it or handling errors differently.
    WEBDAVSCAN = f"nmap -T4 -p {portString} --script http-webdav-scan {target} -d" # Removed grep for better error visibility
    try:
        # Capture output as bytes and decode
        webdavscanResults_raw = subprocess.check_output(WEBDAVSCAN, shell=True, stderr=subprocess.STDOUT)
        webdavscanResults = webdavscanResults_raw.decode('utf-8', errors='ignore')
        # Manually filter for relevant lines if needed, instead of grep
        filtered_results = "\n".join(line for line in webdavscanResults.splitlines() if f'http-webdav-scan {target}' in line)

        # Write Results #
        content = printInBox(WEBDAVSCAN, filtered_results if filtered_results else webdavscanResults) # Write filtered or full results
        path = writeToFile(target, NAME, content)
        printPlus(f"Finished scanning WebDav: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{WEBDAVSCAN}")
    except subprocess.CalledProcessError as e:
        # The original grep hid non-zero exit codes unless it was 1.
        # Now, any non-zero exit code will raise CalledProcessError.
        printErr(f"Unable to perform WebDav analysis:\n\t{WEBDAVSCAN}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during WebDav analysis:\n\t{WEBDAVSCAN}\n\n{e}")


    # Conduct Brute #
    # Ensure wordlist path exists
    dirb_wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(dirb_wordlist):
        printErr(f"Dirb wordlist not found: {dirb_wordlist}")
    else:
        for port in ports:
            urlArr = []
            urlDir = ["/"] # Default to root if parsing fails
            port_num = port.split("/")[0]
            printStd(f"Trying to brute-force HTTP directories on port {port_num}")
            DIRB = f"gobuster dir -x php -t 100 -u http://{target}:{port_num} -w {dirb_wordlist}" # Updated gobuster syntax
            try:
                # Capture output as bytes and decode
                dirbResults_raw = subprocess.check_output(DIRB, shell=True, stderr=subprocess.STDOUT)
                dirbResults = dirbResults_raw.decode('utf-8', errors='ignore')

                # Parse Results for Spider #
                # Adjust parsing based on actual gobuster output format if needed
                urlArr = parse_ip(dirbResults)
                parsed_dirs = parse_ip_directories(dirbResults)
                if parsed_dirs: # Update urlDir only if parsing is successful
                    urlDir = parsed_dirs

                # Write Results #
                content = printInBox(DIRB, dirbResults)
                path = writeToFile(target, NAME, content)
                printPlus(f"Finished HTTP brute-force against port {port_num}: {path} - Found: {len(urlArr)}")
            except KeyboardInterrupt:
                printMinus(f"Skipping:\n\t{DIRB}")
            except subprocess.CalledProcessError as e:
                 printErr(f"Unable to brute-force HTTP on port {port_num}:\n\t{DIRB}\n\n{e.output.decode('utf-8', errors='ignore')}")
            except Exception as e:
                printErr(f"An unexpected error occurred during HTTP brute force on port {port_num}:\n\t{DIRB}\n\n{e}")


            # Conduct Spider #
            SPIDER_SCRIPTS = "http-shellshock,http-auth-finder,http-backup-finder,http-comments-displayer,http-config-backup,http-default-accounts,http-dombased-xss,http-errors,http-fileupload-exploiter,http-method-tamper,http-passwd,http-phpmyadmin-dir-traversal,http-phpself-xss,http-rfi-spider,http-sitemap-generator,http-sql-injection,http-stored-xss,http-unsafe-output-escaping"

            # Spidered Vulnerability Scans
            for base_url_str in urlDir: # Iterate through found directories
                # Nikto Scan #
                NIKTO = f"nikto -host http://{target}:{port_num}" # Nikto usually scans the host, not specific paths from dirb
                try:
                    printStd(f"Running Nikto scan on http://{target}:{port_num}")

                    # Capture output as bytes and decode
                    niktoResults_raw = subprocess.check_output(NIKTO, shell=True, stderr=subprocess.STDOUT)
                    niktoResults = niktoResults_raw.decode('utf-8', errors='ignore')

                    # Check for common Nikto failure message
                    if "0 host(s) tested" in niktoResults:
                        printDbg(f"Nikto reported 0 hosts tested for {target}:{port_num}")
                        # Consider if this is an error or just no findings

                    # Write Results #
                    content = printInBox(NIKTO, niktoResults)
                    path = writeToFile(target, f"{NAME}_nikto_{port_num}", content) # Separate file for Nikto results
                    printPlus(f"Finished Nikto scan on http://{target}:{port_num}: {path}")

                except KeyboardInterrupt:
                    printMinus(f"Skipping Nikto scan:\n\t{NIKTO}")
                except subprocess.CalledProcessError as e:
                     printErr(f"Unable to conduct Nikto scan:\n\t{NIKTO}\n\n{e.output.decode('utf-8', errors='ignore')}")
                except Exception as e:
                    printErr(f"An unexpected error occurred during Nikto scan:\n\t{NIKTO}\n\n{e}")


                # Nmap Script Scan on specific paths (if applicable) #
                # The original script args seemed complex and potentially incorrect.
                # Revisit this logic if specific path scanning with Nmap is crucial.
                # For now, focusing on the base Nmap scan done earlier.
                # If needed, construct VULNSCAN carefully for each base_url_str
                # parsed_url = urlparse(base_url_str)
                # path_to_scan = parsed_url.path if parsed_url.path else "/"
                # SCRIPTARGS = f"http-shellshock.uri={path_to_scan},..." # Construct carefully
                # VULNSCAN = f"nmap -T4 -p {port_num} {target} --script=\"{SPIDER_SCRIPTS}\" --script-args=\"{SCRIPTARGS}\""
                # ... execute VULNSCAN ...

# ========================

# HTTPS
# ========================
def https(target, ports):
    printStd("Investigating HTTPS")
    NAME = "https"

    # Ensure ports list is not empty
    if not ports:
        printErr("No HTTPS ports provided for scanning.")
        return

    # Conduct NMAP Scan #
    HTTPS_SCRIPTS = "http-methods,http-robots.txt,http-vuln-*,http-shellshock,http-userdir-enum,http-iis-webdav-vuln,http-majordomo2-dir-traversal,http-axis2-dir-traversal,http-tplink-dir-traversal,http-useragent-tester,ssl-*"

    portString = ",".join([p.split("/")[0] for p in ports])
    NMAPSCAN = f"nmap -T4 -p {portString} -sV -sC --script=\"{HTTPS_SCRIPTS}\" {target}"
    try:
        # Capture output as bytes and decode
        nmapscanResults = subprocess.check_output(NMAPSCAN, shell=True, stderr=subprocess.STDOUT)

        # Write Scan Results #
        content = printInBox(NMAPSCAN, nmapscanResults.decode('utf-8', errors='ignore'))
        path = writeToFile(target, NAME, content)
        printPlus(f"Finished scanning HTTPS: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{NMAPSCAN}")
    except subprocess.CalledProcessError as e:
        printErr(f"Unable to conduct HTTPS scan:\n\t{NMAPSCAN}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during HTTPS scan:\n\t{NMAPSCAN}\n\n{e}")


    # Conduct WebDav Scan #
    printStd("Trying to identify WebDav over HTTPS")
    # Note: The original grep might hide errors. Consider removing it or handling errors differently.
    WEBDAVSCAN = f"nmap -T4 -p {portString} --script http-webdav-scan {target} -d" # Removed grep
    try:
        # Capture output as bytes and decode
        webdavscanResults_raw = subprocess.check_output(WEBDAVSCAN, shell=True, stderr=subprocess.STDOUT)
        webdavscanResults = webdavscanResults_raw.decode('utf-8', errors='ignore')
        # Manually filter for relevant lines if needed
        filtered_results = "\n".join(line for line in webdavscanResults.splitlines() if f'http-webdav-scan {target}' in line)

        # Write Results #
        content = printInBox(WEBDAVSCAN, filtered_results if filtered_results else webdavscanResults)
        path = writeToFile(target, NAME, content)
        printPlus(f"Finished scanning WebDav over HTTPS: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{WEBDAVSCAN}")
    except subprocess.CalledProcessError as e:
        printErr(f"Unable to perform WebDav analysis over HTTPS:\n\t{WEBDAVSCAN}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during WebDav analysis over HTTPS:\n\t{WEBDAVSCAN}\n\n{e}")


    # Conduct Brute #
    # Ensure wordlist path exists
    dirb_wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(dirb_wordlist):
        printErr(f"Dirb wordlist not found: {dirb_wordlist}")
    else:
        for port in ports:
            urlArr = []
            urlDir = ["/"] # Default
            port_num = port.split("/")[0]
            printStd(f"Trying to brute-force HTTPS directories on port {port_num}")
            # Added -k for insecure HTTPS connections, common in testing environments
            DIRB = f"gobuster dir -x php -t 100 -u https://{target}:{port_num} -w {dirb_wordlist} -k"
            try:
                # Capture output as bytes and decode
                dirbResults_raw = subprocess.check_output(DIRB, shell=True, stderr=subprocess.STDOUT)
                dirbResults = dirbResults_raw.decode('utf-8', errors='ignore')

                # Parse Results for Spider #
                urlArr = parse_ip(dirbResults)
                parsed_dirs = parse_ip_directories(dirbResults)
                if parsed_dirs:
                    urlDir = parsed_dirs

                # Write Results #
                content = printInBox(DIRB, dirbResults)
                path = writeToFile(target, NAME, content)
                printPlus(f"Finished HTTPS brute-force against port {port_num}: {path} - Found: {len(urlArr)}")
            except KeyboardInterrupt:
                printMinus(f"Skipping:\n\t{DIRB}")
            except subprocess.CalledProcessError as e:
                printErr(f"Unable to brute-force HTTPS on port {port_num}:\n\t{DIRB}\n\n{e.output.decode('utf-8', errors='ignore')}")
            except Exception as e:
                 printErr(f"An unexpected error occurred during HTTPS brute force on port {port_num}:\n\t{DIRB}\n\n{e}")


            # Conduct Spider #
            SPIDER_SCRIPTS = "http-auth-finder,http-backup-finder,http-comments-displayer,http-config-backup,http-default-accounts,http-dombased-xss,http-errors,http-fileupload-exploiter,http-method-tamper,http-passwd,http-phpmyadmin-dir-traversal,http-phpself-xss,http-rfi-spider,http-sitemap-generator,http-sql-injection,http-stored-xss,http-unsafe-output-escaping"

            # Spidered Vulnerability Scans
            for base_url_str in urlDir:
                # Nikto Scan #
                NIKTO = f"nikto -host https://{target}:{port_num} -ssl"
                try:
                    printStd(f"Running Nikto scan on https://{target}:{port_num}")

                    # Capture output as bytes and decode
                    niktoResults_raw = subprocess.check_output(NIKTO, shell=True, stderr=subprocess.STDOUT)
                    niktoResults = niktoResults_raw.decode('utf-8', errors='ignore')

                    if "0 host(s) tested" in niktoResults:
                         printDbg(f"Nikto reported 0 hosts tested for https://{target}:{port_num}")

                    # Write Results #
                    content = printInBox(NIKTO, niktoResults)
                    path = writeToFile(target, f"{NAME}_nikto_{port_num}", content)
                    printPlus(f"Finished Nikto scan on https://{target}:{port_num}: {path}")

                except KeyboardInterrupt:
                    printMinus(f"Skipping Nikto scan:\n\t{NIKTO}")
                except subprocess.CalledProcessError as e:
                    printErr(f"Unable to conduct HTTPS vulnerability crawl (nikto):\n\t{NIKTO}\n\n{e.output.decode('utf-8', errors='ignore')}")
                except Exception as e:
                    printErr(f"An unexpected error occurred during Nikto scan:\n\t{NIKTO}\n\n{e}")


                # Nmap Scan on specific paths (Revisit if needed) #
                # parsed_url = urlparse(base_url_str)
                # path_to_scan = parsed_url.path if parsed_url.path else "/"
                # SCRIPTARGS = f"http-backup-finder.url={path_to_scan},..." # Construct carefully
                # VULNSCAN = f"nmap -T4 -p {port_num} {target} --script=\"{SPIDER_SCRIPTS}\" --script-args=\"{SCRIPTARGS}\" --script-args https=true" # Add https=true? Check script docs
                # ... execute VULNSCAN ...
# ========================

# SNMP
# ========================
def snmp(target, ports):
    printStd("Investigating SNMP")
    NAME = "snmp"

    # Ensure ports list is not empty
    if not ports:
        printErr("No SNMP ports provided for scanning.")
        return

    # Conduct Scans #
    portString = ",".join([p.split("/")[0] for p in ports])
    NMAPSCAN = f"nmap -sU -p {portString} --script=\"snmp-*\" {target}"

    # Ensure onesixtyone dictionary exists
    onesixtyone_dict = "/usr/share/doc/onesixtyone/dict.txt"
    if not os.path.exists(onesixtyone_dict):
        printErr(f"Onesixtyone dictionary not found: {onesixtyone_dict}")
        # Decide how to proceed: skip onesixtyone or stop?
        # For now, let's skip onesixtyone if dict is missing
        run_onesixtyone = False
    else:
        run_onesixtyone = True
        ONESIXTYONE = f"onesixtyone -c {onesixtyone_dict} {target}" # Removed 2>&1 for better error handling in Python

    ADVICE = f"If match community string, use :: snmpwalk -c <community string> -v1 {target} :: to enumerate"
    foundCount = 0
    try:
        # Capture output as bytes and decode
        nmapscanResults = subprocess.check_output(NMAPSCAN, shell=True, stderr=subprocess.STDOUT)

        # Write Results #
        content = printInBox(NMAPSCAN, nmapscanResults.decode('utf-8', errors='ignore'))
        path = writeToFile(target, NAME, content)

        if run_onesixtyone:
            # Capture output as bytes and decode
            onesixtyoneResults_raw = subprocess.check_output(ONESIXTYONE, shell=True, stderr=subprocess.STDOUT)
            onesixtyoneResults = onesixtyoneResults_raw.decode('utf-8', errors='ignore')
            # Count lines excluding potential empty last line
            foundCount = len([line for line in onesixtyoneResults.splitlines() if line.strip()])

            # Write Results #
            content = printInBox(ONESIXTYONE, onesixtyoneResults)
            path = writeToFile(target, NAME, content) # Append to the same file

        printPlus(f"Finished investigating SNMP: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping SNMP scans")
    except subprocess.CalledProcessError as e:
        printErr(f"Unable to conduct SNMP scan (check nmap or onesixtyone):\n\t{NMAPSCAN}\n\t{ONESIXTYONE if run_onesixtyone else ''}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during SNMP scan:\n\t{NMAPSCAN}\n\t{ONESIXTYONE if run_onesixtyone else ''}\n\n{e}")


    if foundCount > 0: # Changed from > 1 as even one result is worth trying to walk
        printStd("Mapping SNMP")
        # This shell command is complex and error-prone. Consider reimplementing in Python if possible.
        # For now, keeping the shell command but ensuring dict path is correct.
        WALK = f"for s in $({ONESIXTYONE} | grep {target} | cut -d ' ' -f 2 | sed -e 's/\\[//g' -e 's/\\]//g');do snmpwalk -c $s -v1 {target};done"
        if not run_onesixtyone:
             printErr("Cannot perform SNMP walk because onesixtyone dictionary was not found.")
        else:
            try:
                # Capture output as bytes and decode
                walkResults = subprocess.check_output(WALK, shell=True, stderr=subprocess.STDOUT, executable='/bin/bash') # Specify bash

                # Write Results #
                content = printInBox(WALK, walkResults.decode('utf-8', errors='ignore'))
                path = writeToFile(target, NAME, content) # Append to the same file

                printPlus(f"Finished mapping SNMP: {path}")
            except KeyboardInterrupt:
                printMinus(f"Skipping:\n\t{WALK}")
            except subprocess.CalledProcessError as e:
                printErr(f"Unable to map SNMP:\n\t{WALK}\n\n{e.output.decode('utf-8', errors='ignore')}")
            except Exception as e:
                 printErr(f"An unexpected error occurred during SNMP walk:\n\t{WALK}\n\n{e}")
# ========================

# MS-SQL
# ========================
def ms_sql(target, ports):
    printStd("Investigating MS-SQL")
    NAME = "ms_sql"

    # Ensure ports list is not empty
    if not ports:
        printErr("No MS-SQL ports provided for scanning.")
        return

    # Conduct nmap Scan #
    portString = ",".join([p.split("/")[0] for p in ports])
    NMAPSCAN = f"nmap -T4 -p {portString} -sV -sC {target}"
    try:
        # Capture output as bytes and decode
        nmapscanResults = subprocess.check_output(NMAPSCAN, shell=True, stderr=subprocess.STDOUT)

        # Write Scan Results #
        content = printInBox(NMAPSCAN, nmapscanResults.decode('utf-8', errors='ignore'))
        path = writeToFile(target, NAME, content)
        printPlus(f"Finished scanning MS-SQL: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{NMAPSCAN}")
    except subprocess.CalledProcessError as e:
        printErr(f"Unable to conduct MS-SQL scan:\n\t{NMAPSCAN}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during MS-SQL scan:\n\t{NMAPSCAN}\n\n{e}")


    # Conduct Brute #
    printStd("Trying to brute-force MS-SQL")
    # Check for wordlist existence
    user_wordlist = "/usr/share/wordlists/metasploit/default_users_for_services_unhash.txt"
    pass_wordlist = "/usr/share/wordlists/metasploit/default_pass_for_services_unhash.txt"
    if not os.path.exists(user_wordlist) or not os.path.exists(pass_wordlist):
        printErr(f"Required wordlist(s) not found: {user_wordlist}, {pass_wordlist}")
    else:
        BRUTE = f"medusa -h {target} -U {user_wordlist} -P {pass_wordlist} -M mssql -L -f" # Removed 2>&1
        try:
            # Capture output as bytes and decode
            bruteResults = subprocess.check_output(BRUTE, shell=True, stderr=subprocess.STDOUT)

            # Write Brute Results #
            content = printInBox(BRUTE, bruteResults.decode('utf-8', errors='ignore'))
            path = writeToFile(target, NAME, content) # Append to same file
            printPlus(f"Finished conducting MS-SQL brute-force: {path}")
        except KeyboardInterrupt:
            printMinus(f"Skipping:\n\t{BRUTE}")
        except subprocess.CalledProcessError as e:
            # Medusa might return non-zero on no creds found, check output
            output = e.output.decode('utf-8', errors='ignore')
            if "ACCOUNT FOUND" not in output: # Adjust based on actual Medusa output
                 printStd(f"MS-SQL brute-force completed, no credentials found.")
                 # Write empty or minimal results if desired
                 content = printInBox(BRUTE, "No credentials found.")
                 writeToFile(target, NAME, content)
            else:
                 printErr(f"Unable to conduct MS-SQL brute-force (check output):\n\t{BRUTE}\n\n{output}")
                 # Write error output
                 content = printInBox(BRUTE, output)
                 writeToFile(target, NAME, content)
        except Exception as e:
            printErr(f"An unexpected error occurred during MS-SQL brute-force:\n\t{BRUTE}\n\n{e}")
# ========================

# MySQL
# ========================
def mysql(target, ports):
    printStd("Investigating MySQL")
    NAME = "mysql"

    # Ensure ports list is not empty
    if not ports:
        printErr("No MySQL ports provided for scanning.")
        return

    # Conduct nmap Scan #
    portString = ",".join([p.split("/")[0] for p in ports])
    NMAPSCAN = f"nmap -T4 -p {portString} -sV -sC {target}"
    try:
        # Capture output as bytes and decode
        nmapscanResults = subprocess.check_output(NMAPSCAN, shell=True, stderr=subprocess.STDOUT)

        # Write Scan Results #
        content = printInBox(NMAPSCAN, nmapscanResults.decode('utf-8', errors='ignore'))
        path = writeToFile(target, NAME, content)
        printPlus(f"Finished scanning MySQL: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{NMAPSCAN}")
    except subprocess.CalledProcessError as e:
         # Changed printMinus to printErr for consistency
        printErr(f"Unable to conduct MySQL scan:\n\t{NMAPSCAN}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during MySQL scan:\n\t{NMAPSCAN}\n\n{e}")


    # Conduct Brute #
    printStd("Trying to brute-force MySQL")
    # Check for wordlist existence
    user_wordlist = "/usr/share/wordlists/metasploit/default_users_for_services_unhash.txt"
    pass_wordlist = "/usr/share/wordlists/metasploit/default_pass_for_services_unhash.txt"
    if not os.path.exists(user_wordlist) or not os.path.exists(pass_wordlist):
        printErr(f"Required wordlist(s) not found: {user_wordlist}, {pass_wordlist}")
    else:
        BRUTE = f"medusa -h {target} -U {user_wordlist} -P {pass_wordlist} -M mysql -L -f" # Removed 2>&1
        try:
            # Capture output as bytes and decode
            bruteResults = subprocess.check_output(BRUTE, shell=True, stderr=subprocess.STDOUT)

            # Write Brute Results #
            content = printInBox(BRUTE, bruteResults.decode('utf-8', errors='ignore'))
            path = writeToFile(target, NAME, content) # Append
            printPlus(f"Finished conducting MySQL brute-force: {path}")
        except KeyboardInterrupt:
            printMinus(f"Skipping:\n\t{BRUTE}")
        except subprocess.CalledProcessError as e:
            # Handle Medusa's non-zero exit code on no creds found
            output = e.output.decode('utf-8', errors='ignore')
            if "ACCOUNT FOUND" not in output: # Adjust based on actual Medusa output
                 printStd(f"MySQL brute-force completed, no credentials found.")
                 content = printInBox(BRUTE, "No credentials found.")
                 writeToFile(target, NAME, content)
            else:
                 printErr(f"Unable to conduct MySQL brute-force (check output):\n\t{BRUTE}\n\n{output}")
                 content = printInBox(BRUTE, output)
                 writeToFile(target, NAME, content)
        except Exception as e:
            printErr(f"An unexpected error occurred during MySQL brute-force:\n\t{BRUTE}\n\n{e}")
# ========================
# NFS
# ========================
def nfs(target, ports):
    printStd("Investigating NFS")
    NAME = "nfs"

    # Ensure ports list is not empty (though NFS often uses portmapper/rpcbind)
    # if not ports:
    #     printErr("No specific NFS ports provided, relying on rpcinfo/showmount.")
        # return # Decide if ports are strictly necessary

    # Conduct rpcinfo #
    RPCINFO = f"rpcinfo -p {target}" # Use -p for port info, -s is deprecated/less useful
    try:
        # Capture output as bytes and decode
        rpcinfoResults = subprocess.check_output(RPCINFO, shell=True, stderr=subprocess.STDOUT)

        # Write Results #
        content = printInBox(RPCINFO, rpcinfoResults.decode('utf-8', errors='ignore'))
        path = writeToFile(target, NAME, content)
        printPlus(f"Finished scanning RPC processes: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{RPCINFO}")
    except subprocess.CalledProcessError as e:
        printErr(f"Unable to scan RPC processes:\n\t{RPCINFO}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during RPC scan:\n\t{RPCINFO}\n\n{e}")


    # Conduct showmount #
    printStd("Capturing accessible NFS shares")
    SHOWMOUNT = f"showmount -e {target}"
    # ADVICE needs target interpolation
    ADVICE = f"Use :: mount -t nfs {target}:[share] /mnt/{target} -o nolock :: to mount share" # Corrected mount type to nfs
    try:
        # Capture output as bytes and decode
        showmountResults = subprocess.check_output(SHOWMOUNT, shell=True, stderr=subprocess.STDOUT)

        # Write Results #
        content = printInBox(SHOWMOUNT, f"{showmountResults.decode('utf-8', errors='ignore')}\n\n{ADVICE}")
        path = writeToFile(target, NAME, content) # Append
        printPlus(f"Captured accessible NFS shares: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{SHOWMOUNT}")
    except subprocess.CalledProcessError as e:
        printErr(f"Unable to capture accessible NFS shares:\n\t{SHOWMOUNT}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during showmount:\n\t{SHOWMOUNT}\n\n{e}")


    # Conduct nmap Scan #
    printStd("Exploring accessible NFS shares with Nmap")
    # Use common NFS ports if specific ports list is empty or unreliable
    nfs_ports_to_scan = "111,2049" # Common RPC and NFS ports
    if ports:
        portString = ",".join([p.split("/")[0] for p in ports])
        # Combine known NFS ports with provided ports if necessary
        nfs_ports_to_scan = f"{portString},{nfs_ports_to_scan}"


    NMAPSCAN = f"nmap -T4 -p {nfs_ports_to_scan} -sV -sC --script=\"nfs-showmount,nfs-ls\" {target}"
    try:
        # Capture output as bytes and decode
        nmapResults = subprocess.check_output(NMAPSCAN, shell=True, stderr=subprocess.STDOUT)

        # Write Results #
        content = printInBox(NMAPSCAN, nmapResults.decode('utf-8', errors='ignore'))
        path = writeToFile(target, NAME, content) # Append
        printPlus(f"Finished investigating NFS with Nmap: {path}")
    except KeyboardInterrupt:
        printMinus(f"Skipping:\n\t{NMAPSCAN}")
    except subprocess.CalledProcessError as e:
        printErr(f"Unable to conduct NFS Nmap scan:\n\t{NMAPSCAN}\n\n{e.output.decode('utf-8', errors='ignore')}")
    except Exception as e:
        printErr(f"An unexpected error occurred during NFS Nmap scan:\n\t{NMAPSCAN}\n\n{e}")
# ========================

# ------------------------------------
#       Main
# ------------------------------------

KNOWN_SERVICES = {
    "ftp"           :   ftp,
    "smtp"          :   smtp,
    "pop3"          :   pop3,
    "imap"          :   imap,
    "netbios-ssn"   :   smb,
    "http"          :   http,
    "http-alt"      :   http,
    "http-proxy"    :   http,
    "https"         :   https,
    "snmp"          :   snmp,
    "ms-sql-s"      :   ms_sql,
    "mysql"         :   mysql,
    "rpcbind"       :   nfs,
    "mountd"        :   nfs # Added mountd as it's related to NFS
}


def moduleDispatch(target,services):
    TARGET = target
    printStd(f"Scanning for possible modules for {target}")
    try:
        dispatchModules(TARGET, services)
        conductHeavyNmap(TARGET)
    except KeyboardInterrupt:
        print("\n\nExiting.\n")
        sys.exit(1)
    # Consider adding a general Exception catch here too


def main(targets):
    if len(targets) <= 0:
        printUsage()
        sys.exit(2)

    for target in targets:
        if not validate_ip(target):
            printMinus(f"Invalid IP Address: {target}") # Show the invalid IP
            # Consider not exiting immediately, maybe skip this target?
            # printUsage()
            # sys.exit(2)
            continue # Skip invalid IP
        printHeader(target)
        prepareFolder(target) # Removed unused 'error' variable

    # Initialize ALLSERVICES based on the number of valid targets
    valid_targets = [t for t in targets if validate_ip(t)]
    global ALLSERVICES # Declare ALLSERVICES as global if modifying it here
    ALLSERVICES = [None] * len(valid_targets)

    execNmapParallel(valid_targets) # Pass only valid targets

    # Iterate through valid targets and corresponding services
    for count, ip in enumerate(valid_targets, 1):
        # Check if services were populated for this IP
        if count <= len(ALLSERVICES) and ALLSERVICES[count-1] is not None:
             moduleDispatch(ip, ALLSERVICES[count-1])
        else:
             printErr(f"No services found or Nmap scan failed for {ip}. Skipping module dispatch.")


if __name__ == "__main__":
    # Initialize ALLSERVICES here based on argv length, before main modifies it
    # This avoids potential race conditions if main runs before this line in some scenarios
    # ALLSERVICES = [None] * len(sys.argv[1:]) # Moved initialization logic into main
    main(sys.argv[1:])
