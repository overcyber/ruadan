#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Ruadan
# Root2Boot automation platform designed to systematically enumernate and exploit using the law of diminishing returns
# DONE: Automate DNS Name lookup NMap XML generation upon discovering a DNS server
# DONE: remove upfront_scan_hosts funciton and merge with enumerate function
# DONE: Import data into MSF database and generate pretty table reports of servers and ports
# DONE: Combine scanning and information gathering loops
# DONE: Create custom password word list from CEWL URL Findings, Users, domains, groups, ComputerName
# DONE: Installer script and setup

# TODO: Seclist directory enumeration orchestation / Seclist user enumeration / Seclist brute forcing
# TODO: Add some FILTERED port results back in if they prodivde enumeration value (MongoDB)
# TODO: Attack plans config associated with one or more Config files - simplify - only specify an attack plan and a target
# TODO: Load findings from files here for merging - dont overwrite user added findings...
# TODO: SMB Hydra is running twice - 139 and 445 - 445 is the only service that returns results - STOP hydra from running 139
# TODO: Pipe any SMB credentials found back into Enum4Linux
# TODO: Command to parse credential findings from Hydra and parse them into ../credentals.txt
# TODO: The findings list can also leverage a regular expression to extract a substring from each line of a findings file
# TODO: remove exploit search function and merge with enumerate function
# TODO: getting false positives from Nikto - Nmap0
# -0.Shell Shock Script against specific folder paths
# nmap 10.11.1.71 -p 80 \
#  --script=http-shellshock \
#  --script-args uri=/cgi-bin/test.cgi --script-args uri=/cgi-bin/admin.cgi
# TODO: Exploit Apache Mod CGI - cp /usr/share/exploitdb/platforms/linux/remote/34900.py ./Documents/EXploitz/Apache_Mod_CGI.py
# TODO: shell shock exploit curl -H 'User-Agent: () { :; }; echo "CVE-2014-6271 vulnerable" bash -c id' http://10.11.1.71/cgi-bin/admin.cgi
# TODO: Append the exact command that is used to the output text files for easy refernce in documentation
# TODO: Create a suggest only mode that dumps a list of commands to try rather than running anything
# TODO: Add color and -color -colour flags to disable it

# TODO: Finish exploitation dynamic replacements from user credentials list
# TODO: More to be done with HTTP enumeration and service identification / exploit searches
# TODO: Move HTTP_NMAP_WEB_SCAN
# TODO: Add config file findings replacers to run on findings after initial results to clean up data for further enumeration (ex. user credentials, and whatweb service findings)
# TODO: hash / bas64 finder / flag post process searching
# TODO: Nmap http enum - include?  or is this redundant at this point?
# TODO: Add Metasploit style summary table with number of services, commands, phases etc.
# 1. NMAP Scan
# 2. Service Enumeration Scan
# 3. Finds relavant exploits and copies to a subfolder
# 3. Word list creation 1st pass
#       Banner Grabx
#       HTTP Enum
#       TODO: Spider site
#       TODO: HTTP Download all assets
#       TODO: Image Scan - Meta / Steg / OCRd
#       TODO: Grab screen shots of pages found
#       Create Site Map txt file for all assets
#       Create Wordlist version1
#
# 4. Service Enumeration with Word List
# 5. Bruteforcing with word list
# 6. Mutation of word list service enumeration
# 7. Bruteforcing with mutation
#
#


"""
Main application logic and automation functions
"""

__version__ = '0.29'
__lastupdated__ = 'March 18, 2018'
__nmap_folder__ = 'Nmap'
__findings_label__ = 'findings'
__accounce_label__ = 'announce'
__password_list_label__ = 'passwordlist'
__urlshttp_list_label__ = 'urlshttp'
__urlshttps_list_label__ = 'urlshttps'
__findings_label_dynamic__ = 'Findings'
__findings_label_list_dynamic__ = 'FindingsList'

###
# Imports
###
import fnmatch
import os
import sys
import time
import re
import socket
import urllib.parse
import configparser as ConfigParser
import argparse
import random
import operator
from pprint import pformat
from pprint import pprint
from shutil import copyfile
import json
import xml.etree.ElementTree as ET
from multiprocessing.dummy import Pool as ThreadPool
import subprocess
from subprocess import Popen, PIPE, STDOUT, DEVNULL
from datetime import datetime

# PROGRESS BAR - Thank you! clint.textui.progress
BAR_TEMPLATE = '%s[%s%s] %i/%i - %s\r'
DOTS_CHAR = '.'
BAR_FILLED_CHAR = '#'
BAR_EMPTY_CHAR = ' '
ETA_INTERVAL = 1
ETA_SMA_WINDOW = 9
STREAM = sys.stderr


class Bar(object):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.done()
        return False  # we're not suppressing exceptions

    def __init__(self, label='', width=32, hide=None, empty_char=BAR_EMPTY_CHAR,
                 filled_char=BAR_FILLED_CHAR, expected_size=None, every=1):
        self.label = label
        self.width = width
        self.hide = hide
        # Only show bar in terminals by default (better for piping, logging etc.)
        if hide is None:
            try:
                self.hide = not STREAM.isatty()
            except AttributeError:  # output does not support isatty()
                self.hide = True
        self.empty_char = empty_char
        self.filled_char = filled_char
        self.expected_size = expected_size
        self.every = every
        self.start = time.time()
        self.ittimes = []
        self.eta = 0
        self.etadelta = time.time()
        self.etadisp = self.format_time(self.eta)
        self.last_progress = 0
        if self.expected_size:
            self.show(0)

    def show(self, progress, count=None):
        if count is not None:
            self.expected_size = count
        if self.expected_size is None:
            raise Exception("expected_size not initialized")
        self.last_progress = progress
        if (time.time() - self.etadelta) > ETA_INTERVAL:
            self.etadelta = time.time()
            self.ittimes = \
                self.ittimes[-ETA_SMA_WINDOW:] + \
                [-(self.start - time.time()) / (progress + 1)]
            self.eta = \
                sum(self.ittimes) / float(len(self.ittimes)) * \
                (self.expected_size - progress)
            self.etadisp = self.format_time(self.eta)
        x = int(self.width * progress / self.expected_size) if self.expected_size else 0
        if not self.hide:
            if ((progress % self.every) == 0 or  # True every "every" updates
                    (progress == self.expected_size)):  # And when we're done
                STREAM.write(BAR_TEMPLATE % (
                    self.label, self.filled_char * x,
                    self.empty_char * (self.width - x), progress,
                    self.expected_size, self.etadisp))
                STREAM.flush()

    def done(self):
        self.elapsed = time.time() - self.start
        elapsed_disp = self.format_time(self.elapsed)
        if not self.hide:
            # Print completed bar with elapsed time
            STREAM.write(BAR_TEMPLATE % (
                self.label, self.filled_char * self.width,
                self.empty_char * 0, self.last_progress,
                self.expected_size, elapsed_disp))
            STREAM.write('\n')
            STREAM.flush()

    def format_time(self, seconds):
        return time.strftime('%H:%M:%S', time.gmtime(seconds))


def bar(it, label='', width=32, hide=None, empty_char=BAR_EMPTY_CHAR,
        filled_char=BAR_FILLED_CHAR, expected_size=8, every=1):
    with Bar(label=label, width=width, hide=hide, empty_char=BAR_EMPTY_CHAR,
             filled_char=BAR_FILLED_CHAR, expected_size=expected_size, every=every) \
            as pbar:
        for i, item in enumerate(it):
            yield item
            pbar.show(i + 1)


class Logger:
    DEBUG = False
    VERBOSE = False
    DEBUG_FILE = None
    VERBOSE_FILE = None

    @staticmethod
    def debug(msg):
        if Logger.DEBUG_FILE is not None:
            Logger.DEBUG_FILE.write(msg + '\n')
            Logger.DEBUG_FILE.flush()
        elif Logger.DEBUG is True:
            print("[!] " + msg)

    @staticmethod
    def verbose(msg):
        if Logger.VERBOSE_FILE is not None:
            Logger.VERBOSE_FILE.write(msg + '\n')
            Logger.VERBOSE_FILE.flush()
        elif Logger.VERBOSE is True:
            print("[*] " + msg)


class Color:

    ENABLE_COLOR = True

    @staticmethod
    def redback():
        if Color.ENABLE_COLOR:
            return "\033[0m\033[37m\033[41m"
        else:
            return ""

    @staticmethod
    def black():
        if Color.ENABLE_COLOR:
            return '\033[0;30m'
        else:
            return ""

    @staticmethod
    def red():
        if Color.ENABLE_COLOR:
            return '\033[0;31m'
        else:
            return ""

    @staticmethod
    def green():
        if Color.ENABLE_COLOR:
            return '\033[0;32m'
        else:
            return ""

    @staticmethod
    def yellow():
        if Color.ENABLE_COLOR:
            return '\033[0;33m'
        else:
            return ""

    @staticmethod
    def blue():
        if Color.ENABLE_COLOR:
            return '\033[0;34m'
        else:
            return ""

    @staticmethod
    def magenta():
        if Color.ENABLE_COLOR:
            return '\033[0;35m'
        else:
            return ""

    @staticmethod
    def cyan():
        if Color.ENABLE_COLOR:
            return '\033[0;36m'
        else:
            return ""

    @staticmethod
    def grey():
        if Color.ENABLE_COLOR:
            return '\033[0;37m'
        else:
            return ""

    @staticmethod
    def white():
        if Color.ENABLE_COLOR:
            return '\033[0;38m'
        else:
            return ""

    @staticmethod
    def reset():
        if Color.ENABLE_COLOR:
            return '\033[0;39m'
        else:
            return ""


class Ruadan:
    def __init__(self, argv):
        self.banner()
        print(Color.green() + "Ruadan Version: " + __version__ + " Updated: " + __lastupdated__ + Color.reset())
        self.parser = argparse.ArgumentParser(
            description='Ruadan is Kali Linux based Enumeration and Pre-exploration Orchestrator.')
        self.parser.add_argument("-install", action='store_true',
                                 help="Install Ruadan and it's requirements")
        self.parser.add_argument("-outputFolder", metavar='folder', type=str, default="",
                                 help='output folder path (default: name of the host file))')
        self.parser.add_argument("-configFile", metavar='file', type=str, default="config.ini",
                                 help='configuration ini file (default: %(default)s)')
        self.parser.add_argument("-attackPlanFile", metavar='file', type=str, default="attackplan.ini",
                                 help='attack plan ini file (default: %(default)s)')
        self.parser.add_argument("-hostFile", metavar='file', type=str, default="targets/hosts.txt",
                                 help='list of hosts to attack (default: %(default)s)')
        self.parser.add_argument("-workspace", metavar='workspace', type=str, default="",
                                 help='Metasploit workspace to import data into (default: is the host filename)')
        self.parser.add_argument("-domain", metavar='domain', type=str, default="megacorpone.com",
                                 help='Domain to be used in DNS enumeration (default: %(default)s)')
        self.parser.add_argument("-dnsServer", metavar='dnsServer', type=str, default="",
                                 help='DNS server option to use with Nmap DNS enumeration. Reveals the host names of'
                                      ' each server (default: %(default)s)')
        self.parser.add_argument("-proxy", metavar='proxy', type=str, default="",
                                 help='Proxy server option to use with scanning tools that support proxies. Should be '
                                      ' in the format of ip:port (default: %(default)s)')
        self.parser.add_argument("-reportFile", metavar='report', type=str, default="report.txt",
                                 help='filename used for the report (default: %(default)s)')
        self.parser.add_argument("-noResume", action='store_true', help='do not resume a previous session')
        self.parser.add_argument("-noColor", action='store_true', help='do not display color')
        self.parser.add_argument("-threadPool", metavar='threads', type=int, default="8",
                                 help='Thread Pool Size (default: %(default)s)')
        self.parser.add_argument("-phase", metavar='phase', type=str, default='', help='only execute a specific phase')
        self.parser.add_argument("-noExploitSearch", action='store_true', help='disable searchspolit exploit searching')
        self.parser.add_argument("-benchmarking", action='store_true',
                                 help='enable bench mark reporting on the execution time of commands(exports '
                                      'to benchmark.csv)')
        self.parser.add_argument("-logging", action='store_true', help='enable verbose and debug data logging to files')
        self.parser.add_argument("-verbose", action='store_true', help='display verbose details during the scan')
        self.parser.add_argument("-debug", action='store_true', help='display debug details during the scan')
        self.parser.add_argument("-ai", action='store_true', help='enable autonomous AI orchestration (RL + Multi-LLM)')
        self.parser.add_argument("-llmProvider", type=str, default="ollama",
                                 choices=['ollama', 'google', 'openai', 'anthropic', 'deepseek', 'nvidia'],
                                 help='LLM provider for AI orchestration (default: %(default)s)')
        self.parser.add_argument("-llmModel", type=str, default=None,
                                 help='specific model name for LLM provider (default: provider default)')
        self.parser.add_argument("-checkpoint", type=str, default="/app/checkpoints/maestro_red_ep1246800.pt",
                                 help='path to RL policy checkpoint (.pt)')
        self.parser.add_argument("-aiSteps", type=int, default=40,
                                 help='maximum steps for autonomous AI orchestration (default: %(default)s)')

        self.args = self.parser.parse_args(argv)

        # Smart hostFile path resolution across Docker and local layouts
        hf_raw = self.args.hostFile
        if isinstance(hf_raw, str):
            this_dir = os.path.dirname(os.path.abspath(__file__))
            # Candidatos DERIVADOS do caminho que o usuário pediu (específicos)
            derived_candidates = [
                hf_raw,
                os.path.join(os.getcwd(), hf_raw),
                os.path.join(this_dir, hf_raw),
                os.path.join("/ruadan", hf_raw),
                os.path.join("/app", hf_raw),
                os.path.join("/app/ruadan", hf_raw),
                os.path.join(this_dir, "targets", os.path.basename(hf_raw)),
                os.path.join("/ruadan/targets", os.path.basename(hf_raw)),
                os.path.join("/targets", os.path.basename(hf_raw)),
                os.path.join("/root_targets", os.path.basename(hf_raw)),
                os.path.join(os.getcwd(), "targets", os.path.basename(hf_raw)),
            ]
            # Fallbacks GENÉRICOS (hosts.txt) — só são aceitos quando o usuário
            # NÃO especificou um hostFile próprio (comando inválido com alvo
            # inexistente JAMAIS deve cair em alvos genéricos silenciosamente!)
            generic_candidates = [
                "/ruadan/targets/hosts.txt",
                "/app/ruadan/targets/hosts.txt",
                "/targets/hosts.txt",
                "targets/hosts.txt",
                "hosts.txt"
            ]
            _hostfile_default = "targets/hosts.txt"
            _explicit = (hf_raw != _hostfile_default)
            resolved = None
            for c in derived_candidates:
                if os.path.isfile(c):
                    resolved = c
                    break
            if resolved is None and not _explicit:
                # sem -hostFile no comando: fallback ao hosts.txt default é legítimo
                for c in generic_candidates:
                    if os.path.isfile(c):
                        resolved = c
                        break
            if resolved is None:
                if _explicit:
                    print(Color.red() + "[-] ERRO FATAL: o hostFile '%s' (especificado no comando) NÃO existe em nenhum "
                          "caminho conhecido. Abortando — refusing alvos genéricos." % hf_raw + Color.reset())
                    print(Color.red() + "    Dica: verifique o caminho/arquivo (targets/ do repo: ruadan/targets/)." + Color.reset())
                else:
                    print(Color.red() + "[-] ERRO FATAL: nenhum hostFile encontrado (nem hosts.txt default). Abortando." + Color.reset())
                sys.exit(2)
            if resolved != hf_raw and os.path.abspath(resolved) != os.path.abspath(hf_raw):
                print(Color.yellow() + "[!] AVISO: hostFile '%s' não encontrado. Usando fallback: '%s'" % (hf_raw, resolved) + Color.reset())
            self.args.hostFile = resolved

        self.hosts = self.args.hostFile

        # Installation Setup
        if self.args.install:
            self.args.configFile = "install.ini"
            self.args.attackPlanFile = "installplan.ini"

        # load config
        self.config = ConfigParser.ConfigParser(interpolation=None, strict=False)
        self.config.read(self.args.configFile, encoding='utf-8')

        Logger.VERBOSE = (self.config.getboolean("System", "Verbose") if self.config.has_option("System", "Verbose") else False) or self.args.verbose
        Logger.DEBUG = (self.config.getboolean("System", "Debug") if self.config.has_option("System", "Debug") else False) or self.args.debug

        # Hostfile basename string for folders and naming
        hf_basename = os.path.basename(self.args.hostFile.name if hasattr(self.args.hostFile, 'name') else str(self.args.hostFile)).split(".")[0]

        # Default output location
        if self.args.outputFolder == "":
            self.args.outputFolder = "." + os.path.sep + hf_basename

        # Nmap scan output folder
        self.nmap_path = os.path.join(self.args.outputFolder, __nmap_folder__)

        # Check folder for existing output and nmap folders
        if not os.path.exists(self.args.outputFolder):
            os.makedirs(self.args.outputFolder)
        elif not self.args.noResume:
            print(Color.yellow() + "[*]" + Color.reset() + " Resuming previous session")

        if not os.path.exists(self.nmap_path):
            os.makedirs(self.nmap_path)

        if self.args.noColor:
            Color.ENABLE_COLOR = False

        # Metasploit workspace name - the workspace name is the name of the host file minus its extension
        if self.args.workspace == "":
            self.workspace = hf_basename
        else:
            self.workspace = self.args.workspace

        # load attack plan
        self.plan = ConfigParser.ConfigParser(interpolation=None, strict=False)
        self.plan.read(self.args.attackPlanFile, encoding='utf-8')

        self.nmap_dns_server = ""
        if self.args.dnsServer != "":
            self.nmap_dns_server = " --dns-server " + self.args.dnsServer

        self.proxy_server = ""
        if self.args.proxy != "":
            self.proxy_server = " --proxy " + self.args.proxy

        # Master NMAP Data Structure Dict
        self.nmap_dict = {}
        self.host_to_ip = {}
        self.ip_to_host = {}
        self.target_urls = {}

        # current enumeration phase command que
        self.phase_commands = []

        # announced vulnerabilities - Prevent findings from being reported multiple times
        self.announced = {}
        # calculate risk scores as we enumerate
        self.risk_score = {}
        # track that these commands are only run once per phase
        self.run_once = {}

        # Current Thread Pool command contents
        self.thread_pool_commands = []
        self.thread_pool_errors = []

        # Lists discovered during enumeration
        self.findings = {'users': [], 'urls': [], 'groups': [], 'passwords': [], 'vulnerabilities': []}

        # write errors to error log inside outputFolder rather than polluting cwd
        err_log_path = os.path.join(self.args.outputFolder, "commanderrorlog.txt")
        try:
            self.command_error_log = open(err_log_path, 'w', encoding='utf-8', errors='ignore')
        except OSError:
            self.command_error_log = open(os.devnull, 'w')

        self.active_commands = os.path.join(self.args.outputFolder, "activecommands.txt")
        self.debug_log = None
        self.verbose_log = None
        if self.args.logging:
            try:
                self.debug_log = open(os.path.join(self.args.outputFolder, "debuglog.txt"), 'w', encoding='utf-8', errors='ignore')
                self.verbose_log = open(os.path.join(self.args.outputFolder, "verboselog.txt"), 'w', encoding='utf-8', errors='ignore')
                Logger.DEBUG_FILE = self.debug_log
                Logger.VERBOSE_FILE = self.verbose_log
            except OSError:
                pass

        self.benchmarking_csv = None
        if self.args.benchmarking:
            try:
                self.benchmarking_csv = open(os.path.join(self.args.outputFolder, "benchmark.csv"), 'w', encoding='utf-8', errors='ignore')
                self.benchmarking_csv.write("TIME,COMMAND\n")
            except OSError:
                pass
        self.devnull = subprocess.DEVNULL

    def close(self):
        if hasattr(self, 'command_error_log') and self.command_error_log and not self.command_error_log.closed:
            self.command_error_log.close()
        if hasattr(self, 'debug_log') and self.debug_log and not self.debug_log.closed:
            self.debug_log.close()
        if hasattr(self, 'verbose_log') and self.verbose_log and not self.verbose_log.closed:
            self.verbose_log.close()
        if hasattr(self, 'benchmarking_csv') and self.benchmarking_csv and not self.benchmarking_csv.closed:
            self.benchmarking_csv.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    # Parse Nmap XML - Reads all the Nmap xml files in the Nmap folder
    def parse_nmap_xml(self):
        Logger.verbose("[+] Reading Nmap XML Output Files...")
        port_attribs_to_read = ['protocol', 'portid']
        service_attribs_to_read = ['name', 'product', 'version', 'extrainfo', 'method', 'tunnel']
        state_attribs_to_read = ['state', 'reason']
        xml_nmap_elements = {'service': service_attribs_to_read, 'state': state_attribs_to_read}
        search_address = {'path': 'address', 'el': 'addr'}
        search_ports = {'path': 'ports', 'el': 'portid'}
        nmap_output_path = os.path.join(self.args.outputFolder, __nmap_folder__)
        if not os.path.exists(nmap_output_path):
            return
        for nmap_file in os.listdir(nmap_output_path):
            if nmap_file.endswith(".xml"):
                nmap_file_path = os.path.join(nmap_output_path, nmap_file)
                Logger.debug("XML PARSE: " + nmap_file_path)
                try:
                    tree = ET.parse(nmap_file_path)
                except Exception as e:
                    Logger.debug("XML PARSE: Error Parsing : " + nmap_file_path + " - " + str(e))
                    continue
                root = tree.getroot()
                for i in root.iter('host'):
                    e = i.find(search_address['path'])
                    find_ports = i.find(search_ports['path'])
                    if find_ports is not None and e is not None:
                        addr = e.get(search_address['el'])
                        if addr is None:
                            continue
                        if self.nmap_dict.get(addr, None) is None:
                            self.nmap_dict[addr] = {}

                        # Extract hostname from <hostnames> element
                        hostnames_elem = i.find('hostnames')
                        if hostnames_elem is not None:
                            for hn in hostnames_elem.iter('hostname'):
                                h_name = hn.get('name', '').strip()
                                if h_name and not self.nmap_dict[addr].get('hostname'):
                                    self.nmap_dict[addr]['hostname'] = h_name
                                    break
                        port_dict = []
                        for port in find_ports.iter('port'):
                            element_dict = {}
                            self.xml_to_dict(port_attribs_to_read, port, element_dict)
                            for attr in state_attribs_to_read:
                                element_dict[attr] = ''
                            for attr in service_attribs_to_read:
                                element_dict[attr] = ''
                            element_dict['name'] = 'unknown'

                            # 1. Parse <state> element
                            state_elem = port.find('state')
                            if state_elem is not None:
                                for attr in state_attribs_to_read:
                                    element_dict[attr] = state_elem.get(attr, '')

                            # 2. Parse <service> element
                            service_elem = port.find('service')
                            if service_elem is not None:
                                for attr in service_attribs_to_read:
                                    val = service_elem.get(attr, '')
                                    if attr == 'name' and self.config.has_option('Service Labels', val):
                                        element_dict[attr] = self.config.get('Service Labels', val)
                                    else:
                                        element_dict[attr] = val

                                if service_elem.get('hostname', '') != '':
                                    self.nmap_dict[addr]['hostname'] = service_elem.get('hostname', '')
                                if service_elem.get('tunnel', '') == 'ssl' and element_dict.get('name', '') == 'http':
                                    element_dict['name'] = 'https'

                            # Ensure non-empty service name and resolve from Service Ports if unknown
                            if not element_dict.get('name') or element_dict.get('name') == 'unknown':
                                element_dict['name'] = 'unknown'
                                if self.config.has_section('Service Ports'):
                                    for s_name, s_ports in self.config.items('Service Ports'):
                                        if str(element_dict.get('portid')) in [p.strip() for p in s_ports.split(',')]:
                                            element_dict['name'] = s_name
                                            break

                            # 3. Merge with existing port if already recorded
                            port_was_merged = False
                            if self.nmap_dict[addr].get('ports', None) is not None:
                                for pos, port_item in enumerate(self.nmap_dict[addr]['ports']):
                                    if str(port_item.get('portid')) == str(element_dict.get('portid')):
                                        port_was_merged = True
                                        for element in service_attribs_to_read:
                                            if element_dict.get(element, '') != '':
                                                self.nmap_dict[addr]['ports'][pos][element] = element_dict[element]
                                        for element in state_attribs_to_read:
                                            if element_dict.get(element, '') != '':
                                                self.nmap_dict[addr]['ports'][pos][element] = element_dict[element]
                                        if self.nmap_dict[addr]['ports'][pos].get('name') == 'unknown' and element_dict.get('name') != 'unknown':
                                            self.nmap_dict[addr]['ports'][pos]['name'] = element_dict['name']
                                        break
                            if port_was_merged is False:
                                port_dict.append(element_dict)
                        if self.nmap_dict[addr].get('ports', None) is None:
                            self.nmap_dict[addr]['ports'] = port_dict
                        else:
                            self.nmap_dict[addr]['ports'] = self.nmap_dict[addr]['ports'] + port_dict
            Logger.debug("NMAP XML PARSE: - Finished NMAP Dict Creation:\n " + str(self.nmap_dict))
            # Sincronização bidirecional entre chaves de IP e Hostname no nmap_dict
            self.sync_nmap_dict_hosts()
            Logger.debug("NMAP XML PARSE: - Synced NMAP Dict:\n " + str(self.nmap_dict))

    def sync_nmap_dict_hosts(self):
        """
        Sincroniza portas e metadados bidirecionalmente entre chaves de IP e Hostname no nmap_dict.
        Garante que ferramentas web vejam portas sob o hostname e ferramentas de rede vejam sob o IP.
        """
        keys = list(self.nmap_dict.keys())
        for k in keys:
            entry = self.nmap_dict[k]
            k_is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', k))

            hn = entry.get('hostname') or (getattr(self, 'ip_to_host', {}).get(k) if k_is_ip else k)
            ip = entry.get('ip') or (k if k_is_ip else (getattr(self, 'host_to_ip', {}).get(k) or self.resolve_target_ip(k)))

            if k_is_ip and not hn:
                hn = self.resolve_ip_hostname(k)
                if hn:
                    if hasattr(self, 'ip_to_host'):
                        self.ip_to_host[k] = hn
                    if hasattr(self, 'host_to_ip'):
                        self.host_to_ip[hn] = k

            if hn:
                entry['hostname'] = hn
            if ip and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
                entry['ip'] = ip

            other_keys = []
            if hn and hn != k:
                other_keys.append(hn)
            if ip and ip != k and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
                other_keys.append(ip)

            for ok in other_keys:
                if ok not in self.nmap_dict:
                    self.nmap_dict[ok] = {'ports': []}
                if hn:
                    self.nmap_dict[ok]['hostname'] = hn
                if ip and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
                    self.nmap_dict[ok]['ip'] = ip

                target_ports = self.nmap_dict[ok].setdefault('ports', [])
                source_ports = entry.get('ports', [])
                for sp in source_ports:
                    sp_portid = str(sp.get('portid', ''))
                    sp_proto = sp.get('protocol', 'tcp')
                    exists = False
                    for idx, tp in enumerate(target_ports):
                        if str(tp.get('portid', '')) == sp_portid and tp.get('protocol', 'tcp') == sp_proto:
                            exists = True
                            for attr in ('name', 'product', 'version', 'extrainfo', 'tunnel', 'state'):
                                if sp.get(attr) and not tp.get(attr):
                                    target_ports[idx][attr] = sp[attr]
                            break
                    if not exists:
                        target_ports.append(dict(sp))

    @staticmethod
    def sanitize_target(raw_target: str):
        """
        Sanitiza uma string de alvo que pode vir como:
        - URL: 'https://juice.octopux/' -> ('juice.octopux', 'https', 443)
        - URL com porta: 'http://juice.octopux:8080/path' -> ('juice.octopux', 'http', 8080)
        - Host com porta: 'juice.octopux:8080' -> ('juice.octopux', None, 8080)
        - Host puro ou IP: 'juice.octopux' -> ('juice.octopux', None, None)
        - IP puro: '192.168.50.160' -> ('192.168.50.160', None, None)
        """
        target = str(raw_target).strip()
        if not target:
            return "", None, None

        scheme = None
        port = None

        if "://" in target:
            try:
                parsed = urllib.parse.urlparse(target)
                scheme = parsed.scheme.lower() if parsed.scheme else None
                host = parsed.hostname or target
                port = parsed.port
                if port is None and scheme in ("http", "https"):
                    port = 443 if scheme == "https" else 80
                return host, scheme, port
            except Exception:
                pass

        # Sem esquema HTTP/HTTPS: remove caminhos ou barras finais
        clean = target.split('/')[0].strip()
        # Trata porta se vier no formato host:porta (e não IPv6 puro)
        if ":" in clean and not clean.startswith("["):
            parts = clean.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                clean = parts[0]
                port = int(parts[1])

        return clean, scheme, port

    @staticmethod
    def resolve_target_ip(host_or_ip: str) -> str:
        """
        Resolve um hostname para IP usando socket.gethostbyname com fallback para /etc/hosts.
        Se já for um IP válido, retorna o próprio IP.
        """
        if not host_or_ip:
            return host_or_ip
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host_or_ip):
            return host_or_ip

        # 1. Tenta resolução via DNS / sistema operacional
        try:
            ip = socket.gethostbyname(host_or_ip)
            if ip and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
                return ip
        except Exception:
            pass

        # 2. Fallback direto para o /etc/hosts
        try:
            if os.path.exists('/etc/hosts'):
                with open('/etc/hosts', 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.split('#')[0].strip()
                        if not line:
                            continue
                        parts = line.split()
                        if len(parts) >= 2:
                            ip_cand = parts[0]
                            names = parts[1:]
                            if host_or_ip.lower() in [n.lower() for n in names]:
                                if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip_cand):
                                    return ip_cand
        except Exception:
            pass

        return host_or_ip

    @staticmethod
    def resolve_ip_hostname(ip: str):
        """
        Tenta encontrar um hostname virtual correspondente a um IP consultando o /etc/hosts ou DNS reverso.
        """
        if not ip or not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
            return None
        # 1. Consulta /etc/hosts primeiro (preserva o mapeamento exato do lab, ex: 192.168.50.160 -> juice.octopux)
        try:
            if os.path.exists('/etc/hosts'):
                with open('/etc/hosts', 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.split('#')[0].strip()
                        if not line:
                            continue
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] == ip:
                            for n in parts[1:]:
                                if n.lower() not in ('localhost', 'broadcasthost', 'ip6-localhost', 'ip6-loopback'):
                                    return n
        except Exception:
            pass

        # 2. DNS Reverso
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            if name and name != ip:
                return name
        except Exception:
            pass
        return None

    @staticmethod
    def merge_two_dicts(x, y):
        z = x.copy()
        z.update(y)
        return z

    # find exploits from exploit db and copy them to service folder
    # TODO: Copy results to service folders - update nmap_dict with other web app etc products and versions...
    def exploit_search(self, command_label):
        if self.args.noExploitSearch:
            return False
        Logger.debug("exploit_search()")
        for host in self.nmap_dict:
            for service in self.nmap_dict[host].get('ports', []):
                product = service.get('product', '').strip()
                version = service.get('version', '').strip()
                service_name = service.get('name', '').strip()
                
                target_query = ""
                if product:
                    target_query = f"{product} {version}".strip() if version else product
                elif service_name and service_name not in ('unknown', 'always'):
                    target_query = service_name

                if not target_query:
                    continue

                command_keys = {
                    'output': self.get_enumeration_path(host, service.get('name', 'unknown'), service.get('portid', '0'), command_label),
                    'target': f'"{target_query}"' if ' ' in target_query else target_query}
                base, filename = os.path.split(command_keys['output'])  # Resume file already exists
                if not self.args.noResume and len(self.find_files(base, filename + ".*")) > 0:
                    Logger.debug("exploit_search() -Exploit Search file already exists: "
                                 + command_keys['output'])
                else:
                    if not self.config.has_section(command_label):
                        Logger.debug("exploit_search() - Section not found in config: " + command_label)
                        continue
                    self.execute_command(self.prepare_command(command_label, command_keys))
                    json_file = command_keys['output'] + ".json"
                    if not os.path.exists(json_file):
                        continue
                    with open(json_file, 'r', encoding='utf-8', errors='ignore') as data_file:
                        try:
                            data = json.load(data_file)
                        except Exception:
                            continue
                        results = data.get('RESULTS') or data.get('RESULTS_EXPLOIT') or []
                        if len(results) == 0:
                            try:
                                os.remove(json_file)
                            except OSError:
                                pass
                        else:  # copy exploits to exploit folder
                            exploits_path = os.path.join(base, "exploits")
                            if not os.path.exists(exploits_path):
                                os.makedirs(exploits_path)
                            for exploit in results:
                                exploit_path = exploit.get('Path') or exploit.get('path')
                                if exploit_path and os.path.exists(exploit_path):
                                    exploit_base, exploit_filename = os.path.split(exploit_path)
                                    copyfile(exploit_path, os.path.join(exploits_path, exploit_filename))

    # Enumerate a phase
    # phases are defined in attackplan.ini
    # enumerate will create a que of all the commands to run in a phase
    # then it will create a progress bar and execute a specified number of threads at the same time
    # until all the threads are finished then the results are parsed by another function
    def enumerate(self, phase_name):
        Logger.debug("Enumerate - " + phase_name)
        self.phase_commands = []
        self.thread_pool_errors = []
        if not self.plan.has_section(phase_name):
            Logger.debug("enumerate() - Section not found in attack plan: " + phase_name)
            return
        # Deduplicação de alvos espelhados: o sync_nmap_dict_hosts() espelha as
        # portas nas DUAS keys (hostname<->IP) do mesmo host físico. Sem este
        # filtro, cada fase executava 2x (uma por key) — dobrando o tempo do run
        # e criando pastas de output duplicadas. Processa apenas a PRIMEIRA key
        # de cada IP efetivo (a canônica vem primeiro: prioridade hostname/SNI).
        _seen_effective = set()
        for host in list(self.nmap_dict.keys()):
            _entry = self.nmap_dict[host] or {}
            _eff = str(_entry.get('ip') or host)
            if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', _eff):
                _eff = str(getattr(self, 'host_to_ip', {}).get(host) or host)
            if _eff in _seen_effective:
                Logger.debug("enumerate() - contraparte espelhada pulada (mesmo IP que " + _eff + "): " + host)
                continue
            _seen_effective.add(_eff)
            Logger.debug("enumerate() - Host: " + host)
            host_ports = [str(d['portid']) for d in self.nmap_dict[host].get('ports', []) if 'portid' in d]
            if self.plan.has_option(phase_name, 'always'):
                self.nmap_dict[host]['ports'].append(
                    {'state': 'open', 'name': 'always', 'portid': '0', 'product': 'Ruadan Added Always Service'})
            if self.plan.has_option(phase_name, 'run once'):
                if self.run_once.get(phase_name) is None:
                    self.run_once[phase_name] = host
                    self.nmap_dict[host]['ports'].append(
                        {'state': 'open', 'name': 'run once', 'portid': '-1', 'product': 'Ruadan Added Run Once Service'})
            for service in list(self.nmap_dict[host].get('ports', [])):
                Logger.debug("\tenumerate() - port_number: " + str(service))
                for known_service, ports in self.config.items('Service Ports'):
                    service_name = service.get('name', '')
                    service_state = service.get('state', '')
                    service_port = str(service.get('portid', ''))
                    is_closed = ('closed' in service_state) and ('open' not in service_state)
                    if not is_closed \
                            and (service_name.find(known_service) != -1 or service_port in ports.split(',')):
                        if self.plan.has_option(phase_name, known_service):
                            for command_label in self.plan.get(phase_name, known_service).split(','):
                                command_label = command_label.strip()
                                if command_label != '':
                                    if not self.config.has_section(command_label):
                                        Logger.debug("\tenumerate() - command section not found: " + command_label)
                                        continue
                                    # Para serviços web (HTTP/HTTPS), se tivermos o hostname virtual mapeado,
                                    # utiliza preferencialmente o hostname para suportar VirtualHosts / SNI
                                    cmd_target = host
                                    is_web_svc = (service_name in ('http', 'https') or str(service_port) in ('80', '443', '8080', '8443', '3000'))
                                    if is_web_svc and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
                                        target_hn = self.nmap_dict[host].get('hostname') or getattr(self, 'ip_to_host', {}).get(host)
                                        if target_hn:
                                            cmd_target = target_hn

                                    command_keys = {
                                        'output': self.get_enumeration_path(host, service_name, service_port,
                                                                            command_label),
                                        'output folder': self.args.outputFolder,
                                        'output nmap': os.path.join(self.nmap_path, command_label.replace(" ", "_") + "_" + host.replace(".", "_")),
                                        'target': cmd_target,
                                        'domain': self.args.domain,
                                        'service': service_name,
                                        'port': service_port,
                                        'host ports comma': ",".join(host_ports),
                                        'host ports space': " ".join(host_ports),
                                        'host file': self.args.hostFile.name if hasattr(self.args.hostFile, 'name') else str(self.args.hostFile),
                                        'nmap dns server': self.nmap_dns_server,
                                        'nmap proxy server': self.proxy_server,
                                        'proxy server': self.args.proxy,
                                        'workspace': self.workspace,
                                    }
                                    base, filename = os.path.split(command_keys['output'])  # Resume file already exists
                                    if not self.args.noResume and len(self.find_files(base, filename + ".*")) > 0:
                                        Logger.debug("enumerate() - RESUME - output file already exists: "
                                                     + command_keys['output'])
                                    else:
                                        command = self.prepare_command(command_label, command_keys)
                                        # TODO: Check for dictionary tags / list tags / findings lists
                                        do_not_append = False
                                        if "<" + __findings_label_dynamic__ + " " in command:
                                            findings_path = os.path.join(self.args.outputFolder, host.replace(".", "_"))
                                            findings_files = self.find_files(findings_path, "*.txt")
                                            for findings_file in findings_files:
                                                replacement = "<" + __findings_label_dynamic__ + " " + str(findings_file).replace(".txt", "") + ">"
                                                if replacement in command:
                                                    findings_file_path = os.path.join(findings_path, findings_file)
                                                    command = command.replace(replacement, findings_file_path)
                                        # Still have a findings tag in the command?  do not add it to the list -
                                        if "<" + __findings_label_dynamic__ + " " in command:
                                            do_not_append = True
                                            Logger.debug("enumerate() - Did not append command that still contained findings label " + command)
                                        # Findings Lists
                                        if "<" + __findings_label_list_dynamic__ + " " in command:
                                            findings_path = os.path.join(self.args.outputFolder, host.replace(".", "_"))
                                            findings_files = self.find_files(findings_path, "*.txt")
                                            for findings_file in findings_files:
                                                replacement = "<" + __findings_label_list_dynamic__ + " " + str(
                                                    findings_file).replace(".txt", "") + ">"
                                                if replacement in command:
                                                    findings_file_path = os.path.join(findings_path, findings_file)
                                                    with open(findings_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                                        content = [x.strip() for x in f.readlines() if x.strip()]
                                                        for line in content:
                                                            new_command = command
                                                            new_command = new_command.replace(replacement, line)
                                                            self.phase_commands.append(new_command)
                                        # Lists
                                        for section in self.config.sections():
                                            if section.startswith("List ") or "List" in section:
                                                if command.find("<" + section + ">") != -1:  # include entire list from section
                                                    do_not_append = True
                                                    for item in self.config.items(section):
                                                        new_command = command
                                                        new_command = new_command.replace("<" + section + ">", item[1])
                                                        self.phase_commands.append(new_command)
                                                else:
                                                    for item in self.config.items(section):
                                                        command = command.replace("<" + item[0] + ">", item[1])
                                        if not do_not_append and "<" + __findings_label_dynamic__ not in command:
                                            self.phase_commands.append(command)
                                            Logger.debug("enumerate() - added command : " + command_label)
                                            
                                            # If target has a resolved hostname, also schedule scan against the hostname
                                            host_hostname = self.nmap_dict[host].get('hostname') or getattr(self, 'ip_to_host', {}).get(host)
                                            if host_hostname and host_hostname != host and host_hostname != cmd_target:
                                                cmd_keys_hn = command_keys.copy()
                                                cmd_keys_hn['target'] = host_hostname
                                                cmd_keys_hn['output'] = self.get_enumeration_path(host_hostname, service_name, service_port, command_label)
                                                cmd_hn = self.prepare_command(command_label, cmd_keys_hn)
                                                self.phase_commands.append(cmd_hn)
                                                Logger.debug("enumerate() - added hostname command : " + command_label + " for " + host_hostname)
                                        else:
                                            Logger.debug("enumerate() - skipped command : " + command_label)
                        else:
                            Logger.debug("\tenumerate() - NO command section found for phase: " + phase_name +
                                         " service name: " + known_service)
        self.phase_commands = self.remove_duplicates(self.phase_commands)
        if len(self.phase_commands) > 0:
            pool = ThreadPool(self.args.threadPool)
            for _ in bar(pool.imap_unordered(self.execute_command, self.phase_commands),
                         expected_size=len(self.phase_commands)):
                pass
            pool.close()
            pool.join()

    @staticmethod
    def remove_duplicates(list_with_duplicates):
        return list(set(list_with_duplicates))

    def execute_command(self, command):
        Logger.verbose("root@kali:/# " + command)
        Logger.debug("execute_command() - Starting: - " + command)
        command_start_time = time.time()
        tool_cmd = command.strip().split()[0] if command.strip() else "tool"
        print(Color.cyan() + " [*] " + Color.reset() + f"Executando ferramenta: {Color.yellow()}{tool_cmd}{Color.reset()} -> {command[:90]}...")
        with open(self.active_commands, 'w', encoding='utf-8', errors='ignore') as active_command_report_file:
            active_command_report_file.write("Last Update: " + str(datetime.now()) + "\n")
            active_command_report_file.write(pformat(self.thread_pool_commands, indent=4, width=1))
        self.thread_pool_commands.append(command)
        process = Popen(command, shell=True, stdin=PIPE, stderr=self.command_error_log, stdout=self.devnull)
        if process.stdin:
            process.stdin.close()
        ret_code = process.wait()
        elapsed_sec = time.time() - command_start_time
        if ret_code != 0:
            Logger.debug("execute_command() - ERRORS EXECUTING:  - " + command)
            self.thread_pool_errors.append(command)
            print(Color.yellow() + f" [!] Ferramenta {tool_cmd} finalizada (código: {ret_code}, tempo: {elapsed_sec:.1f}s)" + Color.reset())
        else:
            print(Color.green() + f" [+] Ferramenta {tool_cmd} concluída com sucesso ({elapsed_sec:.1f}s)" + Color.reset())
        Logger.debug("execute_command() - COMPLETED! - " + command)
        if command in self.thread_pool_commands:
            self.thread_pool_commands.remove(command)

        # Audit log for every executed command
        try:
            cmd_log_file = os.path.join(self.args.outputFolder, "command_execution_history.log")
            with open(cmd_log_file, "a", encoding="utf-8") as f_hist:
                status_str = "SUCCESS" if ret_code == 0 else f"EXIT_{ret_code}"
                f_hist.write(f"[{datetime.now().isoformat()}] [{status_str}] [{elapsed_sec:.2f}s] {command}\n")
        except Exception:
            pass
        if self.args.benchmarking:
            with open(self.active_commands, 'w', encoding='utf-8', errors='ignore') as active_command_report_file:
                active_command_report_file.write("Last Update: " + str(datetime.now()) + "\n")
                active_command_report_file.write(pformat(self.thread_pool_commands, indent=4, width=1))
            self.benchmarking_csv.write(
                time.strftime('%H:%M:%S', time.gmtime(time.time() - command_start_time)) + "," + command.replace(",", " ") + "\n")

    def enumerate_plan(self, plan):
        if not self.plan.has_section(plan) or not self.plan.has_option(plan, "Order"):
            return
        for phase in self.plan.get(plan, "Order").split(","):
            phase = phase.strip()
            if not phase:
                continue
            print(Color.green() + "[+]" + Color.reset() + " Starting Phase: " + phase)
            Logger.verbose("[+] Starting Phase: " + phase)
            try:
                if self.args.phase == phase or self.args.phase == '':
                    self.enumerate(phase)
            except KeyboardInterrupt:
                Logger.debug("[X] Keyboard Interrupt Detected... exiting phase:: " + phase)
                Logger.debug("[X] Thread Pool at Interrupt: \n" + pformat(self.thread_pool_commands))
                print(Color.red() + "[X]" + Color.reset() + " Keyboard Interrupt Detected... exiting phase: " + phase)
                print(Color.red() + "[X]" + Color.reset() + " Thread Pool at Interrupt:")
                pprint(self.thread_pool_commands)
                continue
            except ValueError as err:
                bar(self.phase_commands, expected_size=len(self.phase_commands))
                if len(self.thread_pool_errors) > 0:
                    Logger.debug("[X] Phase completed but encountered the following errors:  \n"
                                 + pformat(self.thread_pool_errors) + pformat(self.thread_pool_commands))
                    print(Color.red() + "[X]" + Color.reset() + " Phase completed but encountered the following errors: \n"
                          + pformat(self.thread_pool_errors) + pformat(self.thread_pool_commands))
                continue
            self.parse_nmap_xml()
            self.write_report_file(self.nmap_dict, self.args.outputFolder, self.args.reportFile)
            Logger.verbose("[+] Finding's Post Processing...")
            self.findings_post_processing()

    def findings_post_processing(self):
        for current_host in self.hosts:
            current_host = current_host.strip()
            if not current_host or current_host.startswith("#"):
                continue
            host_path = os.path.join(self.args.outputFolder, current_host.replace(".", "_"))
            if not os.path.exists(host_path):
                continue
            files_to_process = [os.path.join(dp, f) for dp, dn, fn in os.walk(os.path.expanduser(host_path))
                                for f in fn]
            self.findings = {'users': [], 'urls': [], 'groups': [], 'passwords': [], 'vulnerabilities': []}
            # TODO: Load findings from files here for merging - dont overwrite user added findings...

            for file in files_to_process:
                base, filename = os.path.split(file)
                if base.endswith(__nmap_folder__):
                    continue
                file_segments = filename.split("_")
                file_segments.pop()
                config_command_name = " ".join(file_segments)
                if self.config.has_section(config_command_name):
                    for item in self.config.items(config_command_name):
                        if __findings_label__ in item[0]:
                            list_type = str(item[0]).split(" ")[1]
                            list_type = ''.join([i for i in list_type if not i.isdigit()])  # remove digits in item name
                            if self.findings.get(list_type) is None:
                                self.findings[list_type] = []
                            try:
                                regex = re.compile(item[1])
                            except re.error:
                                continue
                            # First try line by line
                            wholefile = ""
                            try:
                                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                                    for line in f:
                                        wholefile += line
                                        match = regex.match(line)
                                        if match is not None and match.groups():
                                            self.findings[list_type].append(match.group(1))
                                            announcement = current_host + ":  \t" + match.group(1)
                                            if __accounce_label__ in item[0] and self.announced.get(announcement) != 1:
                                                self.announced[announcement] = 1
                                                print(Color.redback() + "[!] " + announcement +
                                                      " " + re.sub(__findings_label__ + " " + __accounce_label__ + r"\d*", "", str(item[0]))
                                                      + Color.reset())
                            except (OSError, UnicodeError):
                                continue

                            # Next try multiline search mode
                            matches = re.search(item[1], wholefile, re.MULTILINE)
                            if matches and matches.groups() and matches.group(1) is not None:
                                self.findings[list_type].append(matches.group(1))
                                announcement = current_host + ":  \t" + matches.group(1)
                                if __accounce_label__ in item[0] and self.announced.get(announcement) != 1:
                                    self.announced[announcement] = 1
                                    print(Color.redback() + "[!] " + announcement +
                                          " " + re.sub(__findings_label__ + " " + __accounce_label__ + r"\d*", "", str(item[0])) +
                                          Color.reset())
            # Remove duplicates and output results to findings files
            for findings_list in self.findings:
                self.findings[findings_list] = self.remove_duplicates(self.findings[findings_list])
                self.findings[findings_list].sort()
                if len(self.findings[findings_list]) > 0:
                    with open(os.path.join(host_path, findings_list + ".txt"), 'w', encoding='utf-8', errors='ignore') as findings_file:
                        findings_file.write("\n".join(self.findings[findings_list]))
            # Calculate Risk Score
            risk_score = 0
            for findings_list in self.findings:
                risk_score += len(self.findings.get(findings_list, [])) * 1
            if len(self.findings.get(__accounce_label__, [])) > 0:
                risk_score += 1000
            risk_score -= len(self.findings.get(__password_list_label__, []))
            risk_score -= len(self.findings.get(__urlshttp_list_label__, []))
            risk_score -= len(self.findings.get(__urlshttps_list_label__, []))
            if len(self.findings.get(__urlshttp_list_label__, [])) > 20:
                risk_score += 20
            else:
                risk_score += len(self.findings.get(__urlshttp_list_label__, []))
            if len(self.findings.get(__urlshttps_list_label__, [])) > 20:
                risk_score += 20
            else:
                risk_score += len(self.findings.get(__urlshttps_list_label__, []))
            self.risk_score[current_host] = risk_score

    def get_enumeration_path(self, host, service, port, command):
        ip_path = os.path.join(self.args.outputFolder, host.replace(".", "_"))
        if not os.path.exists(ip_path):
            os.makedirs(ip_path)
        service_path = os.path.join(ip_path, service.replace(" ", "_"))
        if not os.path.exists(service_path):
            os.makedirs(service_path)
        return os.path.join(service_path, command.replace(" ", "_") + "_" + str(port))

    def prepare_command(self, command, keyvalues):
        command_str = self.config.get(command, "command")
        Logger.debug("prepare_command() command: " + command_str)
        for k in keyvalues:
            Logger.debug("    prepare_command() key: " + k)
            command_str = command_str.replace("<" + k + ">", str(keyvalues[k]))
        return command_str

    def xml_to_dict(self, list_to_read, xml_elements, dict_obj):
        for element in list_to_read:
            value = xml_elements.get(element, '')
            if element == "name" and self.config.has_option("Service Labels", value):
                dict_obj[element] = self.config.get("Service Labels", value)
            else:
                dict_obj[element] = value
        return dict_obj

    def write_report_file(self, data, folder, file):
        report_path = os.path.join(folder, file)
        with open(report_path, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(pformat(data, indent=4, width=1))

    def write_csv_report_file(self, data, header, folder, file):
        report_path = os.path.join(folder, file)
        with open(report_path, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(header)
            for item in data:
                f.write(str(item[0]) + "," + str(item[1]) + "\n")

    def find_files(self, base, pattern):
        if not os.path.exists(base):
            return []
        return [n for n in fnmatch.filter(os.listdir(base), pattern) if
                os.path.isfile(os.path.join(base, n))]

    def banner(self):
        banner_numbers = [1, 2, 3]
        banners = {
            1: self.banner_flame,
            2: self.banner_doom,
            3: self.banner_block
        }
        secure_random = random.SystemRandom()
        banners[secure_random.choice(banner_numbers)]()

    @staticmethod
    def banner_flame():
        print(Color.red() + '\n' +
              '                  )             (   (    \n' +
              '         (     ( /(   (         )\\ ))\\ ) \n' +
              ' (   (   )\\    )\\())( )\\     ( (()/(()/( \n' +
              ' )\\  )((((_)( ((_)\\ )((_)    )\\ /(_))(_) \n' +
              '((_)((_)\\ _ )\\ _((_|(_)_  _ ((_|_))(_))  \n' +
              ' ____  _   _   _    ____    _    _   _ \n' +
              '|  _ \\| | | | / \\  |  _ \\  / \\  | \\ | |\n' +
              '| |_) | | | |/ _ \\ | | | |/ _ \\ |  \\| |\n' +
              '|  _ <| |_| / ___ \\| |_| / ___ \\| |\\  |\n' +
              '|_| \\_\\\\___/_/   \\_\\____/_/   \\_\\_| \\_|\n' +
              'Get to shell.' + Color.reset())

    @staticmethod
    def banner_doom():
        print(Color.yellow() + '\n ' +
              ' _____  _    _         _____          _   _ \n' +
              '|  __ \\| |  | |  /\\   |  __ \\   /\\   | \\ | |\n' +
              '| |__) | |  | | /  \\  | |  | | /  \\  |  \\| |\n' +
              '|  _  /| |  | |/ /\\ \\ | |  | |/ /\\ \\ | . ` |\n' +
              '| | \\ \\| |__| / ____ \\| |__| / ____ \\| |\\  |\n' +
              '|_|  \\_\\\\____/_/    \\_\\_____/_/    \\_\\_| \\_|\n' +
              'Root to boot enumeration platform.' + Color.reset())

    @staticmethod
    def banner_block():
        print(Color.magenta() + '\n' +
              ' ___ _   _  _   ___   _   _  _ \n' +
              '| _ \\ | | |/_\\ |   \\ /_\\ | \\| |\n' +
              '|   / |_| / _ \\| |) / _ \\| .` |\n' +
              '|_|_\\\\___/_/ \\_\\___/_/ \\_\\_|\\_|\n' +
              'Systematic enumeration and exploitation.' + Color.reset())

    ##################################################################################
    # Entry point for command-line execution
    ##################################################################################

    @property
    def main(self):
        start_time = time.time()
        print(Color.cyan())
        print("Configuration file: " + str(self.args.configFile))
        print("Attack plan file:   " + str(self.args.attackPlanFile))
        print("Output Path:        " + str(self.args.outputFolder))
        print("Host File:          " + str(self.args.hostFile.name if hasattr(self.args.hostFile, 'name') else self.args.hostFile))
        print(Color.reset())
        Logger.debug("DEBUG MODE ENABLED!")
        Logger.verbose("VERBOSE MODE ENABLED!")

        if hasattr(self.hosts, 'read'):
            raw_hosts = self.hosts.read().splitlines()
        elif isinstance(self.hosts, str):
            with open(self.hosts, 'r', encoding='utf-8', errors='ignore') as hf:
                raw_hosts = hf.read().splitlines()
        else:
            raw_hosts = list(self.hosts)
        self.hosts = [h.strip() for h in raw_hosts if h.strip() and not h.strip().startswith('#')]

        # ============================================================================
        # Normalização e Sanitização de alvos:
        # Suporta URLs completas (ex: https://juice.octopux/ ou http://alvo:8080/),
        # hostnames virtuais (ex: juice.octopux) e IPs puros (ex: 192.168.50.160).
        # Resolve IPs via DNS e /etc/hosts, vinculando bidirecionalmente host <-> IP.
        # PRESERVA o hostname virtual para ferramentas web (Nikto, Gobuster, cURL, etc.)
        # e unifica alvos duplicados que apontam para o mesmo IP físico.
        # ============================================================================
        self.host_to_ip = {}
        self.ip_to_host = {}
        self.target_urls = {}

        _canonical_targets = []
        _ip_seen = {}  # ip -> canonical_name escolhido

        for raw_entry in self.hosts:
            clean_host, scheme, port = self.sanitize_target(raw_entry)
            if not clean_host:
                continue

            resolved_ip = self.resolve_target_ip(clean_host)
            is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', clean_host))

            if not is_ip and resolved_ip and resolved_ip != clean_host:
                self.host_to_ip[clean_host] = resolved_ip
                if resolved_ip not in self.ip_to_host:
                    self.ip_to_host[resolved_ip] = clean_host
            elif is_ip:
                hn = self.resolve_ip_hostname(clean_host)
                if hn:
                    self.ip_to_host[clean_host] = hn
                    if hn not in self.host_to_ip:
                        self.host_to_ip[hn] = clean_host

            if scheme:
                self.target_urls[clean_host] = raw_entry

            # Deduplicação inteligente de alvos que compartilham o mesmo IP:
            # Hostname virtual tem prioridade sobre IP cru (carrega SNI/VHost).
            effective_ip = resolved_ip if (resolved_ip and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', resolved_ip)) else clean_host

            if effective_ip not in _ip_seen:
                _ip_seen[effective_ip] = clean_host
                _canonical_targets.append(clean_host)
            else:
                prev_choice = _ip_seen[effective_ip]
                # Se a escolha anterior foi um IP cru e agora recebemos um hostname virtual para o mesmo IP, atualiza
                if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', prev_choice) and not is_ip:
                    _canonical_targets[_canonical_targets.index(prev_choice)] = clean_host
                    _ip_seen[effective_ip] = clean_host
                    print(Color.cyan() + f"[i] Alvo '{prev_choice}' atualizado para o hostname virtual '{clean_host}' ({effective_ip})." + Color.reset())

        for h, ip in self.host_to_ip.items():
            print(Color.cyan() + f"[i] Alvo '{h}' vinculado ao IP real {ip} (via /etc/hosts/DNS)." + Color.reset())

        self.hosts = _canonical_targets
        Logger.verbose("Hosts:" + str(self.hosts))
        for host in self.hosts:
            self.nmap_dict[host] = {"ports": []}
            if host in self.host_to_ip:
                self.nmap_dict[host]["ip"] = self.host_to_ip[host]
                self.nmap_dict[host]["hostname"] = host
            elif host in self.ip_to_host:
                self.nmap_dict[host]["hostname"] = self.ip_to_host[host]
                self.nmap_dict[host]["ip"] = host
            # Garante que a contraparte também exista no nmap_dict para sincronização
            counterpart = self.host_to_ip.get(host) or self.ip_to_host.get(host)
            if counterpart and counterpart not in self.nmap_dict:
                self.nmap_dict[counterpart] = {
                    "ports": [],
                    "ip": self.host_to_ip.get(counterpart, host if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host) else counterpart),
                    "hostname": self.ip_to_host.get(counterpart, counterpart if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', counterpart) else host)
                }

        # Check if Autonomous AI Mode is enabled
        if getattr(self.args, 'ai', False):
            print(Color.cyan() + "\n==================================================================" + Color.reset())
            print(Color.cyan() + "[+] Ruadan AI Engine ativado (red-MPPO Reinforcement Learning + Multi-LLM)" + Color.reset())
            print(Color.cyan() + f"    - Provedor LLM:  {getattr(self.args, 'llmProvider', 'ollama')} (Modelo: {getattr(self.args, 'llmModel', 'default')})" + Color.reset())
            print(Color.cyan() + f"    - Alvo(s):       {self.hosts}" + Color.reset())
            print(Color.cyan() + "==================================================================\n" + Color.reset())
            try:
                workspace_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                if workspace_dir not in sys.path:
                    sys.path.insert(0, workspace_dir)
                from bridge.ai_orchestrator import RuadanAIBrain
                brain = RuadanAIBrain(
                    ruadan_instance=self,
                    checkpoint_path=getattr(self.args, 'checkpoint', None),
                    llm_provider=getattr(self.args, 'llmProvider', None),
                    llm_model=getattr(self.args, 'llmModel', None),
                    max_steps=getattr(self.args, 'aiSteps', 40)
                )
                brain.run_ai_cycle()
            except Exception as e:
                Logger.debug("Ruadan AI Engine error: " + str(e))
                print(Color.red() + f"[-] Ruadan AI Engine error: {e}" + Color.reset())
                import traceback
                traceback.print_exc()
            finally:
                sorted_x = sorted(self.risk_score.items(), key=operator.itemgetter(1))
                self.write_csv_report_file(sorted_x, "Host,Risk Score\n", self.args.outputFolder, "riskscores.csv")
                print(Color.grey() + "[+]" + Color.reset() + " Elapsed Time: " + time.strftime('%H:%M:%S', time.gmtime(time.time() - start_time)))
                Logger.verbose("Goodbye!")
                self.close()
            return 0

        print(Color.yellow() + "[*] Modo Tradicional legado (sem IA). Para ativar IA autônoma, execute via ./start.sh ou passe a flag -ai." + Color.reset())

        if self.plan.has_section("Nmap Scans") and self.plan.has_option("Nmap Scans", "Order"):
            for scan_phase in self.plan.get("Nmap Scans", "Order").split(","):
                scan_phase = scan_phase.strip()
                if scan_phase != '':
                    self.enumerate_plan(scan_phase)
                self.enumerate_plan("Enumeration Plan")
        else:
            self.enumerate_plan("Enumeration Plan")

        # Begin Post Enumeration Phases
        print(Color.grey() + "[+]" + Color.reset() + " Starting post enumeration...")
        self.enumerate_plan("Post Enumeration Plan")

        try:
            print(Color.grey() + "[+]" + Color.reset() + " Searching for matching exploits...")
            self.exploit_search("SearchSploit JSON")
        except Exception as e:
            Logger.debug("Exploit search exception: " + str(e))
            bar(self.phase_commands, expected_size=len(self.phase_commands))

        # Generate Reports
        sorted_x = sorted(self.risk_score.items(), key=operator.itemgetter(1))
        self.write_csv_report_file(sorted_x, "Host,Risk Score\n", self.args.outputFolder, "riskscores.csv")

        print(Color.grey() + "[+]" + Color.reset() + " Elapsed Time: " + time.strftime('%H:%M:%S', time.gmtime(time.time() - start_time)))
        Logger.verbose("Goodbye!")
        self.close()
        return 0


def main(argv=None):
    ruadan = Ruadan(argv if argv is not None else sys.argv[1:])
    return ruadan.main


if __name__ == "__main__":
    sys.exit(main())
