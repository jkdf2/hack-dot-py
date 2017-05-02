#!venv/bin/python

import subprocess
from prettytable import PrettyTable
from libnmap.parser import NmapParser
from collections import namedtuple
import os
import sys
import time


FILE_PREFIX = "results"
MAC_LENGTH  = 6  # The number of octets in a mac address

def sudo_user():
    return os.getuid() == 0

def clean_old_results():
    try:
        os.remove(FILE_PREFIX + ".xml")
    except FileNotFoundError:
        pass

    try:
        os.remove(FILE_PREFIX + "-01.csv")
    except FileNotFoundError:
        pass

def dump_network_info():
    """
    Saves all output from nmap and airodump-ng scans to a file.
    nmap results: FILE_PREFIX.xml
    airodump results: FILE_PREFIX.csv
    TODO: What should this return or do on FAILURE?
    Mary: recommends running nmap BEFORE airodump if applicable because
    nmap in monitor mode may not work correctly.
    """
    # Wifi interface
    interface = subprocess.check_output(["nmcli", "-t", "-f", "DEVICE", "connection","show", "--active"]).decode().strip()
    # SSID of network user is connected to
    print("Scanning for wireless networks...")
    # Sometimes this fails and says "command failed: Device or resource busy (-16)"
    sp1 = subprocess.Popen(["iw", "dev", interface, "link"], stdout=subprocess.PIPE)
    sp2 = subprocess.Popen(["grep", "SSID"], stdin=sp1.stdout, stdout=subprocess.PIPE)
    # TODO: Handle user not being connected to a network
    user_ssid = subprocess.check_output(["cut", "-f2-", "-d:"], stdin=sp2.stdout).decode().strip()
    # TODO: Note that iwgetid relies on deprecated iwconfig and does not work in modern Debian.
    #       Can use nmcli to determine the current network instead?

    # Create a dictionary of ssids and bssids -- {ssid : bssid}
    iw_scan1 = subprocess.Popen(["sudo", "iw", interface, "scan"], stdout=subprocess.PIPE)
    iw_scan2 = subprocess.Popen(["egrep", "^BSS|SSID:"], stdin=iw_scan1.stdout, stdout=subprocess.PIPE).communicate()[0].decode().strip().splitlines()
    ssid_dict = {}
    for bssid, ssid in zip(iw_scan2[0::2], iw_scan2[1::2]):
        ssid_dict[ssid.split(":", 1)[1].strip()] = bssid.split(":", 1)[1][0:14]
    # Create enumerated table
    ssids_table = PrettyTable(["*","Option","SSID"])
    ssids_table.hrules=True
    option_num = 1
    for entry in ssid_dict:
        connected = ""
        if entry == user_ssid:
            connected += "*"
        ssids_table.add_row([connected, option_num, entry])
        option_num+=1
    print(ssids_table)
    print("* = You are connected to this network -- detailed results available\n")
    # TODO: Deal with bad input
    user_input = input("Choose an SSID to target: ")
    victim_network = ssids_table.get_string(border=False, header=False, fields=["SSID"], start=int(user_input)-1, end=int(user_input)).strip()
    if victim_network == user_ssid:
        print("You are connected to " + victim_network + ". Running nmap... ")
        # Get IPs
        sp = subprocess.Popen(["ip", "addr", "show", interface], stdout=subprocess.PIPE)
        ips = subprocess.check_output(["grep", "inet", "-m", "1"], stdin=sp.stdout).decode()[9:24]
        sp.wait()
        # TODO: Check output, log verbosely
        nmap = subprocess.call(["nmap", "-n", "-A", "-oX", FILE_PREFIX+".xml", ips], stdout=subprocess.DEVNULL) # should we print nmap results to screen too?
        print("Done.\n")
    else:
        print("You are not connected to " + victim_network + ".\n")

    # Airodump -- working on this
    print("Enabling monitor mode... ")
    try:
        subprocess.check_output(["sudo", "airmon-ng", "start", interface])
        print("Starting airodump for 10 seconds... ")
        airodump = subprocess.Popen(["sudo", "airodump-ng","--bssid", ssid_dict[victim_network], interface+"mon", "-w", FILE_PREFIX, "-o", "csv"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # After 10 seconds, raise a TimeoutExpired exception to stop airodump
        o_airodump, unused_stderr = airodump.communicate(timeout=10)
        airodump.terminate()
    except subprocess.CalledProcessError as e:
        print ("Failed to enable monitor mode: " + e.output)
    except subprocess.TimeoutExpired:
        print("Disabling monitor mode... ")
        subprocess.check_output(["sudo", "airmon-ng", "stop", interface+"mon"])
        subprocess.call(["service", "network-manager", "start"])
        print("Done.\n")
        # Fixes invisible text in terminal & no echo after terminating airodump
        subprocess.call(["stty", "sane"])

def create_target_table():
    """
    Creates a table of potential victims.
    Allows a user to choose a victim by number, or
    all victims by pressing "A"
    """

    # Client   = namedtuple("Client", ["MAC", "Wifi Card Vendor", "IP Address", "Power", "Services"])
    Client   = namedtuple("Client", "mac, vendor, ip, power, services")
    Service  = namedtuple("Service", "port, state, service")
    clients  = dict()


    ap = parse_airodump(clients, Client)
    parse_nmap(clients, Client, Service, ap)

    # TODO: Provide a table of clients for the user to pick from.
    # TODO: Should we somehow exclude ourselves from the list of possible victims??

    # TODO: What info does Mary need in order to execute attack?
    execute_hack()

def parse_airodump(clients, Client):
    try:
        with open(FILE_PREFIX + "-01.csv") as airodump_file:
            ap_seen = False  # The first MAC we see is the Access Point / Station
            for line in airodump_file:
                line = list(map(str.strip, line.split(",")))
                if len(line[0].split(":")) == MAC_LENGTH:
                    line.pop()  # Last entry is an empty string; discard it
                    if not ap_seen:
                        ap_seen = True
                        AP      = namedtuple("AP", "bssid, ssid")
                        bssid   = line[0]
                        ssid    = line[-1]
                        ap      = AP(bssid, ssid)
                    else:
                        # Construct a Client from the airodump information.
                        mac          = line[0]
                        power        = line[3]
                        clients[mac] = Client(mac, None, None, power, None)

        return ap
    except FileNotFoundError as e:
        sys.exit("No airodump results found - fatal exception: '{}'".format(e))

def parse_nmap(clients, Client, Service, ap):
    try:
        nmap_report = NmapParser.parse_fromfile(FILE_PREFIX + ".xml")
    except Exception as e:
        nmap_report = None
        print("Skipping nmap results as NmapParser encountered exception: {}".format(type(e).__name__))

    if nmap_report is not None:
        for host in nmap_report.hosts:
            if host.is_up():
                if host.services:
                    services = list()
                    for service in host.services:
                        services.append(Service(service.port, service.state, service.service))
                else:
                    services = None

                try:
                    client = clients[host.mac]
                    client = client._replace(vendor=host.vendor,ip=host.address,services=services)
                    clients[host.mac] = client
                except KeyError:
                    if host.mac != ap.bssid:
                        clients[host.mac] = Client(host.mac, host.vendor, host.address, None, services)

def execute_hack():
    """
    Takes some information (WHAT?) in order to attack the victim.
    """
    pass

if __name__ == "__main__":
    if sudo_user():
        # TODO: Pass variables & arguments as needed
        clean_old_results()
        dump_network_info()
        create_target_table()
        print("uber l33t haxxing just happened")
    else:
        print("Script requires root access to perform network operations.")