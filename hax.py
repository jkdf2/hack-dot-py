#!venv/bin/python

import subprocess
from prettytable import PrettyTable
from libnmap.parser import NmapParser
import os
import sys


FILE_PREFIX = "results"
MAC_LENGTH  = 6  # The number of octets in a mac address

def sudo_user():
    return os.getuid() == 0

def parse_arguments():
    pass

def clean_old_results():
    try:
        os.remove(FILE_PREFIX + ".xml")
    except FileNotFoundError:
        pass

    try:
        os.remove(FILE_PREFIX + ".csv")
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
    sp1 = subprocess.Popen(["iw", "dev", "wlan0", "link"], stdout=subprocess.PIPE)
    sp2 = subprocess.Popen(["grep", "SSID"], stdin=sp1.stdout, stdout=subprocess.PIPE)
    user_ssid = subprocess.check_output(["cut", "-f2-", "-d:"], stdin=sp2.stdout).decode().strip()
    # TODO: Note that iwgetid relies on deprecated iwconfig and does not work in modern Debian.
    #       Can use nmcli to determine the current network instead?

    ssids = subprocess.Popen(["nmcli", "-t", "-f", "SSID", "dev", "wifi"], stdout=subprocess.PIPE).communicate()[0].decode()
    # Remove duplicates
    ssids_set = set(ssids.split('\n'))
    # Create table
    ssids_table = PrettyTable(["*","Option","SSID"])
    # ssids_table.hrules=True
    # ssids_table.vrules=False
    # ssids_table.border=False
    option_num = 1
    for entry in ssids_set:
        connected = ""
        if entry == user_ssid.strip():
            connected += "*"
        ssids_table.add_row([connected, option_num, entry])
        option_num+=1
    print(ssids_table)
    print("* = You are connected to this network -- detailed results available\n")
    # TODO: Deal with bad input
    user_input = input("Choose an SSID to target: ")
    network = ssids_table.get_string(border=False, header=False, fields=["SSID"], start=int(user_input)-1, end=int(user_input)).strip()
    if network == user_ssid:
        print("You are connected to " + network + ". Running nmap...", end="")
        # Get IPs
        # TODO: use all interfaces that start with "wl"???
        sp = subprocess.Popen(["ip", "addr", "show", "wlan0"], stdout=subprocess.PIPE)
        ips = subprocess.check_output(["grep", "inet", "-m", "1"], stdin=sp.stdout).decode()[9:24]
        sp.wait()
        subprocess.call(["nmap", "-n", "-A", "-oX", FILE_PREFIX+".xml", ips], stdout=open(os.devnull, 'wb')) # should we print nmap results to screen too?
        print("Done.\n")
    else:
        print("You are not connected to " + network + ".\n")

    # Airodump -- working on this
    # print("Enabling monitor mode... ", end="")
    # try:
    #     subprocess.check_output(["sudo", "airmon-ng", "start", interface])
    #     print("Success")
    #     airodump = subprocess.Popen(["sudo", "airodump-ng", interface+"mon", "-w", FILE_PREFIX, "-o", "csv"], stdout=subprocess.PIPE) #doesn't work
    #     o_airodump, unused_stderr = airodump.communicate(timeout=10)
    #     airodump.kill()
    #     subprocess.check_output(["sudo", "airmon-ng", "stop", interface+"mon"])
    #     subprocess.call(["service", "network-manager", "start"])
    # except subprocess.CalledProcessError as e:
    #     print ("Failed to enable monitor mode: " + e.output)


def create_target_table():
    """
    Creates a table of potential victims.
    Allows a user to choose a victim by number, or
    all victims by pressing "A"
    """

    # TODO: Parse results from dump_network_info
    try:
        with open(FILE_PREFIX + ".csv") as airodump_file:
            station_seen = False
            for line in airodump_file:
                line = list(map(str.strip, line.split(",")))
                if len(line[0].split(":")) == MAC_LENGTH:
                    line.pop()  # Last entry is an empty string
                    if not station_seen:
                        # TODO: Parse the SSID here, if needed.
                        station_seen = True
                        print("Station info: {}".format(line))
                    else:
                        print("Client info: {}".format(line))

    except FileNotFoundError as e:
        sys.exit("No airodump results found - fatal exception: '{}'".format(e))

    try:
        nmap_results = NmapParser.parse_fromfile(FILE_PREFIX + ".xml")
    except Exception as e:
        nmap_results = None
        print("Skipping nmap results as NmapParser encountered exception: {}".format(type(e).__name__))

    if nmap_results is not None:
        print("Info about nmap_results var:")
        print(type(nmap_results))
        print(dir(nmap_results))

    # TODO: What info does Mary need in order to execute attack?

    execute_hack()

def execute_hack():
    """
    Takes some information (WHAT?) in order to attack the victim.
    """
    pass

if __name__ == "__main__":
    # TODO: Pass variables & arguments as needed
    if sudo_user():
        parse_arguments()
        # clean_old_results()
        dump_network_info()
        create_target_table()
        print("uber l33t haxxing just happened")
    else:
        print("Script requires root access to perform network operations.")
