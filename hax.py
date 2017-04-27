#!/usr/bin/python3

import subprocess
from prettytable import PrettyTable

def parse_arguments():
    pass

def dump_network_info():
    """
    Saves all output from nmap and airodump-ng scans to a file named
    TODO: Agree on a file naming convention.
    TODO: What should this return or do on FAILURE?
    Mary: recommends running nmap BEFORE airodump if applicable because
    nmap in monitor mode may not work correctly.
    """
    # SSID of network user is connected to
    user_ssid = subprocess.Popen(["iwgetid", "-r"], stdout=subprocess.PIPE).communicate()[0].strip()
    ssids = subprocess.Popen(["nmcli", "-t", "-f", "SSID", "dev", "wifi"], stdout=subprocess.PIPE).communicate()[0]
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
    network = ssids_table.get_string(border=False, header=False, fields=["SSID"], start=user_input-1, end=user_input).strip()
    if network == user_ssid:
        print("You are connected to " + network + ". Running nmap...")
        # Get IPs
        # TODO: use all interfaces that start with "wl"???
        sp = subprocess.Popen(["ip", "addr", "show", "wlan0"], stdout=subprocess.PIPE)
        ips = subprocess.check_output(["grep", "inet", "-m", "1"], stdin=sp.stdout)[9:24]
        sp.wait()
        nmap_scan = open("nmap_scan", "w")
        subprocess.call(["nmap", "-n", "-Pn", "oG", "nmap_scan", ips], stdout = nmap_scan) # should we print nmap results to screen too?
        nmap_scan.close()
    else:
        print("You are not connected to " + network + ". ")

    # TODO: airodump stuff

def create_target_table():
    """
    Creates a table of potential victims.
    Allows a user to choose a victim by number, or
    all victims by pressing "A"
    """

    # TODO: Parse results from dump_network_info

    # TODO: What info does Mary need in order to execute attack?

    execute_hack()

def execute_hack():
    """
    Takes some information (WHAT?) in order to attack the victim.
    """
    pass

if __name__ == "__main__":
    # TODO: Pass variables & arguments as needed
    parse_arguments()
    dump_network_info()
    create_target_table()
    print("uber l33t haxxing just happened")
