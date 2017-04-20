#!/usr/bin/python3

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
    pass

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
