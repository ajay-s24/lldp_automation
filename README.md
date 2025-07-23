# LLDP and NIC Diagnostics Script

## Overview

This Python script runs locally on your computer and uses SSH to connect to remote Linux servers and Juniper switches to perform network interface diagnostics. It automates:

- Discovering NICs on the remote server based on a matching string
- Checking physical link and LLDP neighbor presence before and after link resets
- Retrieving cable lengths via `ethtool` on the server or by logging into Juniper switch CLI
- Validating LLDP consistency across server reboots


## Features

- Finds network interfaces on the remote server matching a NIC description string
- Retrieves IP addresses of those interfaces
- Performs LLDP link down/up tests remotely
- Fetches and summarizes LLDP neighbor information
- Gets cable assembly length either from the server (`ethtool`) or from the Juniper switch CLI
- Saves LLDP state before reboot and compares with after reboot state


## Usage

Run the script locally on your computer.

The script will prompt you to enter:
1. Remote server hostname or IP address
2. SSH username and password for the server
3. NIC match string, could be network interface hardware name, NIC name, etc. (if left blank, uses default, which is "Broadcom Inc. and subsidiaries")
4. If multiple interfaces match, select which interface to test
5. Switch hostname/IP and SSH credentials (only if cable length via `ethtool` is unavailable)
6. Whether to reboot the server for LLDP consistency testing

## Major Functions

- read_config(): Loads NIC string config from nic_config.json.
- ssh_connect(): Connects to a remote server via SSH using Paramiko.
- get_interfaces_and_ips: Extracts IP address of a given network interface.
- run_ssh_command: Executes a command on a remote host over SSH and captures output.
- get_cable_length_ssh(): Tries to get cable length using ethtool -m.
- get_lldp_neighbors_local_ssh() / get_lldp_neighbors_summary_ssh(): Gathers LLDP info before/after reboot.
- compare_lldp_before_after(): Compares pre/post-reboot LLDP states using difflib.
- get_cable_length_from_switch(): Queries Juniper switch for cable length if ethtool fails.
- lldp_interface_exists(): Verifies if interface has LLDP data.
- test_lldp_link_down_up(): Validates LLDP neighbor disappearance/reappearance on interface admin down/up and ensures physical link is detected.

## Example Output

`NIC String from config: 'Broadcom Inc. and subsidiaries'
Enter server hostname (or IP): svl-d-ai-srv01
Enter server username: root
Enter server password: 
Enter NIC match string (default 'Broadcom Inc. and subsidiaries'): 
Found interfaces and IPs:
enp13s0np0: 10.200.3.27
enp55s0np0: 10.200.10.27
enp181s0np0: 10.200.10.20
Multiple interfaces found. Select one:
1: enp13s0np0 (10.200.3.27)
2: enp55s0np0 (10.200.10.27)
3: enp181s0np0 (10.200.10.20)
Enter choice number: 2
Selected device: enp55s0np0

Running link down/up test on interface: enp55s0np0
Testing LLDP behavior for interface 'enp55s0np0'

Initial physical link status: UP
Interfaces found: ['eno8303', 'enp13s0np0', 'enp55s0np0', 'enp181s0np0']
PASS: Interface enp55s0np0 found in LLDP neighbors initially.
Bringing interface enp55s0np0 DOWN...
PASS: Interface enp55s0np0 correctly absent from LLDP neighbors after link down.
Bringing interface enp55s0np0 UP...
Waiting for interface enp55s0np0 to appear in LLDP neighbors. Will timeout after 30 seconds.
PASS: Interface enp55s0np0 found in LLDP neighbors after link up.
Overall test: PASSED.

Switch management IP: 10.83.6.101
Local NIC MAC: 9c:5a:80:dd:c2:d9
Connected switch info for enp55s0np0:
ny-q5230-04.englab.juniper.net:
  Interface: enp55s0np0
  PortDescr: ny-q5130-04-et-0/0/2-enp13s0np0-svl-d-ai-srv01
  PortId: local 508
Cable assembly length for enp55s0np0: 2.00m
Saving LLDP data before reboot...
Reboot the server before LLDP comparison? (y/n): n
asaravanan@JNPR-MAC-T4KR7F ~ % python3 ~/Downloads/lldp_automation_folder/lldp_automation.py
NIC String from config: 'Broadcom Inc. and subsidiaries'
Enter server hostname (or IP): svl-d-ai-srv01
Enter server username: root
Enter server password: 
Enter NIC match string (default 'Broadcom Inc. and subsidiaries'): 
Found interfaces and IPs:
enp13s0np0: 10.200.3.27
enp55s0np0: 10.200.10.27
enp181s0np0: 10.200.10.20
Multiple interfaces found. Select one:
1: enp13s0np0 (10.200.3.27)
2: enp55s0np0 (10.200.10.27)
3: enp181s0np0 (10.200.10.20)
Enter choice number: 2
Selected device: enp55s0np0

Running link down/up test on interface: enp55s0np0
Testing LLDP behavior for interface 'enp55s0np0'

Initial physical link status: UP
Interfaces found: ['eno8303', 'enp13s0np0', 'enp55s0np0', 'enp181s0np0']
PASS: Interface enp55s0np0 found in LLDP neighbors initially.
Bringing interface enp55s0np0 DOWN...
PASS: Interface enp55s0np0 correctly absent from LLDP neighbors after link down.
Bringing interface enp55s0np0 UP...
Waiting for interface enp55s0np0 to appear in LLDP neighbors. Will timeout after 30 seconds.
PASS: Interface enp55s0np0 found in LLDP neighbors after link up.
Overall test: PASSED.

Switch management IP: 10.83.6.101
Local NIC MAC: 9c:5a:80:dd:c2:d9
Connected switch info for enp55s0np0:
ny-q5230-04.englab.juniper.net:
  Interface: enp55s0np0
  PortDescr: ny-q5130-04-et-0/0/2-enp13s0np0-svl-d-ai-srv01
  PortId: local 508
Cable assembly length for enp55s0np0: 2.00m
Saving LLDP data before reboot...
Reboot the server before LLDP comparison? (y/n): y

Rebooting server svl-d-ai-srv01...
Reboot command issued successfully (SSH session may close automatically).
Waiting for svl-d-ai-srv01 to become available after reboot...
Server is back online.
Waiting 30 seconds for LLDP info to populate after reboot...
Trying to retrieve LLDP data after reboot with retries...
LLDP data retrieved successfully.
LLDP data matches before and after reboot (ignoring 'age').
