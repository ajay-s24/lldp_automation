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
