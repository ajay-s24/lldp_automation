# LLDP and NIC Diagnostics Script

## Overview

This Python script runs locally on your computer and uses SSH to connect to remote Linux servers and Juniper switches to perform network interface diagnostics. It automates:

- Discovering NICs on the remote server based on a matching string
- Retrieving cable lengths via `ethtool` on the server or by logging into Juniper switch CLI
- Validating LLDP consistency across server reboots
- Validating physical connectivity with LLDP link down/up tests.
- Optional network tests such as laser on/off, Soft OIR, channelization, FEC configuration, and AE Bundle/LACP.
  
Note: The AE Bundle/LACP test only verifies the switch-side configuration, not the server-side bonding, function needs to be updated.


## Features

- Server NIC Discovery: Finds interfaces matching a NIC description string (default: "Broadcom Inc. and subsidiaries").
- Retrieves IP addresses of those interfaces
- Fetches and summarizes LLDP neighbor information
- Gets cable assembly length either from the server (`ethtool`) or from the Juniper switch CLI
- Saves LLDP state before reboot and compares with after reboot state
- Performs LLDP link down/up tests remotely
- Optional Tests:
  - LLDP link down/up test
  - Laser on/off test (switch-side)
  - Soft OIR test on all ports
  - Channelization test
  - FEC mode test
  - AE Bundle/LACP test
  - Traffic test for IPv4 and IPv6
- Server/Switch Login Handling: Can use stored credentials from a YAML file or prompt for credentials manually.


## Usage

Run the script locally on your computer.

The script will prompt you to enter:
1. NIC match string, could be network interface hardware name, NIC name, etc. (if left blank, uses default, which is "Broadcom Inc. and subsidiaries")
2. If multiple interfaces match, select which interface to test
3. Switch hostname/IP and SSH credentials (if credentials not in YAML file)
4. Whether to run optional tests
5. Whether to reboot the server for LLDP consistency testing

## Major Functions

- read_config(): Loads NIC match string configuration from nic_config.json.
- get_interfaces_and_ips(): Returns IP addresses for interfaces matching the NIC string.
- run_ssh_command(): Executes a command over SSH and captures output.
- get_lldp_neighbors_local_ssh() / get_lldp_neighbors_summary_ssh(): Retrieves LLDP info from the server.
- get_cable_length_ssh(): Attempts to get cable length using ethtool -m.
- get_cable_length_from_switch(): Queries the Juniper switch for cable length if ethtool fails.
- compare_lldp_before_after(): Compares pre- and post-reboot LLDP states.
- lldp_interface_exists(): Checks if the interface has LLDP data.
- Optional Tests:
  - test_lldp_link_down_up(): Validates LLDP neighbor disappearance and reappearance on interface down/up.
  - laser_on_off_test(): Simulates laser on/off
  - soft_oir_all_ports(): Simulates Soft Online Insertion/Removal and checks alarms before and after
  - test_channelization(): Tests various channelization modes by validating that sub-interfaces can be created and work properly at various lane/speed configurations
  - test_fec_modes(): Configures various FEC and checks interface status
  - test_ae_lacp_bundle() (switch-side only, needs server-side implementation): Configures AE bundle and enables LACP
  - run_traffic_test(): Runs traffic test for ipv4 and ipv6

## Example Output

```
NIC String from config: 'Broadcom Inc. and subsidiaries'
Available servers:
1: svl-d-ai-srv01
2: svl-d-ai-srv02
3: svl-d-ai-srv03
4: svl-d-ai-srv04
5: svl-hp-ai-srv01
6: svl-hp-ai-srv02
7: svl-hp-ai-srv03
8: svl-hp-ai-srv04
Select server number: 4
Selected server: svl-d-ai-srv04
Enter NIC match string (default 'Broadcom Inc. and subsidiaries'): 
Multiple interfaces found. Select one:
1: enp13s0np0 (10.200.10.29)
2: enp55s0np0 (10.200.10.28)
Enter choice number: 1
Selected device: enp13s0np0
Switch management IP: 10.83.6.101
Local NIC MAC: 9c:5a:80:dd:c2:d9
Connected switch info for enp13s0np0:
ny-q5230-04.englab.juniper.net:
  Interface: enp13s0np0
  PortDescr: et-0/0/56
  PortId: local 630
Using credentials for switch ny-q5230-04.englab.juniper.net from yaml file to log in.

Cable assembly length for enp13s0np0: 2.50m
Run LLDP link down/up test? (y/n): y

=== Testing LLDP behavior for interface 'enp13s0np0' ===

Initial physical link: UP
Waiting for interface enp13s0np0 to appear in LLDP neighbors. Will timeout if waiting after 120 seconds.
enp13s0np0 is present in LLDP neighbors.
PASS: Interface enp13s0np0 found in LLDP neighbors.
Bringing interface enp13s0np0 DOWN...
Waiting for interface enp13s0np0 to disappear from LLDP neighbors.  Will timeout if waiting after 120 seconds.
enp13s0np0 is no longer present in LLDP neighbors.
PASS: Interface enp13s0np0 disappeared from LLDP neighbors after link down.
Bringing interface enp13s0np0 UP...
Waiting for interface enp13s0np0 to appear in LLDP neighbors. Will timeout if waiting after 120 seconds.
enp13s0np0 is present in LLDP neighbors.
PASS: Interface enp13s0np0 reappeared in LLDP neighbors.
Overall test: PASSED.

===== Completed LLDP link down/up test for enp13s0np0 =====

Run laser on/off test for connected port? (y/n): y

===== Starting Laser ON/OFF test on et-0/0/56 =====

[WARNING] Optics diagnostics not supported on et-0/0/56, falling back to physical link check.
[Before] Laser/Link status: Up
Turning laser OFF on et-0/0/56...
[After OFF] Laser/Link status: Up
Turning laser ON on et-0/0/56...
[After ON] Laser/Link status: Up
[FAIL] Laser ON/OFF behavior NOT as expected on et-0/0/56

===== Completed Laser On/Off Test =====

Run Soft OIR test on all ports? Test time for all ports ~5 to 10 minutes (y/n): y

===== Starting Soft OIR on all active interfaces =====

Capturing alarms before Soft OIR...

Simulating Soft OIR on et-0/0/0...

Simulating Soft OIR on et-0/0/1...

Simulating Soft OIR on et-0/0/10...

Simulating Soft OIR on et-0/0/11...

Simulating Soft OIR on et-0/0/12...

Simulating Soft OIR on et-0/0/13...

Simulating Soft OIR on et-0/0/14...

Simulating Soft OIR on et-0/0/15...

Simulating Soft OIR on et-0/0/16...

Simulating Soft OIR on et-0/0/17...

Simulating Soft OIR on et-0/0/18...

Simulating Soft OIR on et-0/0/19...

Simulating Soft OIR on et-0/0/2...

Simulating Soft OIR on et-0/0/20...

Simulating Soft OIR on et-0/0/21...

Simulating Soft OIR on et-0/0/22...

Simulating Soft OIR on et-0/0/23...

Simulating Soft OIR on et-0/0/24...

Simulating Soft OIR on et-0/0/25...

Simulating Soft OIR on et-0/0/26...

Simulating Soft OIR on et-0/0/27...

Simulating Soft OIR on et-0/0/28...

Simulating Soft OIR on et-0/0/29...

Simulating Soft OIR on et-0/0/3...

Simulating Soft OIR on et-0/0/30...

Simulating Soft OIR on et-0/0/31...

Simulating Soft OIR on et-0/0/32...

Simulating Soft OIR on et-0/0/33...

Simulating Soft OIR on et-0/0/34...

Simulating Soft OIR on et-0/0/35...

Simulating Soft OIR on et-0/0/36...

Simulating Soft OIR on et-0/0/37...

Simulating Soft OIR on et-0/0/38...

Simulating Soft OIR on et-0/0/39...

Simulating Soft OIR on et-0/0/4...

Simulating Soft OIR on et-0/0/40...

Simulating Soft OIR on et-0/0/41...

Simulating Soft OIR on et-0/0/42...

Simulating Soft OIR on et-0/0/43...

Simulating Soft OIR on et-0/0/44...

Simulating Soft OIR on et-0/0/45...

Simulating Soft OIR on et-0/0/46...

Simulating Soft OIR on et-0/0/47...

Simulating Soft OIR on et-0/0/48...

Simulating Soft OIR on et-0/0/49...

Simulating Soft OIR on et-0/0/5...

Simulating Soft OIR on et-0/0/50...

Simulating Soft OIR on et-0/0/51...

Simulating Soft OIR on et-0/0/52...

Simulating Soft OIR on et-0/0/53...

Simulating Soft OIR on et-0/0/54...

Simulating Soft OIR on et-0/0/55...

Simulating Soft OIR on et-0/0/56...

Simulating Soft OIR on et-0/0/57...

Simulating Soft OIR on et-0/0/58...

Simulating Soft OIR on et-0/0/59...

Simulating Soft OIR on et-0/0/6...

Simulating Soft OIR on et-0/0/60...

Simulating Soft OIR on et-0/0/61...

Simulating Soft OIR on et-0/0/62...

Simulating Soft OIR on et-0/0/63...

Simulating Soft OIR on et-0/0/64...

Simulating Soft OIR on et-0/0/65...

Simulating Soft OIR on et-0/0/7...

Simulating Soft OIR on et-0/0/8...

Simulating Soft OIR on et-0/0/9...
Capturing alarms after Soft OIR...

--- Alarms Before ---
11 alarms currently active
Alarm time               Class  Description
2025-08-06 14:34:58 PDT  Major  Fan Tray 3 Absent
2025-08-20 06:00:00 PDT  Minor  EVPN-VXLAN feature(262) usage requires a license
2025-08-06 14:34:23 PDT  Minor  port-0/0/10: Optics does not support configured speed
2025-08-06 14:34:24 PDT  Minor  port-0/0/14: Optics does not support configured speed
2025-08-06 14:34:25 PDT  Minor  port-0/0/8: Optics does not support configured speed
2025-08-19 14:43:55 PDT  Minor  port-0/0/9: Optics does not support configured speed
2025-08-06 14:32:57 PDT  Major  PSM 0 Unit Offline
2025-08-06 14:32:57 PDT  Major  PSM 0 Input Under Voltage Failure
2025-08-06 14:32:57 PDT  Minor  PSM 0 Fan2 Fail
2025-08-06 14:32:50 PDT  Major  Host 0 Disk 2 not bootable
2025-08-06 14:33:52 PDT  Minor  Zone 0 No Redundant Power

--- Alarms After ---
11 alarms currently active
Alarm time               Class  Description
2025-08-06 14:34:58 PDT  Major  Fan Tray 3 Absent
2025-08-20 06:00:00 PDT  Minor  EVPN-VXLAN feature(262) usage requires a license
2025-08-06 14:34:23 PDT  Minor  port-0/0/10: Optics does not support configured speed
2025-08-06 14:34:24 PDT  Minor  port-0/0/14: Optics does not support configured speed
2025-08-06 14:34:25 PDT  Minor  port-0/0/8: Optics does not support configured speed
2025-08-19 14:43:55 PDT  Minor  port-0/0/9: Optics does not support configured speed
2025-08-06 14:32:57 PDT  Major  PSM 0 Unit Offline
2025-08-06 14:32:57 PDT  Major  PSM 0 Input Under Voltage Failure
2025-08-06 14:32:57 PDT  Minor  PSM 0 Fan2 Fail
2025-08-06 14:32:50 PDT  Major  Host 0 Disk 2 not bootable
2025-08-06 14:33:52 PDT  Minor  Zone 0 No Redundant Power

No change in alarms after Soft OIR.

===== Completed Soft OIR Test for all ports =====

Run channelization test? Test time ~5 to 10 minutes (y/n): y

===== Channelization Test for et-0/0/56 =====

Supported channelization modes for port 56: ['4x10', '4x25', '4x100', '2x50', '2x100', '2x200', '1x40', '1x50', '1x100', '1x200', '1x400']

--- Testing 4x10G mode ---

Sub-interfaces after channelization:

et-0/0/56:0             up    down
et-0/0/56:0.16386       up    down multiservice
et-0/0/56:1             up    down
et-0/0/56:2             up    down
et-0/0/56:2.16386       up    down multiservice
et-0/0/56:3             up    down


--- Testing 4x25G mode ---

Sub-interfaces after channelization:

et-0/0/56:0             up    down
et-0/0/56:0.16386       up    down multiservice
et-0/0/56:1             up    down
et-0/0/56:1.16386       up    down multiservice
et-0/0/56:2             up    down
et-0/0/56:2.16386       up    down multiservice
et-0/0/56:3             up    down
et-0/0/56:3.16386       up    down multiservice


--- Testing 4x100G mode ---

Sub-interfaces after channelization:

et-0/0/56:0             up    down
et-0/0/56:0.16386       up    down multiservice
et-0/0/56:1             up    down
et-0/0/56:1.16386       up    down multiservice
et-0/0/56:2             up    down
et-0/0/56:2.16386       up    down multiservice
et-0/0/56:3             up    down
et-0/0/56:3.16386       up    down multiservice


--- Testing 2x50G mode ---

Sub-interfaces after channelization:

et-0/0/56:0             up    down
et-0/0/56:0.16386       up    down multiservice
et-0/0/56:1             up    down
et-0/0/56:1.16386       up    down multiservice


--- Testing 2x100G mode ---

Sub-interfaces after channelization:

et-0/0/56:0             up    down
et-0/0/56:0.16386       up    down multiservice
et-0/0/56:1             up    down
et-0/0/56:1.16386       up    down multiservice


--- Testing 2x200G mode ---

Sub-interfaces after channelization:

et-0/0/56:0             up    up
et-0/0/56:0.16386       up    up   multiservice
et-0/0/56:1             up    down
et-0/0/56:1.16386       up    down multiservice


--- Testing 1x40G mode ---

Sub-interfaces after channelization:

et-0/0/56:0             up    down
et-0/0/56:0.16386       up    down multiservice


--- Testing 1x50G mode ---

Sub-interfaces after channelization:

et-0/0/56:0             up    down
et-0/0/56:0.16386       up    down multiservice


--- Testing 1x100G mode ---

Sub-interfaces after channelization:

et-0/0/56:0             up    down
et-0/0/56:0.16386       up    down multiservice


--- Testing 1x200G mode ---

Sub-interfaces after channelization:

et-0/0/56:0             up    down
et-0/0/56:0.16386       up    down multiservice


===== Channelization Test Summary =====
4x10G: PASS
4x25G: PASS
4x100G: PASS
2x50G: PASS
2x100G: PASS
2x200G: PASS
1x40G: PASS
1x50G: PASS
1x100G: PASS
1x200G: PASS

===== Completed Channelization Test for et-0/0/56 =====


Run FEC test (configure + verify)? (y/n): y

Starting FEC mode test on the selected interface...
=== Starting FEC mode tests on et-0/0/56 ===

Saving original configuration...

--- Testing FEC mode: fec74 ---
FEC status for interface et-0/0/56:
  FEC Mode: FEC119
  Corrected Errors: 955
  Uncorrected Errors: 0
  PRE FEC BER: 2.0625000318741e-10

[FAIL] Expected: fec74, Got: FEC119

--- Testing FEC mode: fec91 ---
FEC status for interface et-0/0/56:
  FEC Mode: FEC119
  Corrected Errors: 955
  Uncorrected Errors: 0
  PRE FEC BER: 2.0625000318741e-10

[FAIL] Expected: fec91, Got: FEC119

--- Testing FEC mode: none ---
FEC status for interface et-0/0/56:
  FEC Mode: FEC119
  Corrected Errors: 955
  Uncorrected Errors: 0
  PRE FEC BER: 2.0625000318741e-10

[FAIL] Expected: none, Got: FEC119

Restoring original configuration...

=== Completed FEC mode tests ===


Run AE Bundle test? (y/n): y

=== Testing AE LACP Bundle on ny-q5230-04 for interface et-0/0/56 ===

Selected AE ID: ae1
Selected VLAN ID: 2
Assigned local IP 11.0.1.2/24 and peer IP 11.0.1.1/24

Found unit 0 under et-0/0/56, removing...
Cleanup successful.

AE local test configuration successful on et-0/0/56.

Peer switch: N/A, Peer port: N/A
Configured et-0/0/56 into ae1 on ny-q5230-04 successfully.

LACP status on local switch:
Aggregated interface: ae1
    LACP state:           Role   Exp   Def  Dist  Col  Syn  Aggr  Timeout  Activity
      et-0/0/56          Actor   Yes   Yes    No   No   No   Yes     Fast    Active
      et-0/0/56        Partner    No   Yes    No   No   No   Yes     Fast   Passive
    LACP protocol:        Receive State  Transmit State          Mux State 
      et-0/0/56                 Expired   Fast periodic           Detached


Cleaning up AE configuration...

=== AE LACP Bundle Test Completed ===


Completed AE Bundle + LACP Test on et-0/0/56 Successfully

Run traffic test? (y/n): y

=== Traffic Test for Device: enp13s0np0 ===
Device enp13s0np0 IPv4: 10.200.10.29, IPv6: fe80::966d:aeff:fed4:6c46
Copying ~/OSTG_KR from san-ft-ai-srv01 → svl-hp-ai-srv02 ...
Running command on san-ft-ai-srv01...
Copy successful!
Starting server_ostg.py on remote server...
Waiting 5 seconds for traffic server to start...
Starting IPv4 traffic...
IPv4 traffic test: PASSED (HTTP 200)
Starting IPv6 traffic...
IPv6 traffic test: PASSED (HTTP 200)

Traffic test PASSED for both IPv4 and IPv6.

===== Completed Traffic Test for enp13s0np0 =====


Saving LLDP data before reboot...

Reboot the server? (y/n): y

Rebooting server svl-d-ai-srv04...
Reboot command issued. Waiting for server to go down...
Waiting for svl-d-ai-srv04 to become available after reboot...
Server is back online and responsive.
Waiting 30 seconds for LLDP info to populate after reboot...
Trying to retrieve LLDP data after reboot with retries...
LLDP data retrieved successfully.
LLDP data has changed after reboot. Differences:
--- before.json
+++ after.json
@@ -1,5 +1,5 @@
 {
-  "age": "0 day, 03:17:30",
+  "age": "0 day, 00:02:49",
   "chassis": {
     "ny-q5230-04.englab.juniper.net": {
       "capability": [

```
