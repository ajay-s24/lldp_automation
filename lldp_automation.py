# Required Libraries
import getpass
import json
import yaml
import paramiko
import os
import time
import difflib
import re
from jnpr.junos import Device
from jnpr.junos.exception import ConnectError
from lxml import etree


# Path to local config file
CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'nic_config.json')

# Path to credentials file
CREDS_PATH = os.path.join(os.path.dirname(__file__), 'creds.yaml')

def run_ssh_command(host, username, password, command, suppress_ssh_errors=False):
    """
    Run a command on a remote host via SSH.

    Args:
        host (str): Hostname.
        username (str): SSH username.
        password (str): SSH password.
        command (str): Command to execute.
        suppress_ssh_errors (bool): If True, suppress error messages.

    Returns:
        str: Output from the command or None on failure.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, username=username, password=password)
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        ssh.close()

        if error and not error.lower().startswith('warning') and not suppress_ssh_errors:
            print(f"Error running remote command '{command}': {error.strip()}")

        return output
    except Exception as e:
        if not suppress_ssh_errors:
            print(f"SSH connection error: {e}")
        return None
    
def get_active_interfaces(host, username, password):
    output = run_ssh_command(host, username, password, 'cli -c "show interfaces terse | match et-"')
    interfaces = set()
    for line in output.splitlines():
        match = re.match(r'^(et-\d+/\d+/\d+)', line)
        if match:
            interfaces.add(match.group(1))
    return sorted(interfaces)

def get_tx_laser_disabled_alarm(host, username, password, interface):
    """
    Fetch the 'Tx laser disabled alarm' state for a specific interface on the Juniper switch.

    Args:
        host (str): IP or hostname of the switch.
        username (str): SSH username.
        password (str): SSH password.
        interface (str): Target interface string (may include hostname suffixes).

    Returns:
        str: 'On', 'Off', or 'Unknown'
    """
    try:
        # Extract base interface from input (e.g., et-0/0/47 from ny-q5230-04-et-0/0/47-ens5np0...)
        base_iface_match = re.search(r'(?:ge|et|xe|lt)-\d+/\d+/\d+', interface)
        if not base_iface_match:
            print(f"[WARN] Could not extract base interface from '{interface}'")
            return "Unknown"
        base_iface = base_iface_match.group(0)

        command = 'cli -c "show interfaces diagnostics optics | no-more"'
        output = run_ssh_command(host, username, password, command)
        if not output:
            print("[ERROR] Empty output from optics diagnostics command")
            return "Unknown"

        lines = output.splitlines()
        current_iface = None
        in_target_iface_block = False
        in_lane_section = False

        for line in lines:
            line = line.strip()

            # Detect interface block start, interface can have suffix like :0 or .0
            iface_match = re.match(r'^Physical interface:\s+(\S+)', line)
            if iface_match:
                current_iface_full = iface_match.group(1)  # e.g., et-0/0/0:0
                # Extract base iface by stripping suffixes like :0 or .0
                current_iface_base = re.sub(r'[:.]\d+$', '', current_iface_full)
                in_target_iface_block = (current_iface_base == base_iface)
                in_lane_section = False
                continue

            if not in_target_iface_block:
                continue

            # Detect lane section start
            if re.match(r'^Lane \d+', line):
                in_lane_section = True
                continue

            # If inside lane section and line has the Tx laser disabled alarm
            if in_lane_section and 'Tx laser disabled alarm' in line:
                state_match = re.search(r'Tx laser disabled alarm\s*:\s*(\S+)', line)
                if state_match:
                    return state_match.group(1)

        return "Unknown"

    except Exception as e:
        print(f"[ERROR] Exception while fetching laser alarm for {interface}: {e}")
        return "Unknown"

    except Exception as e:
        print(f"[ERROR] Failed to fetch laser alarm state for {interface}: {e}")
        return "Unknown"

def laser_on_off_test(host, username, password, interface):
    print(f"\nStarting Laser ON/OFF test on interface {interface}")

    before = get_tx_laser_disabled_alarm(host, username, password, interface)
    print(f"[Before] Tx laser disabled alarm: {before}")

    # Deactivate interface (laser off)
    cmds_deactivate = [
        f"deactivate interfaces {interface}",
    ]
    for cmd in cmds_deactivate:
        run_ssh_command(host, username, password, f'cli -c "{cmd}"')
    run_ssh_command(host, username, password, 'cli -c "commit"')
    time.sleep(3)

    after_deactivate = get_tx_laser_disabled_alarm(host, username, password, interface)
    print(f"[After Deactivate] Tx laser disabled alarm: {after_deactivate}")

    # Reactivate interface (laser on)
    cmds_activate = [
        f"activate interfaces {interface}",
    ]
    for cmd in cmds_activate:
        run_ssh_command(host, username, password, f'cli -c "{cmd}"')
    run_ssh_command(host, username, password, 'cli -c "commit"')
    time.sleep(3)

    after_reactivate = get_tx_laser_disabled_alarm(host, username, password, interface)
    print(f"[After Reactivate] Tx laser disabled alarm: {after_reactivate}")

    # Evaluate expected behavior:
    # Before deactivate: laser disabled alarm should be Off (laser enabled)
    # After deactivate: laser disabled alarm should be On (laser off)
    # After reactivate: laser disabled alarm should be Off again (laser enabled)
    if before == 'Off' and after_deactivate == 'On' and after_reactivate == 'Off':
        print(f"[PASS] Laser ON/OFF behavior validated successfully on {interface}\n")
        return True
    else:
        print(f"[FAIL] Laser ON/OFF behavior NOT as expected on {interface}\n")
        return False

def get_alarms(host, username, password):
    return run_ssh_command(host, username, password, 'cli -c "show chassis alarms"')

def soft_oir_on_interface(host, username, password, interface):
    print(f"\nSimulating Soft OIR on {interface}...")

    # Deactivate all related config
    deactivate_cmds = [
        f"deactivate interfaces {interface}",
        f"deactivate routing-instances evpn-1 interface {interface}.0",
        f"deactivate protocols rstp interface {interface}"
    ]
    for cmd in deactivate_cmds:
        run_ssh_command(host, username, password, f'cli -c "{cmd}"')

    run_ssh_command(host, username, password, 'cli -c "commit"')
    time.sleep(2)

    # Reactivate
    activate_cmds = [
        f"activate interfaces {interface}",
        f"activate routing-instances evpn-1 interface {interface}.0",
        f"activate protocols rstp interface {interface}"
    ]
    for cmd in activate_cmds:
        run_ssh_command(host, username, password, f'cli -c "{cmd}"')

    run_ssh_command(host, username, password, 'cli -c "commit"')

def soft_oir_all_ports(host, username, password):
    print("\nCapturing alarms before Soft OIR...")
    alarms_before = get_alarms(host, username, password)

    interfaces = get_active_interfaces(host, username, password)

    for iface in interfaces:
        soft_oir_on_interface(host, username, password, iface)

    print("Capturing alarms after Soft OIR...")
    alarms_after = get_alarms(host, username, password)

    print("\n--- Alarms Before ---")
    print(alarms_before.strip())

    print("\n--- Alarms After ---")
    print(alarms_after.strip())

    if alarms_before == alarms_after:
        print("\nNo change in alarms after Soft OIR.")
    else:
        print("\nAlarms changed after Soft OIR. Differences:")
        before_lines = alarms_before.splitlines()
        after_lines = alarms_after.splitlines()
        diff = difflib.unified_diff(before_lines, after_lines, fromfile='Before', tofile='After', lineterm='')
        for line in diff:
            print(line)

def select_server(servers):
    print("Available servers:")
    for idx, srv in enumerate(servers, 1):
        print(f"{idx}: {srv['name']}")
    choice = input("Select server number: ").strip()
    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(servers):
        print("Invalid choice.")
        return None
    return servers[int(choice) - 1]

def get_switch_creds(switches, switch_name):
    for switch in switches:
        if switch['name'] == switch_name:
            return switch['username'], switch['password']
    print(f"No credentials found for switch '{switch_name}'")
    return None, None

def get_capable_speeds_from_pic(server_ip, username, password, port_num):
    """
    Fetch and parse 'show chassis pic' output for the given port_num
    to extract capable port speeds like '1x400G', '4x100G', etc.

    Returns:
        List of tuples: [(num_sub_ports, speed_per_subport), ...]
    """
    cmd = f"cli -c 'show chassis pic fpc-slot 0 pic-slot 0 | match \"^ *{port_num} \"'"
    output = run_ssh_command(server_ip, username, password, cmd)
    
    # Example line format:
    #  24     0       1x400G 1x200G 4x10G 1x40G 4x25G 1x100G 4x100G 2x100G 2x200G 2x50G 1x50G
    # Extract all "NxM G" patterns (like 4x100G)
    modes = []
    pattern = re.compile(r'(\d+)x(\d+)G', re.IGNORECASE)
    
    for match in pattern.finditer(output):
        lanes = int(match.group(1))
        speed = int(match.group(2))
        modes.append((lanes, speed))
    
    # Sort by lanes desc (prefer more sub-ports first), then speed asc
    modes = sorted(modes, key=lambda x: (-x[0], x[1]))

    return modes

def test_channelization(server_ip, username, password, interface, port_num):
    print(f"\n===== Channelization Test for {interface} =====")

    # Step 1: Get original speed
    try:
        media_before = run_ssh_command(server_ip, username, password,
            f"cli -c 'show interfaces {interface} media'")
        speed_match = re.search(r'Speed: (\d+)g', media_before, re.IGNORECASE)
        original_speed = int(speed_match.group(1)) if speed_match else None
        if not original_speed:
            print("Could not parse original speed, defaulting to 400")
            original_speed = 400
    except Exception as e:
        print(f"Failed to get original speed: {e}")
        original_speed = 400

    # Step 2: Get supported modes from chassis PIC output for this port number
    try:
        modes = get_capable_speeds_from_pic(server_ip, username, password, port_num)
        mode_strings = [f"{lanes}x{speed}" for lanes, speed in modes]
        print(f"Supported channelization modes for port {port_num}: {mode_strings}")
    except Exception as e:
        print(f"Failed to get capable speeds from PIC: {e}")
        modes = []

    results = {}

    for lanes, speed in modes:
        if lanes == 1 and speed == original_speed:
            continue

        mode_str = f"{lanes}x{speed}G"
        print(f"\n--- Testing {mode_str} mode ---")

        try:
            # Apply channelization
            cmds = [
                f"set interfaces {interface} number-of-sub-ports {lanes}",
                f"set interfaces {interface} speed {speed}g"
            ]
            channelize_cmd = "cli -c 'configure; " + " ; ".join(cmds) + " ; commit and-quit'"
            run_ssh_command(server_ip, username, password, channelize_cmd)
            time.sleep(10)

            # Verify sub-interfaces
            sub_intf_status = run_ssh_command(
                server_ip, username, password,
                f"cli -c 'show interfaces terse | match \"{interface}([^0-9]|$)\"'"
            )
            print("\nSub-interfaces after channelization:\n")
            print(sub_intf_status)

            # Revert to original speed
            revert_cmds = [
                f"delete interfaces {interface} number-of-sub-ports",
                f"set interfaces {interface} speed {original_speed}g"
            ]
            dechannel_cmd = "cli -c 'configure; " + " ; ".join(revert_cmds) + " ; commit and-quit'"
            run_ssh_command(server_ip, username, password, dechannel_cmd)
            time.sleep(10)
            sub_interfaces_found = bool(re.search(rf"{re.escape(interface)}:\d+", sub_intf_status))
            revert_cmds = [
                f"delete interfaces {interface} number-of-sub-ports",
                f"set interfaces {interface} speed {original_speed}g"
            ]
            dechannel_cmd = "cli -c 'configure; " + " ; ".join(revert_cmds) + " ; commit and-quit'"
            run_ssh_command(server_ip, username, password, dechannel_cmd)
            time.sleep(10)
            if sub_interfaces_found:
                results[mode_str] = "PASS"
            else:
                results[mode_str] = "FAIL (No sub-interfaces found)"
        except Exception as e:
            print(f"Error during testing {mode_str} mode: {e}")
            results[mode_str] = f"FAIL - {e}"

            # Try to revert safely in case of failure
            try:
                revert_cmds = [
                    f"delete interfaces {interface} number-of-sub-ports",
                    f"set interfaces {interface} speed {original_speed}g"
                ]
                dechannel_cmd = "cli -c 'configure; " + " ; ".join(revert_cmds) + " ; commit and-quit'"
                run_ssh_command(server_ip, username, password, dechannel_cmd)
                time.sleep(10)
            except Exception as revert_err:
                print(f"Failed to revert interface after error: {revert_err}")

    print("\n===== Channelization Test Summary =====")
    for mode, status in results.items():
        print(f"{mode}: {status}")

    print(f"\n===== Completed Channelization Test for {interface} =====\n")

def lldp_interface_exists(server_ip, username, password, interface):
    """
    Check if interface is shown in 'lldpcli show neighbors'.
    Returns True if interface is present, else False.
    """
    output = run_ssh_command(server_ip, username, password, 'lldpcli show neighbors')
    if not output:
        print("Failed to get LLDP neighbors.")
        return False

    # Look for lines starting with 'Interface:' and check if interface matches
    interfaces = [iface.rstrip(',') for iface in re.findall(r'Interface:\s+(\S+)', output, re.IGNORECASE)]
    return interface in interfaces

def is_link_up(server_ip, username, password, interface):
    """
    Determine whether the network interface has a physical link.
    Uses /sys/class/net/{interface}/operstate which is widely supported.
    """
    output = run_ssh_command(server_ip, username, password, f"cat /sys/class/net/{interface}/operstate")
    return output and output.strip().lower() == "up"

def test_lldp_link_down_up(server_ip, username, password, interface):
    """
    Test LLDP behavior for interface with physical link check:
    1. Ensure link is UP; if not, bring it up.
    2. Confirm interface is in LLDP neighbors.
    3. Bring interface DOWN and verify it's gone from LLDP neighbors.
    4. Bring it UP again and confirm it's back in LLDP neighbors.
    """

    print(f"\n=== Testing LLDP behavior for interface '{interface}' ===\n")

    # Step 0: Check link status
    if is_link_up(server_ip, username, password, interface):
        print(f"Initial physical link: UP")
    else:
        print(f"Initial physical link: DOWN – trying to bring it UP...")
        run_ssh_command(server_ip, username, password, f"ip link set dev {interface} up")
        time.sleep(3)
        if is_link_up(server_ip, username, password, interface):
            print(f"Link is UP now.")
        else:
            print(f"FAIL: Couldn't bring link UP.")
            return False

    # Step 1: Check presence in LLDP neighbors
    if wait_for_interface_in_lldp(server_ip, username, password, interface):
        print(f"PASS: Interface {interface} found in LLDP neighbors.")
    else:
        print(f"FAIL: Interface {interface} NOT found in LLDP neighbors.")
        return False

    # Step 2: Bring interface DOWN
    print(f"Bringing interface {interface} DOWN...")
    run_ssh_command(server_ip, username, password, f"ip link set dev {interface} down")
    if wait_for_interface_not_in_lldp(server_ip, username, password, interface):
        print(f"PASS: Interface {interface} disappeared from LLDP neighbors after link down.")
    else:
        print(f"FAIL: Interface {interface} still present in LLDP after link down.")
        run_ssh_command(server_ip, username, password, f"ip link set dev {interface} up")
        return False

    # Step 3: Bring interface back UP
    print(f"Bringing interface {interface} UP...")
    run_ssh_command(server_ip, username, password, f"ip link set dev {interface} up")
    if wait_for_interface_in_lldp(server_ip, username, password, interface):
        print(f"PASS: Interface {interface} reappeared in LLDP neighbors.")
        return True
    else:
        print(f"FAIL: Interface {interface} NOT found in LLDP neighbors after link up.")
        return False


def wait_for_interface_in_lldp(server_ip, username, password, interface, timeout=120, interval=2):
    """
    Wait up to timeout seconds for interface to appear in lldpcli neighbors, checking every interval seconds.
    Returns True if interface is present, False if timeout reached.
    """
    print(f"Waiting for interface {interface} to appear in LLDP neighbors. Will timeout if waiting after {timeout} seconds.")
    start = time.time()
    while time.time() - start < timeout:
        output = run_ssh_command(server_ip, username, password, 'lldpcli show neighbors')
        if output is None:
            print("Warning: Failed to get LLDP output. Retrying...")
            time.sleep(interval)
            continue
        interfaces = [iface.rstrip(',') for iface in re.findall(r'Interface:\s+(\S+)', output, re.IGNORECASE)]
        if interface in interfaces:
            print(f"{interface} is present in LLDP neighbors.")
            return True
        time.sleep(interval)
    print(f"{interface} not found after {timeout} seconds.")
    return False

def wait_for_interface_not_in_lldp(server_ip, username, password, interface, timeout=120, interval=2):
    """
    Wait up to timeout seconds for interface to disappear from lldpcli neighbors, checking every interval seconds.
    Returns True if interface disappears, False if still present after timeout.
    """
    print(f"Waiting for interface {interface} to disappear from LLDP neighbors.  Will timeout if waiting after {timeout} seconds.")
    start = time.time()
    while time.time() - start < timeout:
        output = run_ssh_command(server_ip, username, password, 'lldpcli show neighbors')
        if output:
            # Find all interfaces listed in LLDP output
            matches = re.findall(r'Interface:\s+(\S+)', output, re.IGNORECASE)
            interfaces = [iface.strip(',') for iface in matches]

            if interface not in interfaces:
                print(f"{interface} is no longer present in LLDP neighbors.")
                return True
        else:
            # No LLDP output, wait and retry
            print("Warning: No LLDP output. Retrying...")
        
        time.sleep(interval)

    print(f"{interface} still present in LLDP neighbors after {timeout} seconds.")
    return False

def read_config():
    """
    Load NIC configuration from a JSON file.

    Returns:
        dict: Dictionary containing NIC configuration, or empty dict on failure.
    """
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading config file: {e}")
        return {}

def read_creds():
    """
    Load device credentials from a YAML file.

    Returns:
        dict: Dictionary containing server and switch credentials, or empty dict on failure.
    """
    try:
        with open(CREDS_PATH) as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error reading credentials file: {e}")
        return {}

def run_ssh_command(host, username, password, command, suppress_ssh_errors=False):
    """
    Run a command on a remote host via SSH.

    Args:
        host (str): Hostname.
        username (str): SSH username.
        password (str): SSH password.
        command (str): Command to execute.
        suppress_ssh_errors (bool): If True, suppress error messages.

    Returns:
        str: Output from the command or None on failure.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, username=username, password=password)
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        ssh.close()
        if error and not error.lower().startswith('warning'):
            if not suppress_ssh_errors:
                print(f"Error running remote command '{command}': {error.strip()}")
        return output
    except Exception as e:
        if not suppress_ssh_errors:
            print(f"SSH connection error: {e}")
        return None

def get_lldp_neighbors_local_ssh(server_ip, username, password, interface):
    """
    Retrieve LLDP neighbor information for a specific interface on the server.

    Args:
        server_ip (str): Server IP.
        username (str): SSH username.
        password (str): SSH password.
        interface (str): Network interface name.

    Returns:
        dict or None: LLDP info for that interface or None if not found.
    """
    cmd = 'lldpcli -f json show neighbors'
    output = run_ssh_command(server_ip, username, password, cmd)
    if not output:
        return None
    try:
        data = json.loads(output)
        interface_list = data.get('lldp', {}).get('interface', [])
        for iface_dict in interface_list:
            for iface_name in iface_dict:
                if iface_name.strip().lower() == interface.strip().lower():
                    return iface_dict[iface_name]
        print(f"Interface {interface} not found in LLDP neighbor data.")
    except Exception as e:
        print(f"Error parsing LLDP JSON: {e}")
    return None

def get_interfaces_and_ips(server_hostname, username, password, nic_match_str):
    """
    Discover interfaces on a server that match a NIC string and retrieve their IPs.

    Args:
        server_hostname (str): Server hostname.
        username (str): SSH username.
        password (str): SSH password.
        nic_match_str (str): NIC description match string (e.g., "Broadcom Inc. and subsidiaries").

    Returns:
        dict: Mapping of interface names to IP addresses.
    """
    # Get hardware info of network devices
    lshw_output = run_ssh_command(server_hostname, username, password, 'lshw -C network -businfo')
    if not lshw_output:
        print("Failed to get network hardware info.")
        return {}

    interfaces = []
    for line in lshw_output.splitlines():
        # Look for NIC match string (case-insensitive)
        if nic_match_str.lower() in line.lower():
            parts = line.split()
            if len(parts) >= 2:
                interfaces.append(parts[1]) # Interface name

    if not interfaces:
        print(f"No interfaces matching '{nic_match_str}' found.")
        return {}

    iface_ip_map = {}
    for iface in interfaces:
        ifconfig_output = run_ssh_command(server_hostname, username, password, f'ifconfig {iface}')
        ip = None
        if ifconfig_output:
            for line in ifconfig_output.splitlines():
                line = line.strip()
                if line.startswith('inet '):
                    ip = line.split()[1]
                    break
        iface_ip_map[iface] = ip or "No IP found"

    return iface_ip_map

def get_cable_length_ssh(server_ip, username, password, interface, nic_string):
    """
    Try to get the cable length using ethtool.

    Args:
        server_ip (str): Server IP.
        username (str): SSH username.
        password (str): SSH password.
        interface (str): Interface name.
        nic_string (str): NIC identifier.

    Returns:
        str or None: Cable length string or None if not found.
    """
    if not nic_string:
        print("NIC string not specified, skipping cable assembly length check")
        return None

    # Use ethtool -m for all NICs
    cmd_ethtool = f"ethtool -m {interface}"
    output = run_ssh_command(server_ip, username, password, cmd_ethtool)

    if not output:
        print(f"ethtool -m returned no output for interface {interface}")
        return None

    for line in output.splitlines():
        if 'Cable assembly length' in line or 'Length (Copper)' in line:
            return line.split(":", 1)[1].strip()

    print(f"No cable length info found in ethtool output for {interface}")
    return None

def get_cable_length_from_switch(switch_host, switch_user, switch_pass, port_descr=None):
    """
    Retrieve cable length info from Juniper switch CLI based on port descriptor.

    Args:
        switch_host (str): Switch IP/hostname.
        switch_user (str): SSH username.
        switch_pass (str): SSH password.
        port_descr (str): Port descriptor string (e.g., et-0/0/4).

    Returns:
        str or None: Cable length or None if not found.
    """
    if not port_descr:
        print("Full port description not provided.")
        return None

    # Extract port number from port_descr (e.g., et-0/0/52 -> 52)
    match = re.search(r'(?:ge|et|xe|lt)-\d+/\d+/(\d+)', port_descr)
    if not match:
        print(f"Could not extract port number from PortDescr '{port_descr}'")
        return None
    port_number = match.group(1)
    print(f"Extracted port number '{port_number}' from PortDescr '{port_descr}'")

    # Run JunOS CLI command to find DAC/AEC cable lengths (excluding 1x400G)
    cmd = 'cli -c "show chassis pic fpc-slot 0 pic-slot 0 | match \\"DAC|AEC\\" | except \\"1x400G\\""'
    cable_output = run_ssh_command(switch_host, switch_user, switch_pass, cmd)
    if not cable_output:
        print("Failed to retrieve chassis PIC info from switch.")
        return None

    # Find matching port number in output and return cable length
    for line in cable_output.splitlines():
        parts = line.strip().split()
        if len(parts) < 4:
            continue
        current_port = parts[0]
        length = parts[3]
        if current_port == port_number:
            print(f"Matched port number '{port_number}' -> cable length: {length}")
            return length

    print(f"No matching cable entry found on switch for port number '{port_number}'")
    return None

def get_lldp_neighbors_summary_ssh(server_hostname, username, password, target_interface=None):
    """
    Parse and summarize LLDP neighbor info (interface/sysname/portdescr/portid).

    Args:
        server_hostname (str): Server IP or hostname.
        username (str): SSH user.
        password (str): SSH password.
        target_interface (str or None): If provided, filter only this interface.

    Returns:
        dict: Summary with sysname as key and interface/port details.
    """
    # Include PortId by grepping for "porti"
    cmd = 'lldpcli show neighbors | egrep -i "sysname|portd|porti|interface"'
    output = run_ssh_command(server_hostname, username, password, cmd)
    if not output:
        print("No LLDP neighbor summary found on server.")
        return None

    summary = {}
    current_interface = None
    current_sysname = None
    current_portdescr = None
    current_portid = None

    for line in output.splitlines():
        line = line.strip()

        if line.lower().startswith("interface:"):
            # If we already collected a full entry, store it before moving on
            if current_interface and current_sysname and (current_portdescr or current_portid):
                if (target_interface is None) or (target_interface == current_interface):
                    summary[current_sysname] = {
                        "Interface": current_interface,
                        "PortDescr": current_portdescr or "N/A",
                        "PortId": current_portid or "N/A"
                    }
            # Start new block
            current_interface = line.split(":", 1)[1].strip().split(",")[0]
            current_sysname = current_portdescr = current_portid = None

        elif line.lower().startswith("sysname:"):
            current_sysname = line.split(":", 1)[1].strip()

        elif line.lower().startswith("portdescr:"):
            current_portdescr = line.split(":", 1)[1].strip()

        elif line.lower().startswith("portid:"):
            current_portid = line.split(":", 1)[1].strip()

    # Final catch for last entry
    if current_interface and current_sysname and (current_portdescr or current_portid):
        if (target_interface is None) or (target_interface == current_interface):
            summary[current_sysname] = {
                "Interface": current_interface,
                "PortDescr": current_portdescr or "N/A",
                "PortId": current_portid or "N/A"
            }

    return summary

def extract_switch_hostname(port_descr):
    """
    Extract switch hostname prefix from port descriptor.

    Args:
        port_descr (str): Port descriptor (e.g., qfx3500-et-0/0/3).

    Returns:
        str or None: Hostname (e.g., 'qfx3500') or None.
    """
    match = re.match(r"([a-zA-Z0-9\-]+)-et", port_descr)
    return match.group(1) if match else None

def save_lldp_to_file(data, filename="lldp_before_reboot.json"):
    """
    Save LLDP JSON data to a file.

    Args:
        data (dict): LLDP data.
        filename (str): Output filename.
    """
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Error saving LLDP data: {e}")

def load_lldp_from_file(filename="lldp_before_reboot.json"):
    """
    Load LLDP JSON data from a file.

    Args:
        filename (str): Input filename.

    Returns:
        dict or None: Loaded LLDP data or None.
    """
    try:
        with open(filename) as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading LLDP data: {e}")
        return None

def wait_for_host_ssh(host, username, password, timeout=600, interval=10):
    """
    Wait for server to become reachable and responsive after reboot.
    """
    print(f"Waiting for {host} to become available after reboot...")
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, username=username, password=password, timeout=10)

            # Use a meaningful shell-level command
            stdin, stdout, stderr = ssh.exec_command("uptime")
            output = stdout.read().decode().strip()
            ssh.close()

            if output and "load average" in output:
                print("Server is back online and responsive.")
                return True

        except Exception:
            pass

        time.sleep(interval)

    print(f"Timed out waiting for {host} to come back online.")
    return False

def remove_age_fields(obj):
    """
    Recursively remove 'age' fields from nested JSON objects.

    Args:
        obj (dict or list): LLDP data.

    Returns:
        Cleaned object without 'age' fields.
    """
    if isinstance(obj, dict):
        return {k: remove_age_fields(v) for k, v in obj.items() if k != "age"}
    elif isinstance(obj, list):
        return [remove_age_fields(i) for i in obj]
    return obj

def compare_lldp_before_after(server_host, server_user, server_pass, interface):
    """
    Compare LLDP info from before and after reboot.

    Args:
        server_host (str): Server hostname.
        server_user (str): Username.
        server_pass (str): Password.
        interface (str): Network interface.
    """
    # Load pre-reboot LLDP
    before_data = load_lldp_from_file()
    if not before_data:
        print("No LLDP baseline data found.")
        return

    # Retrieve LLDP data after reboot
    after_data = get_lldp_neighbors_local_ssh(server_host, server_user, server_pass, interface)
    if not after_data:
        print("Failed to retrieve LLDP data after reboot.")
        return

    # Strip age fields
    before_stripped = remove_age_fields(before_data)
    after_stripped = remove_age_fields(after_data)

    # Convert to formatted JSON strings
    before_str = json.dumps(before_stripped, indent=2, sort_keys=True)
    after_str = json.dumps(after_stripped, indent=2, sort_keys=True)

    # Compare ignoring 'age' fields
    if before_str == after_str:
        print("LLDP data matches before and after reboot (ignoring 'age').")
    else:
        print("LLDP data has changed after reboot (ignoring 'age'). Differences:")
        diff = difflib.unified_diff(
            before_str.splitlines(),
            after_str.splitlines(),
            fromfile='before.json',
            tofile='after.json',
            lineterm=''
        )
        for line in diff:
            print(line)

def reboot_server_ssh(host, username, password):
    """
    Reboot a remote Linux server over SSH.
    """
    try:
        print(f"\nRebooting server {host}...")
        run_ssh_command(host, username, password, "nohup reboot >/dev/null 2>&1 &", suppress_ssh_errors=True)
        print("Reboot command issued. Waiting for server to go down...")
        time.sleep(10)  # Give it time to drop the session
    except Exception as e:
        print(f"Failed to send reboot command: {e}")

def wait_for_lldp_ready(server_host, server_user, server_pass, interface, timeout=120, interval=10):
    """
    Wait silently for LLDP data to become available after reboot.

    Args:
        server_host (str): Hostname/IP.
        server_user (str): SSH user.
        server_pass (str): SSH password.
        interface (str): Network interface.
        timeout (int): Maximum total wait time in seconds.
        interval (int): Delay between attempts in seconds.

    Returns:
        dict or None: LLDP neighbor data or None if unavailable.
    """
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            lldp_data = get_lldp_neighbors_local_ssh(server_host, server_user, server_pass, interface)
            if lldp_data:
                print("LLDP data retrieved successfully.")
                return lldp_data
        except:
            pass
        time.sleep(interval)

    print("Failed to retrieve LLDP data after timeout.")
    return None

def main():
    """
    Main entry point for the NIC and LLDP diagnostics script.

    This function performs the following steps:
    1. Reads NIC match string from a configuration file.
    2. Prompts the user for server credentials and NIC match string (just click 'enter' to go ahead with default match string).
    3. Retrieves interfaces and their IP addresses matching the NIC string.
    4. Allows the user to select a device if multiple matches are found.
    5. Retrieves LLDP neighbor data for the selected interface.
    6. Displays LLDP neighbor and switch management IP info.
    7. Attempts to retrieve cable length info using ethtool. If unavailable,
       falls back to querying the switch.
    8. Saves LLDP data before reboot.
    9. Optionally reboots the server and waits for it to come back online.
    10. Retrieves and compares LLDP data before and after reboot, ignoring 'age' fields.

    This script requires the server and switch to support SSH connections and
    the necessary commands (`lldpcli`, `ethtool`, JunOS CLI).

    User input is required for server and switch login credentials, and NIC match strings.
    """
    config = read_config()
    nic_string_from_conf = config.get("NIC String", "")

    print(f"NIC String from config: '{nic_string_from_conf}'")

    creds = read_creds()

    # Step 1: Select server at start
    server = None
    while not server:
        server = select_server(creds.get('servers', []))
    print(f"Selected server: {server['name']}")

    # Use server credentials here for SSH etc.
    server_host = server['name']
    server_user = server['username']
    server_pass = server['password']

    # Prompt for NIC match string, fallback to config if empty
    user_match_string = input(f"Enter NIC match string (default '{nic_string_from_conf}'): ").strip()
    if not user_match_string:
        user_match_string = nic_string_from_conf
        if not user_match_string:
            print("NIC match string is required.")
            return

    # Get interfaces and IPs matching NIC string
    iface_ip_map = get_interfaces_and_ips(server_host, server_user, server_pass, user_match_string)
    if not iface_ip_map:
        return

    print("Found interfaces and IPs:")
    for iface, ip in iface_ip_map.items():
        print(f"{iface}: {ip}")

    # If multiple interfaces found, prompt user to select one
    if len(iface_ip_map) > 1:
        interfaces = list(iface_ip_map.keys())
        print("Multiple interfaces found. Select one:")
        for idx, iface in enumerate(interfaces):
            print(f"{idx+1}: {iface} ({iface_ip_map[iface]})")
        choice = input("Enter choice number: ").strip()
        try:
            device = interfaces[int(choice) - 1]
        except:
            print("Invalid choice.")
            return
    else:
        device = next(iter(iface_ip_map))

    print(f"Selected device: {device}")

    # Retrieve LLDP data for the selected interface
    local_lldp = get_lldp_neighbors_local_ssh(server_host, server_user, server_pass, device)
    if not local_lldp:
        print(f"No LLDP data found for interface {device}")
        return

    # Extract switch management IP from LLDP chassis info if available
    chassis = local_lldp.get('chassis', {})
    switch_ip = None
    if chassis:
        for chassis_name, details in chassis.items():
            switch_ip = details.get('mgmt-ip')
            if switch_ip:
                break

    if not switch_ip:
        print("Switch management IP not found in LLDP data.")
    else:
        print(f"Switch management IP: {switch_ip}")

    # Extract local NIC MAC address from LLDP data
    local_mac = None
    if chassis:
        for chassis_name, details in chassis.items():
            mac_id = details.get('id', {})
            if mac_id and 'value' in mac_id:
                local_mac = mac_id['value']
                break

    if not local_mac:
        print("Could not find MAC address of local NIC in LLDP data.")
    else:
        print(f"Local NIC MAC: {local_mac}")
    
    # Retrieve summary of LLDP neighbors with interface and port description
    lldp_summary = get_lldp_neighbors_summary_ssh(server_host, server_user, server_pass, target_interface=device)
    if lldp_summary:
        print(f"Connected switch info for {device}:")
        for sysname, data in lldp_summary.items():
            print(f"{sysname}:")
            for key, val in data.items():
                print(f"  {key}: {val}")
    else:
        print("No LLDP neighbor summary data found.")

    # Attempt to get cable length via ethtool
    cable_len = get_cable_length_ssh(server_host, server_user, server_pass, device, user_match_string)
    port_descr = None
    if cable_len:
        print(f"Cable assembly length for {device}: {cable_len}")  
    else:
        print(f"No cable assembly length info available for {device} by using ethtool.\nAttempting to get cable lengths from switch...")

        switch_sysname = next(
            (key for key, entry in lldp_summary.items()
             if entry.get("Interface", "").lower() == device.lower()),
            None
        )
        creds = read_creds()

    # Normalize to short name (strip domain if present)
    if switch_sysname and '.' in switch_sysname:
        switch_shortname = switch_sysname.split('.')[0]
    else:
        switch_shortname = switch_sysname

    # Try to find switch credentials in creds.yaml
    switch_info = next(
        (s for s in creds.get('switches', []) if s['name'] == switch_shortname),
        None
    )

    if lldp_summary and switch_sysname:
            port_descr = lldp_summary[switch_sysname].get("PortDescr")
    match = re.search(r'(?:ge|et|xe|lt)-\d+/\d+/(\d+)', port_descr)
    retry = 'y'
    if switch_info:
        switch_user = switch_info['username']
        switch_pass = switch_info['password']
        print(f"Using credentials for switch {switch_sysname} from yaml file to log in.\n")
    else:
        print(f"Switch {switch_sysname} not found in creds.yaml. Please enter credentials manually.")
        while True:
            switch_user = input("Enter switch username: ").strip()
            switch_pass = getpass.getpass("Enter switch password: ")

            # Try a harmless command to validate credentials
            test_result = run_ssh_command(switch_sysname, switch_user, switch_pass, "show version")

            if test_result == "AUTH_ERROR":
                print("Incorrect username or password.")
            elif test_result is None:
                print("Could not connect to switch (check hostname or network).")
            else:
                print("Switch login successful.\n")
                break

            retry = input("Try logging in again? (y/n): ").strip().lower()
            if retry != 'y':
                print("Skipping switch-related tests.\n")
                switch_user = None
                switch_pass = None
                break

    print(f"Querying cable lengths and interfaces from switch {switch_shortname}...")
    if lldp_summary and switch_sysname:
        port_descr = lldp_summary[switch_sysname].get("PortDescr")

    # Get cable length info from switch CLI
    switch_cable_info = get_cable_length_from_switch(switch_shortname, switch_user, switch_pass, port_descr)
    if switch_cable_info:
        print(f"Cable length reported by switch for port descr '{port_descr}': {switch_cable_info}")
    else:
        print("Failed to retrieve cable length info from switch.")

    # Call the link down/up test
    run_link_test = input("Run LLDP link down/up test? (y/n): ").strip().lower()
    if run_link_test == 'y':
        link_test_result = test_lldp_link_down_up(server_host, server_user, server_pass, device)
        print(f"Overall test: {'PASSED' if link_test_result else 'FAILED'}.\n")
        print(f"===== Completed LLDP link down/up test for {device} =====\n")
    else:
        print("\nSkipped LLDP link down/up test.\n")

    # Extract switch name from LLDP summary
    switch_sysname = next(
        (key for key, entry in lldp_summary.items()
            if entry.get("Interface", "").lower() == device.lower()),
        None
    )

    creds = read_creds()

    # Normalize to short name (strip domain if present)
    if switch_sysname and '.' in switch_sysname:
        switch_shortname = switch_sysname.split('.')[0]
    else:
        switch_shortname = switch_sysname

    # Try to find switch credentials in creds.yaml
    switch_info = next(
        (s for s in creds.get('switches', []) if s['name'] == switch_shortname),
        None
    )

    if lldp_summary and switch_sysname:
            port_descr = lldp_summary[switch_sysname].get("PortDescr")
    match = re.search(r'(?:ge|et|xe|lt)-\d+/\d+/(\d+)', port_descr)
    retry = 'y'
    if switch_info:
        switch_user = switch_info['username']
        switch_pass = switch_info['password']
        print(f"Using credentials for switch {switch_sysname} from yaml file to log in.\n")
    else:
        print(f"Switch {switch_sysname} not found in creds.yaml. Please enter credentials manually.")
        while True:
            switch_user = input("Enter switch username: ").strip()
            switch_pass = getpass.getpass("Enter switch password: ")

            # Try a harmless command to validate credentials
            test_result = run_ssh_command(switch_sysname, switch_user, switch_pass, "show version")

            if test_result == "AUTH_ERROR":
                print("Incorrect username or password.")
            elif test_result is None:
                print("Could not connect to switch (check hostname or network).")
            else:
                print("Switch login successful.\n")
                break

            retry = input("Try logging in again? (y/n): ").strip().lower()
            if retry != 'y':
                print("Skipping switch-related tests.\n")
                switch_user = None
                switch_pass = None
                break

    # Run laser on/off test
    run_laser_test = input("Run laser on/off test for connected port? (y/n): ").strip().lower()
    if run_laser_test == 'y' and switch_user and switch_pass and port_descr:
        laser_on_off_test(switch_sysname, switch_user, switch_pass, port_descr)
    else:
        print("Skipping laser on/off test.\n")

    # Run soft OIR test on all ports
    if retry == 'y':
        run_soft_oir = input("Run Soft OIR test on all ports? Test time for all ports ~5 to 10 minutes (y/n): ").strip().lower()
        if run_soft_oir == 'y':
            soft_oir_all_ports(switch_sysname, switch_user, switch_pass)
            print(f"\n===== Completed Soft OIR Test for all ports =====\n")
        else:
            print("Skipping Soft OIR test on all ports.\n")
    
    # Run channelization test
    if retry == 'y':
        if input("Run channelization test? Test time ~5 to 10 minutes (y/n): ").lower().strip() == 'y':
            test_channelization(switch_shortname, switch_user, switch_pass, match.group(0), match.group(1))
        else:
            print(f"Failed to extract interface from port description: {port_descr}")
    
    # Save LLDP data before reboot for comparison later
    print("\nSaving LLDP data before reboot...")
    save_lldp_to_file(local_lldp)

    # Prompt user if they want to reboot the server and compare LLDP before/after reboot
    should_reboot = input("\nReboot the server before LLDP comparison? (y/n): ").strip().lower()
    if should_reboot == 'y':
        reboot_server_ssh(server_host, server_user, server_pass)

        # Wait for SSH to become available again after reboot
        if not wait_for_host_ssh(server_host, server_user, server_pass):
            return

        # Wait additional time for LLDP daemons to start after SSH is ready
        print("Waiting 30 seconds for LLDP info to populate after reboot...")
        time.sleep(30)

        # Retrieve LLDP data after reboot with retries
        print("Trying to retrieve LLDP data after reboot with retries...")
        lldp_after = wait_for_lldp_ready(server_host, server_user, server_pass, device)
        if not lldp_after:
            print("Failed to retrieve LLDP data after reboot.") 
            return
        
        # Compare LLDP data before and after reboot, ignoring 'age' fields
        compare_lldp_before_after(server_host, server_user, server_pass, device)

if __name__ == '__main__':
    main()
