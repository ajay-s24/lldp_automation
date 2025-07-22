# Required Libraries
import getpass
import json
import paramiko
from jnpr.junos import Device
from jnpr.junos.exception import ConnectError
import os
import time
import difflib
import re

# Path to local config file
CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'nic_config.json')

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

def test_lldp_link_down_up(server_ip, username, password, interface):
    """
    Test LLDP behavior for interface with physical link check:
    1. Check physical link is UP; if DOWN, bring it UP and verify
    2. Verify interface is present in LLDP neighbors initially
    3. Bring interface DOWN, check absence in LLDP neighbors
    4. Bring interface UP, check presence in LLDP neighbors again
    """

    print(f"Testing LLDP behavior for interface '{interface}'\n")

    # Check physical link status with ethtool
    output = run_ssh_command(server_ip, username, password, f"ethtool {interface} | grep -i 'Link detected'")
    link_up = False
    if output and "yes" in output.lower():
        print(f"Initial physical link status: UP")
        link_up = True
    else:
        print(f"Initial physical link status: DOWN")
        print(f"Trying to bring interface {interface} UP...")
        run_ssh_command(server_ip, username, password, f"ip link set dev {interface} up")
        time.sleep(3)
        output_after_up = run_ssh_command(server_ip, username, password, f"ethtool {interface} | grep -i 'Link detected'")
        if output_after_up and "yes" in output_after_up.lower():
            print(f"Interface {interface} is UP after bringing it up.")
            link_up = True
        else:
            print(f"FAIL: Unable to bring interface {interface} UP. Aborting LLDP test.")
            return False

    # Proceed only if link is up
    if not link_up:
        print(f"FAIL: Physical link is down and could not be brought up.")
        return False

    # Step 1: Check interface appears in LLDP neighbors
    interfaces = [iface.rstrip(',') for iface in re.findall(r'Interface:\s+(\S+)', run_ssh_command(server_ip, username, password, 'lldpcli show neighbors'), re.IGNORECASE)]
    print(f"Interfaces found: {interfaces}")
    if interface in interfaces:
        print(f"PASS: Interface {interface} found in LLDP neighbors initially.")
    else:
        print(f"FAIL: Interface {interface} NOT found in LLDP neighbors initially.")
    
    # Step 2: Bring interface down
    print(f"Bringing interface {interface} DOWN...")
    run_ssh_command(server_ip, username, password, f"ip link set dev {interface} down")
    time.sleep(3)  # small pause before checking

    # Verify interface is NOT in LLDP neighbors now
    interfaces_after_down = [iface.rstrip(',') for iface in re.findall(r'Interface:\s+(\S+)', run_ssh_command(server_ip, username, password, 'lldpcli show neighbors'), re.IGNORECASE)]
    if interface in interfaces_after_down:
        print(f"FAIL: Interface {interface} still present in LLDP neighbors after link down.")
        return False
    print(f"PASS: Interface {interface} correctly absent from LLDP neighbors after link down.")

    # Step 3: Bring interface back up
    print(f"Bringing interface {interface} UP...")
    run_ssh_command(server_ip, username, password, f"ip link set dev {interface} up")
    time.sleep(3)

    # Wait for interface to appear again in LLDP neighbors with polling
    if not wait_for_interface_in_lldp(server_ip, username, password, interface):
        print(f"FAIL: Interface {interface} NOT found in LLDP neighbors after link up.")
        return False
    print(f"PASS: Interface {interface} found in LLDP neighbors after link up.")

    return True


def wait_for_interface_in_lldp(server_ip, username, password, interface, timeout=30, interval=2):
    """
    Wait up to timeout seconds for interface to appear in lldpcli neighbors, checking every interval seconds.
    Returns True if interface is present, False if timeout reached.
    """
    start = time.time()
    print(f"Waiting for interface {interface} to appear in LLDP neighbors. Will timeout after {timeout} seconds.")
    while time.time() - start < timeout:
        interfaces = [iface.rstrip(',') for iface in re.findall(r'Interface:\s+(\S+)', run_ssh_command(server_ip, username, password, 'lldpcli show neighbors'), re.IGNORECASE)]
        if interface in interfaces:
            return True
        time.sleep(interval)
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

def get_interfaces_and_ips(server_ip, username, password, nic_match_str):
    """
    Discover interfaces on a server that match a NIC string and retrieve their IPs.

    Args:
        server_ip (str): Server IP.
        username (str): SSH username.
        password (str): SSH password.
        nic_match_str (str): NIC description match string (e.g., "Broadcom Inc. and subsidiaries").

    Returns:
        dict: Mapping of interface names to IP addresses.
    """
    # Get hardware info of network devices
    lshw_output = run_ssh_command(server_ip, username, password, 'lshw -C network -businfo')
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
        ifconfig_output = run_ssh_command(server_ip, username, password, f'ifconfig {iface}')
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
    match = re.search(r'et-0/0/(\d+)', port_descr)
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
            current_interface = line.split(":", 1)[1].strip().split(",")[0]
        elif line.lower().startswith("sysname:"):
            current_sysname = line.split(":", 1)[1].strip()
        elif line.lower().startswith("portdescr:"):
            current_portdescr = line.split(":", 1)[1].strip()
        elif line.lower().startswith("portid:"):
            current_portid = line.split(":", 1)[1].strip()

        # Once all relevant fields are captured, store and reset
        if current_interface and current_sysname and (current_portdescr or current_portid):
            if (target_interface is None) or (target_interface == current_interface):
                summary[current_sysname] = {
                    "Interface": current_interface,
                    "PortDescr": current_portdescr or "N/A",
                    "PortId": current_portid or "N/A"
                }
            current_interface = current_sysname = current_portdescr = current_portid = None

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
    Wait until SSH becomes available on a host.

    Args:
        host (str): Hostname/IP.
        username (str): SSH user.
        password (str): SSH password.
        timeout (int): Max wait time in seconds.
        interval (int): Polling interval in seconds.

    Returns:
        bool: True if SSH is available, False if timed out.
    """
    print(f"Waiting for {host} to become available after reboot...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, username=username, password=password, timeout=10)
            # Simple command to verify the shell is ready
            stdin, stdout, stderr = ssh.exec_command("hostname")
            output = stdout.read().decode().strip()
            if output:
                print("Server is back online.")
                ssh.close()
                return True
            ssh.close()
        except Exception as e:
            print(f"SSH not ready yet: {e}")
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

    Args:
        host (str): Hostname/IP.
        username (str): SSH username.
        password (str): SSH password.
    """
    try:
        print(f"\nRebooting server {host}...")
        output = run_ssh_command(host, username, password, "reboot")
        print("Reboot command issued successfully (SSH session may close automatically).")
    except Exception as e:
        print(f"Failed to send reboot command: {e}")

def wait_for_lldp_ready(server_host, server_user, server_pass, interface, retries=6, delay=10):
    """
    Wait for LLDP data to become available after reboot.

    Args:
        server_host (str): Hostname/IP.
        server_user (str): SSH user.
        server_pass (str): SSH password.
        interface (str): Network interface.
        retries (int): Number of attempts.
        delay (int): Delay between retries in seconds.

    Returns:
        dict or None: LLDP neighbor data or None if unavailable.
    """
    for attempt in range(retries):
        try:
            lldp_data = get_lldp_neighbors_local_ssh(server_host, server_user, server_pass, interface)
            if lldp_data:
                print("LLDP data retrieved successfully.")
                return lldp_data
        except Exception as e:
            print(f"Attempt {attempt+1} failed: {e}")
        print(f"Waiting {delay} seconds before retrying...")
        time.sleep(delay)
    print("Failed to retrieve LLDP data after multiple attempts.")
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

    # Prompt for server hostname/IP
    server_host = input("Enter server hostname (or IP): ").strip()
    if not server_host:
        print("Server hostname/IP is required.")
        return

    # Prompt for server username and password
    server_user = input("Enter server username: ").strip()
    server_pass = getpass.getpass("Enter server password: ")

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

    # Call the link down/up test first
    print(f"\nRunning link down/up test on interface: {device}")
    link_test_result = test_lldp_link_down_up(server_host, server_user, server_pass, device)
    print(f"Overall test: {'PASSED' if link_test_result else 'FAILED'}.\n")

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
    if cable_len:
        print(f"Cable assembly length for {device}: {cable_len}")  
    else:
        print(f"No cable assembly length info available for {device} by using ethtool.\nAttempting to get cable lengths from switch...")

        switch_sysname = next(
            (key for key, entry in lldp_summary.items()
             if entry.get("Interface", "").lower() == device.lower()),
            None
        )
        # Find switch system name from LLDP summary
        if switch_sysname:
            switch_hostname = switch_sysname.split('.')[0]
            print(f"Found switch from LLDP neighbor summary: {switch_hostname} (full sysname: {switch_sysname})")
        else:
            switch_hostname = input("Enter switch hostname manually: ").strip()
            if not switch_hostname:
                print("Switch hostname is required.")
                return
                  
        # Prompt for switch login credentials
        switch_user = input("Enter switch username: ").strip()
        switch_pass = getpass.getpass("Enter switch password: ")

        print(f"Querying cable lengths and interfaces from switch {switch_hostname}...")
        port_descr = None
        if lldp_summary and switch_sysname:
            port_descr = lldp_summary[switch_sysname].get("PortDescr")

        # Get cable length info from switch CLI
        switch_cable_info = get_cable_length_from_switch(switch_hostname, switch_user, switch_pass, port_descr)
        if switch_cable_info:
            print(f"Cable length reported by switch for port descr '{port_descr}': {switch_cable_info}")
        else:
            print("Failed to retrieve cable length info from switch.")

    # Save LLDP data before reboot for comparison later
    print("Saving LLDP data before reboot...")
    save_lldp_to_file(local_lldp)

    # Prompt user if they want to reboot the server and compare LLDP before/after reboot
    should_reboot = input("Reboot the server before LLDP comparison? (y/n): ").strip().lower()
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
