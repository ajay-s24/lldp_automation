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

def test_ae_lacp_bundle(local_switch, local_user, local_pass, local_iface):
    print(f"\n=== Testing AE LACP Bundle on {local_switch} for interface {local_iface} ===\n")

    # Pick next available AE ID
    config_output = run_ssh_command(local_switch, local_user, local_pass,
                                    "cli -c 'show configuration interfaces | match ae'")
    existing_ae_ids = set(int(m.group(1)) for m in re.finditer(r'ae(\d+)', config_output))
    ae_id = 1
    while ae_id in existing_ae_ids and ae_id <= 127:
        ae_id += 1
    if ae_id > 127:
        print("No available AE IDs.")
        return False
    ae_name = f"ae{ae_id}"
    print(f"Selected AE ID: {ae_name}")

    # Pick next available VLAN ID
    vlan_output = run_ssh_command(local_switch, local_user, local_pass, "cli -c 'show configuration vlans'")
    used_vlans = set(int(m.group(1)) for m in re.finditer(r'vlan-id\s+(\d+)', vlan_output))
    vlan_id = 2
    while vlan_id in used_vlans and vlan_id <= 4094:
        vlan_id += 1
    if vlan_id > 4094:
        print("No available VLAN IDs.")
        return False
    print(f"Selected VLAN ID: {vlan_id}")

    local_ip = f"11.0.{ae_id}.2/24"
    peer_ip  = f"11.0.{ae_id}.1/24"
    print(f"Assigned local IP {local_ip} and peer IP {peer_ip}\n")

    # Always attempt cleanup in finally
    try:
        # Cleanup interface if needed
        iface_check = run_ssh_command(local_switch, local_user, local_pass,
                                      f"cli -c 'show configuration interfaces {local_iface}'")
        if "unit 0" in iface_check:
            print(f"Found unit 0 under {local_iface}, removing...")
            cleanup_cmds = [f"delete interfaces {local_iface} unit 0"]
            ri_check = run_ssh_command(local_switch, local_user, local_pass,
                                       f"cli -c 'show configuration routing-instances | display set | match {local_iface}'")
            for line in ri_check.splitlines():
                cleanup_cmds.append(f"delete {line.strip().replace('set ', '')}")
            run_ssh_command(local_switch, local_user, local_pass,
                            f"cli -c 'configure; {'; '.join(cleanup_cmds)}; commit and-quit'")
            print("Cleanup successful.\n")

        # Configure AE locally
        cmds_local_test = [
            "set chassis aggregated-devices ethernet device-count 20",
            f"set interfaces {local_iface} ether-options 802.3ad {ae_name}",
            f"set interfaces {ae_name} description Test",
            f"set interfaces {ae_name} aggregated-ether-options lacp active"
        ]
        for cmd in cmds_local_test:
            run_ssh_command(local_switch, local_user, local_pass, f"cli -c 'configure; {cmd}; commit and-quit'")
        print(f"AE local test configuration successful on {local_iface}.\n")

        # Get peer info (LLDP)
        lldp_output = run_ssh_command(local_switch, local_user, local_pass,
                                      f"cli -c 'show lldp neighbors interface {local_iface} detail'")
        peer_sysname, peer_port = None, None
        in_section = False
        for line in lldp_output.splitlines():
            line = line.strip()
            if line.startswith("Neighbor Information:"):
                in_section = True
            if in_section:
                if line.startswith("System name"):
                    peer_sysname = line.split(":", 1)[1].strip()
                elif line.startswith("Port description"):
                    peer_port = line.split(":", 1)[1].strip()
            if peer_sysname and peer_port:
                break

        print(f"Peer switch: {peer_sysname if peer_sysname else 'N/A'}, Peer port: {peer_port if peer_port else 'N/A'}")

        # Configure full AE locally
        cmds_local_full = [
            "set chassis aggregated-devices ethernet device-count 20",
            f"set interfaces {local_iface} ether-options 802.3ad {ae_name}",
            f"set interfaces {ae_name} description LinkAgg",
            f"set interfaces {ae_name} vlan-tagging",
            f"set interfaces {ae_name} encapsulation flexible-ethernet-services",
            f"set interfaces {ae_name} aggregated-ether-options lacp active",
            f"set interfaces {ae_name} unit 0 vlan-id {vlan_id}",
            f"set interfaces {ae_name} unit 0 family inet address {local_ip}"
        ]
        for cmd in cmds_local_full:
            run_ssh_command(local_switch, local_user, local_pass, f"cli -c 'configure; {cmd}; commit and-quit'")

        print(f"Configured {local_iface} into {ae_name} on {local_switch} successfully.")

        # Peer configuration omitted if missing
        if peer_sysname and peer_port:
            print("Peer configuration skipped in this version.")

        # Verify LACP
        print("\nLACP status on local switch:")
        print(run_ssh_command(local_switch, local_user, local_pass, "cli -c 'show lacp interfaces'"))

    finally:
        # Always cleanup AE
        print("\nCleaning up AE configuration...")
        run_ssh_command(local_switch, local_user, local_pass,
                        f"cli -c 'configure; delete interfaces {ae_name}; commit and-quit'")

    print("\n=== AE LACP Bundle Test Completed ===\n")
    return True

def check_fec_status(host, username, password, iface):
    """
    Check FEC status for a given interface on a Juniper QFX switch via SSH.
    
    Args:
        host (str): Hostname or IP of the switch
        username (str): SSH username
        password (str): SSH password
        iface (str): Interface name, e.g. 'et-0/0/0:0'
    
    Returns:
        dict: Parsed FEC info including mode, corrected errors, uncorrected errors, BER
    """
    # Use only the base physical interface (remove :x if present)
    interface = iface.split(":")[0]

    command = f'cli -c "show interfaces {interface} media"'
    output = run_ssh_command(host, username, password, command)
    if not output:
        print(f"Failed to get output for interface {interface}")
        return None

    fec_info = {
        "interface": interface,
        "fec_mode": None,
        "corrected_errors": None,
        "uncorrected_errors": None,
        "pre_fec_ber": None,
    }

    # Regex patterns to extract data
    fec_mode_re = re.compile(r"Ethernet FEC Mode\s*:\s*(\S+)")
    corrected_re = re.compile(r"FEC Corrected Errors\s+(\d+)")
    uncorrected_re = re.compile(r"FEC Uncorrected Errors\s+(\d+)")
    ber_re = re.compile(r"PRE FEC BER\s+([\d.eE+-]+)")

    # Parse lines
    for line in output.splitlines():
        if fec_info["fec_mode"] is None:
            m = fec_mode_re.search(line)
            if m:
                fec_info["fec_mode"] = m.group(1)
        if fec_info["corrected_errors"] is None:
            m = corrected_re.search(line)
            if m:
                fec_info["corrected_errors"] = int(m.group(1))
        if fec_info["uncorrected_errors"] is None:
            m = uncorrected_re.search(line)
            if m:
                fec_info["uncorrected_errors"] = int(m.group(1))
        if fec_info["pre_fec_ber"] is None:
            m = ber_re.search(line)
            if m:
                try:
                    fec_info["pre_fec_ber"] = float(m.group(1))
                except ValueError:
                    fec_info["pre_fec_ber"] = None

    # Print summary
    print(f"FEC status for interface {interface}:")
    print(f"  FEC Mode: {fec_info['fec_mode']}")
    print(f"  Corrected Errors: {fec_info['corrected_errors']}")
    print(f"  Uncorrected Errors: {fec_info['uncorrected_errors']}")
    print(f"  PRE FEC BER: {fec_info['pre_fec_ber']}\n")

    return fec_info

def test_fec_modes(host, username, password, iface):
    """
    Test configuring different FEC modes on a Juniper interface and verify status.

    Args:
        host (str): Hostname or IP of the switch
        username (str): SSH username
        password (str): SSH password
        iface (str): Interface name, e.g. 'et-0/0/63:0'
    """
    interface = iface.split(":")[0]

    print(f"=== Starting FEC mode tests on {interface} ===\n")

    fec_modes = ["fec74", "fec91", "none"]

    # Save original config so we can restore
    print("Saving original configuration...")
    run_ssh_command(host, username, password,
                    f"cli -c 'show configuration interfaces {iface}'")
    run_ssh_command(host, username, password,
                    "cli -c 'show configuration | display set' > /var/tmp/orig_fec.conf")

    for mode in fec_modes:
        print(f"\n--- Testing FEC mode: {mode} ---")

        # Configure FEC mode
        cmd_set = f"cli -c 'configure; set interfaces {iface} ether-options fec {mode}; commit and-quit'"
        run_ssh_command(host, username, password, cmd_set)

        # Verify
        status = check_fec_status(host, username, password, iface)
        if status and "fec_mode" in status:
            actual_mode = status["fec_mode"]
            if (mode == "none" and (actual_mode is None or actual_mode.lower() == "none")) or \
               (mode != "none" and actual_mode and mode in actual_mode.lower()):
                print(f"[PASS] Expected: {mode}, Got: {actual_mode}")
            else:
                print(f"[FAIL] Expected: {mode}, Got: {actual_mode}")
        else:
            # If no FEC info returned
            if mode == "none":
                print(f"[PASS] Expected: {mode}, Got: None")
            else:
                print(f"[FAIL] Could not verify FEC mode {mode}")

    # Restore original config
    print("\nRestoring original configuration...")
    run_ssh_command(host, username, password,
                    "cli -c 'configure; rollback 0; commit and-quit'")

    print("\n=== Completed FEC mode tests ===\n")

def scp_with_ssh(src_host, dest_host, user, password):
    """
    SSH into src_host and run sshpass scp to copy ~/OSTG_KR to dest_host:/root/.
    """
    scp_cmd = (
        f"sshpass -p '{password}' scp -o StrictHostKeyChecking=no -r "
        f"~/OSTG_KR {user}@{dest_host}:/root/"
    )
    try:
        print(f"Running command on {src_host}...")
        output = run_ssh_command(src_host, user, password, scp_cmd)
        if output is not None:
            print("Copy successful!")
            return True
        else:
            print("Copy failed!")
            return False
    except Exception as e:
        print(f"Copy failed: {e}")
        return False


def run_traffic_test(server_host, server_user, server_pass, device,
                     src_host="san-ft-ai-srv01", src_user="root", src_pass=None):
    """
    Runs the traffic test on the remote server for the given device.
    Evaluates pass/fail based on HTTP response code.
    """
    if src_pass is None:
        src_pass = server_pass

    print(f"\n=== Traffic Test for Device: {device} ===")

    # Get IPv4 and IPv6 addresses
    ipv4_cmd = f"ip -4 addr show dev {device} | grep inet | awk '{{print $2}}' | cut -d/ -f1"
    ipv6_cmd = f"ip -6 addr show dev {device} | grep inet | awk '{{print $2}}' | cut -d/ -f1"

    ipv4_addr = run_ssh_command(server_host, server_user, server_pass, ipv4_cmd).strip()
    ipv6_addr = run_ssh_command(server_host, server_user, server_pass, ipv6_cmd).strip()
    print(f"Device {device} IPv4: {ipv4_addr or 'None'}, IPv6: {ipv6_addr or 'None'}")

    # Step 1: Copy ~/OSTG_KR from src_host to server_host using sshpass on the source
    print(f"Copying ~/OSTG_KR from {src_host} → {server_host} ...")
    if not scp_with_ssh(src_host, server_host, src_user, src_pass):
        print("Failed to copy ~/OSTG_KR from source to destination. Aborting traffic test.")
        return

    # Step 2: Start server_ostg.py in background on remote server
    print("Starting server_ostg.py on remote server...")
    start_cmd = (
    "bash -c 'cd ~/OSTG_KR && "
    "source traffic-env/bin/activate && "
    "python3 server_ostg.py > server_ostg.log 2>&1 &'"
)
    run_ssh_command(server_host, server_user, server_pass, start_cmd)
    print("Waiting 5 seconds for traffic server to start...")
    time.sleep(5)

    ipv4_passed = False
    ipv6_passed = False

    # Step 3: Run IPv4 traffic
    if ipv4_addr:
        print("Starting IPv4 traffic...")
        curl_ipv4_start = f"""curl -s -o /dev/null -w "%{{http_code}}" -X POST http://{ipv4_addr}:8501/api/traffic/start \
            -H "Content-Type: application/json" \
            -d '{{"streams": {{"{device}":[{{"name":"icmp","enabled":true,"frame_size":64,"L3":"IPv4","ipv4_source":"{ipv4_addr}","stream_id":"icmp-uuid-001"}}]}}}}'"""
        result_ipv4 = run_ssh_command(server_host, server_user, server_pass, curl_ipv4_start).strip()
        ipv4_passed = (result_ipv4 == "200")
        print(f"IPv4 traffic test: {f'PASSED (HTTP {result_ipv4})' if ipv4_passed else f'FAILED (HTTP {result_ipv4})'}")
    else:
        print("No IPv4 address found. Skipping IPv4 traffic.")

    # Step 4: Run IPv6 traffic
    if ipv6_addr:
        print("Starting IPv6 traffic...")
        curl_ipv6_start = f"""curl -s -o /dev/null -w "%{{http_code}}" -X POST http://{ipv4_addr}:8501/api/traffic/start \
            -H "Content-Type: application/json" \
            -d '{{"streams": {{"{device}":[{{"name":"icmpv6","enabled":true,"frame_size":64,"L3":"IPv6","ipv6_source":"{ipv6_addr}","stream_id":"icmpv6-uuid-001"}}]}}}}'"""
        result_ipv6 = run_ssh_command(server_host, server_user, server_pass, curl_ipv6_start).strip()
        ipv6_passed = (result_ipv6 == "200")
        print(f"IPv6 traffic test: {f'PASSED (HTTP {result_ipv4})' if ipv6_passed else f'FAILED (HTTP {result_ipv6})'}")
    else:
        print("No IPv6 address found. Skipping IPv6 traffic.")

    # Step 5 & 6: Stop traffic
    if ipv4_addr:
        curl_ipv4_stop = f"""curl -s -X POST http://{ipv4_addr}:8501/api/traffic/stop \
            -H "Content-Type: application/json" \
            -d '{{"streams":[{{"interface":"{device}","stream_id":"icmp-uuid-001"}}]}}'"""
        run_ssh_command(server_host, server_user, server_pass, curl_ipv4_stop)

    if ipv6_addr:
        curl_ipv6_stop = f"""curl -s -X POST http://{ipv4_addr}:8501/api/traffic/stop \
            -H "Content-Type: application/json" \
            -d '{{"streams":[{{"interface":"{device}","stream_id":"icmpv6-uuid-001"}}]}}'"""
        run_ssh_command(server_host, server_user, server_pass, curl_ipv6_stop)

    # Final summary
    if ipv4_passed and ipv6_passed:
        print("\nTraffic test PASSED for both IPv4 and IPv6.")
    elif ipv4_passed:
        print("\nTraffic test PASSED for IPv4 but FAILED for IPv6.")
    elif ipv6_passed:
        print("\nTraffic test PASSED for IPv6 but FAILED for IPv4.")
    else:
        print("\nTraffic test FAILED for both IPv4 and IPv6.")

    print(f"\n===== Completed Traffic Test for {device} =====\n")


def get_tx_laser_disabled_alarm(host, username, password, interface):
    """
    Fetch the 'Tx laser disabled alarm' state for a specific interface.
    If optics diagnostics not supported, fall back to physical link status.
    """
    interface = interface.split(":")[0]
    # Track if we've already warned during this run
    if not hasattr(get_tx_laser_disabled_alarm, "_warning_printed"):
        get_tx_laser_disabled_alarm._warning_printed = False

    try:
        # Try optics diagnostics first
        cmd_optics = f'cli -c "show interfaces diagnostics optics {interface} | no-more"'
        output = run_ssh_command(host, username, password, cmd_optics)
        if output:
            if "not supported" not in output.lower():
                for line in output.splitlines():
                    if "Tx laser disabled alarm" in line:
                        state_match = re.search(r'Tx laser disabled alarm\s*:\s*(\S+)', line)
                        if state_match:
                            return state_match.group(1)
            else:
                if not get_tx_laser_disabled_alarm._warning_printed:
                    print(f"[WARNING] Optics diagnostics not supported on {interface}, falling back to physical link check.")
                    get_tx_laser_disabled_alarm._warning_printed = True
        else:
            if not get_tx_laser_disabled_alarm._warning_printed:
                print(f"[WARNING] No output from optics diagnostics on {interface}, falling back to physical link check.")
                get_tx_laser_disabled_alarm._warning_printed = True
        
        # Fallback: check physical link status
        cmd_phy = f'cli -c "show interfaces {interface} | match \\"Physical link\\""'
        phy_output = run_ssh_command(host, username, password, cmd_phy)
        if phy_output:
            link_match = re.search(r'Physical link is\s*(Up|Down)', phy_output)
            if link_match:
                return link_match.group(1)
            else:
                print(f"Could not parse physical link status for {interface}")
                return "Unknown"
        else:
            print(f"No output from physical link check for {interface}")
            return "Unknown"

    except Exception as e:
        print(f"[ERROR] Exception while fetching laser alarm for {interface}: {e}")
        return "Unknown"
    
def laser_on_off_test(host, username, password, interface):
    """
    Perform laser ON/OFF validation test on a given switch interface.

    This uses CLI-PFE commands to toggle laser state and checks results using
    show interfaces diagnostics optics, or falls back to physical link status.
    """
    print(f"\n===== Starting Laser ON/OFF test on {interface} =====\n")

    # Extract base port from full interface string: et-0/0/0:0 -> et-0/0/0
    base_iface_match = re.match(r'(et|ge|xe|lt)-\d+/\d+/\d+', interface)
    if not base_iface_match:
        print(f"[ERROR] Could not extract base port from '{interface}'")
        return False

    base_iface = base_iface_match.group(0)

    # Extract port number for CLI-PFE command
    port_number_match = re.search(r'/(\d+)$', base_iface)
    if not port_number_match:
        print(f"[ERROR] Could not extract port number from base interface '{base_iface}'")
        return False

    port_number = port_number_match.group(1)

    # Test laser/link state before changes
    before = get_tx_laser_disabled_alarm(host, username, password, interface)
    print(f"[Before] Laser/Link status: {before}")

    if before.lower() in ("unknown", "unknown, optical diagnostics not supported"):
        print("Unable to determine initial laser/link state precisely.")

    # CLI-PFE: Turn laser OFF
    print(f"Turning laser OFF on {base_iface}...")
    laser_off_cmd = f'cli-pfe -c "test picd optics fpc_slot 0 pic_slot 0 port {port_number} cmd laser-off"'
    run_ssh_command(host, username, password, laser_off_cmd)
    time.sleep(3)

    after_off = get_tx_laser_disabled_alarm(host, username, password, interface)
    print(f"[After OFF] Laser/Link status: {after_off}")

    # CLI-PFE: Turn laser ON
    print(f"Turning laser ON on {base_iface}...")
    laser_on_cmd = f'cli-pfe -c "test picd optics fpc_slot 0 pic_slot 0 port {port_number} cmd laser-on"'
    run_ssh_command(host, username, password, laser_on_cmd)
    time.sleep(3)

    after_on = get_tx_laser_disabled_alarm(host, username, password, interface)
    print(f"[After ON] Laser/Link status: {after_on}")

    # Interpret results with fallback logic:
    # For optics diagnostics: expected before="Off", after_off="On", after_on="Off"
    # For physical link fallback: before="Up", after_off="Down", after_on="Up"

    def is_off(val):
        return val.lower() == "off"

    def is_on(val):
        return val.lower() == "on"

    def is_up(val):
        return val.lower() == "up"

    def is_down(val):
        return val.lower() == "down"

    passed = False
    if (is_off(before) and is_on(after_off) and is_off(after_on)):
        passed = True
    elif (is_up(before) and is_down(after_off) and is_up(after_on)):
        passed = True

    if passed:
        print(f"[PASS] Laser ON/OFF behavior validated successfully on {base_iface}")
        return True
    else:
        print(f"[FAIL] Laser ON/OFF behavior NOT as expected on {base_iface}")
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
    print("\n===== Starting Soft OIR on all active interfaces =====\n")

    print("Capturing alarms before Soft OIR...")
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
    
    parent_interface = re.sub(r':\d+$', '', interface) 

    print(f"\n===== Channelization Test for {parent_interface} =====\n")

    # Step 1: Get original speed from child interface (et-0/0/0:0)
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
            # Apply channelization on the parent interface
            cmds = [
                f"set interfaces {parent_interface} number-of-sub-ports {lanes}",
                f"set interfaces {parent_interface} speed {speed}g"
            ]
            channelize_cmd = "cli -c 'configure; " + " ; ".join(cmds) + " ; commit and-quit'"
            run_ssh_command(server_ip, username, password, channelize_cmd)
            time.sleep(10)

            # Verify sub-interfaces
            sub_intf_status = run_ssh_command(
                server_ip, username, password,
                f"cli -c 'show interfaces terse | match \"{parent_interface}:[0-9]+\"'"
            )
            print("\nSub-interfaces after channelization:\n")
            print(sub_intf_status)

            # Check if sub-interfaces appeared
            sub_interfaces_found = bool(re.search(rf"{re.escape(parent_interface)}:\d+", sub_intf_status))

            # Revert to original config
            revert_cmds = [
                f"delete interfaces {parent_interface} number-of-sub-ports",
                f"set interfaces {parent_interface} speed {original_speed}g"
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

            try:
                # Safe revert on failure
                revert_cmds = [
                    f"delete interfaces {parent_interface} number-of-sub-ports",
                    f"set interfaces {parent_interface} speed {original_speed}g"
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
        interfaces = data.get('lldp', {}).get('interface', [])
        for iface_dict in interfaces:
            for iface_name, iface_data in iface_dict.items():
                if iface_name.strip().lower() == interface.strip().lower():
                    return iface_data

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
        line = line.strip()
        if not line or line.startswith("Bus info") or line.startswith("==="):
            continue
        if nic_match_str.lower() in line.lower():
            parts = line.split()
            if len(parts) >= 2 and parts[1].strip():
                interfaces.append(parts[1])

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
    match = re.search(r'(?:ge|et|xe|lt)-\d+/\d+/(\d+)(?::\d+)?', port_descr)
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

def compare_lldp_before_after(server_host, server_user, server_pass, interface):
    """
    Compare LLDP info from before and after reboot, including 'age' fields.

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

    # Convert to formatted JSON strings (including age fields)
    before_str = json.dumps(before_data, indent=2, sort_keys=True)
    after_str = json.dumps(after_data, indent=2, sort_keys=True)

    # Compare full LLDP JSON
    if before_str == after_str:
        print("LLDP data matches before and after reboot (including 'age').")
    else:
        print("LLDP data has changed after reboot. Differences:")
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
    10. Retrieves and compares LLDP data before and after reboot

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

    # Attempt ethtool cable length retrieval
    cable_len = get_cable_length_ssh(server_host, server_user, server_pass, device, user_match_string)

    # Lookup LLDP summary to get switch sysname and port description
    switch_sysname = next(
        (key for key, entry in lldp_summary.items() if entry.get("Interface", "").lower() == device.lower()),
        None
    )

    # Default to "" to avoid NoneType errors
    port_descr = lldp_summary.get(switch_sysname, {}).get("PortDescr", "") if switch_sysname else ""
    # Extract short interface name like et-0/0/2 or et-0/0/2:0 from port_descr
    interface_match = re.search(r'(et|xe|ge|lt)-\d+/\d+/\d+(?::\d+)?', port_descr)
    if interface_match:
        short_interface = interface_match.group(0)
    else:
        short_interface = port_descr
    # Attempt to extract shortname from port description
    match = re.match(r'([^-]+-[^-]+-\d+)', port_descr)
    switch_shortname = match.group(1) if match else (switch_sysname.split('.')[0] if switch_sysname and '.' in switch_sysname else switch_sysname)
    retry = 'y'

    # Load switch credentials (from YAML or prompt)
    creds = read_creds()
    switch_info = next((s for s in creds.get("switches", []) if s["name"] == switch_shortname), None)

    switch_user = None
    switch_pass = None

    if switch_info:
        switch_user = switch_info["username"]
        switch_pass = switch_info["password"]
        print(f"Using credentials for switch {switch_sysname} from yaml file to log in.\n")
    else:
        print(f"Switch {switch_sysname} not found in creds.yaml. Please enter credentials manually.")
        while True:
            switch_user = input("Enter switch username: ").strip()
            switch_pass = getpass.getpass("Enter switch password: ")

            # Validate login
            test_result = run_ssh_command(switch_sysname, switch_user, switch_pass, "show version")
            if test_result == "AUTH_ERROR":
                print("Incorrect username or password.")
            elif test_result is None:
                print("Could not connect to switch (check hostname or network).")
            else:
                print("Switch login successful.\n")
                break

            retry = input("Try logging in again? (y/n): ").strip().lower()
            if retry != "y":
                print("Skipping switch-related tests.\n")
                switch_user = None
                switch_pass = None
                break

    # Always show ethtool-based cable length result
    if cable_len:
        print(f"Cable assembly length for {device}: {cable_len}")
    else:
        print(f"No cable assembly length info available for {device} by using ethtool.")

        # Only do switch-based cable length lookup if needed
        if switch_user and switch_pass and port_descr:
            print(f"Attempting to get cable length from switch {switch_shortname} using interface '{short_interface}'...")
            switch_cable_info = get_cable_length_from_switch(switch_shortname, switch_user, switch_pass, short_interface)

            if switch_cable_info:
                print(f"Cable length reported by switch: {switch_cable_info}")
            else:
                print("Failed to retrieve cable length info from switch.")

    # Final regex port match (you can use this for other diagnostics if needed)
    match = re.search(r'(et|xe|ge)-\d+/\d+/\d+(?::\d+)?', port_descr)
    if retry == 'y':
        run_link_test = input("Run LLDP link down/up test? (y/n): ").strip().lower()
        if run_link_test == 'y':
            link_test_result = test_lldp_link_down_up(server_host, server_user, server_pass, device)
            print(f"Overall test: {'PASSED' if link_test_result else 'FAILED'}.")
            print(f"\n===== Completed LLDP link down/up test for {device} =====\n")
        else:
            print("\nSkipped LLDP link down/up test.\n")
    
    # Run laser on/off test
    if retry == 'y':
        run_laser_test = input("Run laser on/off test for connected port? (y/n): ").strip().lower()
        if run_laser_test == 'y' and switch_user and switch_pass and port_descr:
            laser_on_off_test(switch_shortname, switch_user, switch_pass, short_interface)
            print("\n===== Completed Laser On/Off Test =====\n")
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

    # Run FEC test
    if retry == 'y':
        if input("\nRun FEC test (configure + verify)? (y/n): ").lower().strip() == 'y':
            print("\nStarting FEC mode test on the selected interface...")
            test_fec_modes(switch_shortname, server_user, server_pass, short_interface)
        else:
            print("Skipping FEC test.\n")

    # Run AE Bundle test
    if retry == 'y':
        run_ae_test = input("\nRun AE Bundle test? (y/n): ").lower().strip()
        if run_ae_test == 'y':
            if not short_interface or not switch_user or not switch_pass:
                print("Missing interface or switch credentials. Skipping AE Bundle test.\n")
            else:
                # Call the automation function using existing variables
                success = test_ae_lacp_bundle(
                    local_switch=switch_shortname,
                    local_user=switch_user,
                    local_pass=switch_pass,
                    local_iface=short_interface
                )
                if success:
                    print(f"\nCompleted AE Bundle + LACP Test on {short_interface} Successfully\n")
                else:
                    print(f"\nAE Bundle + LACP Test failed on {short_interface}.\n")
        else:
            print("Skipping AE Bundle test.\n")

    # Run channelization test
    if retry == 'y':
        if match:
            interface_full = match.group(0)
            interface_number = re.search(r'(\d+)(?::\d+)?$', interface_full).group(1)
            if input("Run channelization test? Test time ~5 to 10 minutes (y/n): ").lower().strip() == 'y':
                test_channelization(switch_shortname, switch_user, switch_pass, interface_full, interface_number)
            else:
                print("Skipping channelization test.\n")
        else:
            print(f"Failed to extract interface from port description: {port_descr}")

    # Run traffic test
    if retry == 'y':
        traffic_test = input("Run traffic test? (y/n): ").strip().lower()
        if traffic_test == 'y':
            run_traffic_test(server_host, server_user, server_pass, device)
        else:
            print("Skipping traffic test.\n")

    
    
    # Save LLDP data before reboot for comparison later
    print("\nSaving LLDP data before reboot...")
    save_lldp_to_file(local_lldp)

    # Prompt user if they want to reboot the server and compare LLDP before/after reboot
    should_reboot = input("\nReboot the server? (y/n): ").strip().lower()
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
        
        # Compare LLDP data before and after reboot
        compare_lldp_before_after(server_host, server_user, server_pass, device)

if __name__ == '__main__':
    main()
