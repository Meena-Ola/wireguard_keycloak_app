import subprocess
import ipaddress
import qrcode
from io import BytesIO
import base64
import os
# import wgconfig # We don't need wgconfig in here anymore for writing files, only generating strings
import re # Import regex module
from datetime import datetime, timedelta # Import datetime and timedelta

def generate_wireguard_keys():
    private_key = subprocess.check_output("wg genkey", shell=True).decode("utf-8").strip()
    public_key = subprocess.check_output(f"echo '{private_key}' | wg pubkey", shell=True).decode("utf-8").strip()
    return private_key, public_key

def get_next_available_ip(network_cidr, existing_ips):
    """Finds the next available IP address in the given CIDR, excluding existing IPs."""
    network = ipaddress.ip_network(network_cidr)
    # Start from .2 if server is .1, adjust if server is different
    # This assumes the server IP is .1 within the CIDR range
    server_ip_str = str(network.network_address + 1)

    # Ensure existing_ips includes the server IP if it's within the allocatable range
    if server_ip_str not in existing_ips:
        existing_ips_set = set(existing_ips)
        existing_ips_set.add(server_ip_str)
    else:
        existing_ips_set = set(existing_ips)

    # Start looking for IPs from .2 onwards within the subnet
    # Assuming .1 is reserved for the server
    for i in range(2, network.num_addresses - 1): # Exclude network address (.0) and broadcast address
        ip = network.network_address + i
        if str(ip) not in existing_ips_set:
            return str(ip)
    raise ValueError("No available IP addresses in the subnet.")

def generate_client_config(server_public_key, server_endpoint, client_private_key, client_ip, dns_servers, allowed_ips):
    """Generates a WireGuard client .conf file content."""
    config = f"""[Interface]
PrivateKey = {client_private_key}
Address = {client_ip}/32
DNS = {dns_servers}

[Peer]
PublicKey = {server_public_key}
Endpoint = {server_endpoint}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""
    return config

def generate_server_config_string(peer_data_list, server_private_key, server_address_cidr, listen_port, public_interface):
    """
    Generates the complete WireGuard server wg0.conf content as a string.
    This function no longer writes to file or interacts with subprocess.
    """
    server_ip = server_address_cidr.split('/')[0] # Get just the IP part

    config_lines = []

    # [Interface] section
    config_lines.append("[Interface]")
    config_lines.append(f"PrivateKey = {server_private_key}")
    config_lines.append(f"Address = {server_address_cidr}") # Use the full CIDR for the server
    config_lines.append(f"ListenPort = {str(listen_port)}")
    # Use your actual public interface name from app.config
    config_lines.append(f"PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {public_interface} -j MASQUERADE")
    config_lines.append(f"PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {public_interface} -j MASQUERADE")
    config_lines.append("\n") # Add a newline for separation

    # [Peer] sections
    for peer in peer_data_list:
        # Only include enabled peers in the server config
        if peer.get('enabled', False): # Use .get with default False for safety
            config_lines.append("[Peer]")
            config_lines.append(f"PublicKey = {peer['public_key']}")
            # Add a comment for easier identification
            config_lines.append(f"# Client: {peer.get('keycloak_username', 'Unknown')}")
            config_lines.append(f"AllowedIPs = {peer['assigned_ip']}/32")
            # If you were storing PresharedKey in DB, you'd add it here:
            # if 'preshared_key' in peer and peer['preshared_key']:
            #     config_lines.append(f"PresharedKey = {peer['preshared_key']}")
            config_lines.append("\n") # Add a newline for separation

    return "\n".join(config_lines)

def generate_qr_code(config_content):
    img = qrcode.make(config_content)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode("utf-8")

def parse_wg_show_output(output):
    """
    Parses the output of 'wg show wg0 dump' to extract peer information.
    Returns a dictionary mapping public_key to latest_handshake_timestamp.
    """
    peers_status = {}
    # Regex to capture public key and latest handshake (seconds since epoch)
    # This regex assumes 'wg show wg0 dump' format:
    # public_key\tprivate_key\tendpoint_ip:port\tallowed_ips\tlatest_handshake\ttransfer_rx\ttransfer_tx\tpersistent_keepalive
    # We are interested in public_key (group 1) and latest_handshake (group 5)
    # The dump format is usually a single line per peer, tab-separated.
    peer_line_pattern = re.compile(r'([a-zA-Z0-9+/=]{44})\t([a-zA-Z0-9+/=]{44})\t([0-9.]+:\d+)\t([0-9./,]+)\t(\d+)\t(\d+)\t(\d+)\t([0-9]+)?')

    for line in output.splitlines():
        match = peer_line_pattern.match(line.strip())
        if match:
            public_key = match.group(1)
            latest_handshake_timestamp = int(match.group(5)) # Seconds since Unix epoch
            peers_status[public_key] = datetime.fromtimestamp(latest_handshake_timestamp)
    return peers_status

def get_wireguard_peer_activity():
    """
    Executes 'sudo wg show wg0 dump' and parses its output to get peer activity.
    Returns a dictionary mapping public_key to latest_handshake (datetime object).
    """
    try:
        # Using 'wg show wg0 dump' is more machine-readable than 'wg show'
        # Ensure your sudoers file allows the app user to run 'wg show wg0 dump' without password.
        cmd = ['sudo', 'wg', 'show', 'wg0', 'dump']
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return parse_wg_show_output(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running 'wg show wg0 dump': {e.stderr}")
        return {}
    except FileNotFoundError:
        print("Error: 'wg' command not found. Is WireGuard installed and in PATH?")
        return {}
    except Exception as e:
        print(f"An unexpected error occurred while getting WireGuard peer activity: {e}")
        return {}
