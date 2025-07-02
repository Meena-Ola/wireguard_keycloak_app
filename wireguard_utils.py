import subprocess
import ipaddress
import qrcode
from io import BytesIO
import base64
import os
import wgconfig # pip install wgconfig

def generate_wireguard_keys():
    private_key = subprocess.check_output("wg genkey", shell=True).decode("utf-8").strip()
    public_key = subprocess.check_output(f"echo '{private_key}' | wg pubkey", shell=True).decode("utf-8").strip()
    return private_key, public_key

def get_next_available_ip(network_cidr, existing_ips):
    """Finds the next available IP address in the given CIDR, excluding existing IPs."""
    network = ipaddress.ip_network(network_cidr)
    # Start from .2 if server is .1, adjust if server is different
    start_ip = network.network_address + 2
    for ip_int in range(int(start_ip), int(network.broadcast_address)):
        ip = ipaddress.ip_address(ip_int)
        if str(ip) not in existing_ips:
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

def update_wireguard_server_config(peer_data_list, wg_config_path, server_private_key, server_address, listen_port, public_interface):
    """
    Updates the /etc/wireguard/wg0.conf file with current peers.
    Requires root/sudo privileges for the web app to write to this file.
    **CRITICAL SECURITY NOTE**: Ensure your web app runs with minimal privileges and
    this function is carefully protected.
    A safer alternative is for the web app to write to a temporary file,
    and a separate, more restricted service (e.g., a systemd unit or cron job)
    owned by root then applies the config changes using `wg syncconf`.
    """
    wc = wgconfig.WGConfig(wg_config_path)
    wc.initialize_file() # Clears existing config and adds interface header

    # Add server interface details
    wc.add_attr(None, 'Address', server_address)
    wc.add_attr(None, 'ListenPort', str(listen_port))
    wc.add_attr(None, 'PrivateKey', server_private_key)
    wc.add_attr(None, 'PostUp', f"iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {public_interface} -j MASQUERADE")
    wc.add_attr(None, 'PostDown', f"iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {public_interface} -j MASQUERADE")

    # Add peers
    for peer in peer_data_list:
        if peer['enabled']:
            wc.add_peer(peer['public_key'], f"# {peer['keycloak_username']}")
            wc.add_attr(peer['public_key'], 'AllowedIPs', f"{peer['assigned_ip']}/32")
            # You could add PresharedKey if you use them:
            # wc.add_attr(peer['public_key'], 'PresharedKey', peer['preshared_key'])

    wc.write_file() # Writes to the config file

    # Apply the new configuration
    try:
        subprocess.run(f"sudo wg syncconf {os.getenv('WG_INTERFACE_NAME', 'wg0')} {wg_config_path}", check=True, shell=True)
        print("WireGuard configuration updated and applied.")
    except subprocess.CalledProcessError as e:
        print(f"Error applying WireGuard config: {e}")
        # Log the error, notify admin
        raise

def generate_qr_code(config_content):
    img = qrcode.make(config_content)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode("utf-8")

def update_wireguard_server_config_temp(peer_data_list, wg_config_path, server_private_key, server_address, listen_port, public_interface):
    """
    Updates the /etc/wireguard/wg0.conf file with current peers.
    Requires root/sudo privileges for the web app to write to this file.
    **CRITICAL SECURITY NOTE**: Ensure your web app runs with minimal privileges and
    this function is carefully protected.
    A safer alternative is for the web app to write to a temporary file,
    and a separate, more restricted service (e.g., a systemd unit or cron job)
    owned by root then applies the config changes using `wg syncconf`.
    """
    wc = wgconfig.WGConfig(wg_config_path)
    wc.initialize_file() # Clears existing config and adds interface header

    # Add server interface details
    wc.add_attr(None, 'Address', server_address)
    wc.add_attr(None, 'ListenPort', str(listen_port))
    wc.add_attr(None, 'PrivateKey', server_private_key)
    wc.add_attr(None, 'PostUp', f"iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {public_interface} -j MASQUERADE")
    wc.add_attr(None, 'PostDown', f"iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {public_interface} -j MASQUERADE")

    # Add peers
    for peer in peer_data_list:
        if peer['enabled']:
            wc.add_peer(peer['public_key'], f"# {peer['keycloak_username']}")
            wc.add_attr(peer['public_key'], 'AllowedIPs', f"{peer['assigned_ip']}/32")
            # You could add PresharedKey if you use them:
            # wc.add_attr(peer['public_key'], 'PresharedKey', peer['preshared_key'])

    wc.write_file() # Writes to the config file
    print(f"WireGuard config written to temporary file: {"/etc/wireguard/temp.conf"}")

    # Apply the new configuration
    try:
        subprocess.run(f"sudo wg syncconf {os.getenv('WG_INTERFACE_NAME', 'wg0')} {wg_config_path}", check=True, shell=True)
        print("WireGuard configuration updated and applied.")
    except subprocess.CalledProcessError as e:
        print(f"Error applying WireGuard config: {e}")
        # Log the error, notify admin
        raise