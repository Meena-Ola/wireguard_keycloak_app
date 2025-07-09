import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-secret-key-that-you-should-change'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://admin:admin@localhost/wireguard_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Keycloak Configuration
    KEYCLOAK_SERVER_URL = "http://192.168.56.101:3000/realms/tcc"
    KEYCLOAK_CLIENT_ID = "wireguard-admin-app"
    KEYCLOAK_CLIENT_SECRET = os.environ.get('KEYCLOAK_CLIENT_SECRET')
    KEYCLOAK_REDIRECT_URI = "https://192.168.56.101:5000/oidc/callback"
    KEYCLOAK_SCOPES = "openid profile email roles" # 'roles' is important for custom mapper

    # WireGuard Configuration
    WG_INTERFACE_NAME = "wg0"
    WG_CONFIG_PATH = "/etc/wireguard/wg0.conf" # Make sure your web app user has write access (careful with permissions!)
    WG_SERVER_PUBLIC_KEY = os.environ.get('WG_SERVER_PUBLIC_KEY') # Get this from /etc/wireguard/server_publickey
    WG_SERVER_ENDPOINT = os.environ.get('WG_SERVER_ENDPOINT') or "http://192.168.56.101:51820"
    WG_INTERNAL_NETWORK = "10.8.0.0/24" # Same as in wg0.conf server address
    WG_DNS_SERVERS = "1.1.1.1, 8.8.8.8" # Or your internal DNS
    WG_ALLOWED_IPS = "0.0.0.0/0, ::/0" # Default for full tunnel
