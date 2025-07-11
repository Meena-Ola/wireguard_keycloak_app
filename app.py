# --- ADD THESE TWO LINES AT THE VERY TOP ---
from dotenv import load_dotenv
load_dotenv() # This loads the environment variables from .env
# --- END ADDITION ---

from flask import Flask, render_template, redirect, url_for, session, request, flash, send_file
from authlib.integrations.flask_client import OAuth
from authlib.integrations.base_client.errors import OAuthError
import time
import os
import subprocess
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
from io import BytesIO
import base64
from datetime import datetime, timedelta
from flask_apscheduler import APScheduler # Add this import

# --- SQLAlchemy and Flask-Migrate Imports ---
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
# --- END SQLAlchemy Imports ---

# --- Flask-Login Imports ---
from flask_login import LoginManager, current_user, login_user, logout_user, login_required as flask_login_required
# --- END Flask-Login Imports ---

# --- Import your models ---
from models import db, User, WireGuardPeer
# --- END Import models ---

# For WireGuard utility functions
from wireguard_utils import (
    generate_wireguard_keys,
    get_next_available_ip,
    generate_client_config,
    generate_server_config_string,
    generate_qr_code,
    get_wireguard_peer_activity
)

# --- Logging Configuration ---
logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# --- Flask Configuration ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a_very_secret_and_random_key_for_dev')
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# --- PostgreSQL Database Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    'postgresql://postgres:mysecretpassword@localhost:5432/wireguard_db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# --- END Database Configuration ---

# --- Keycloak Configuration ---
app.config['KEYCLOAK_SERVER_URL'] = os.getenv('KEYCLOAK_SERVER_URL', "http://192.168.56.101:3000/realms/tcc")
app.config['KEYCLOAK_CLIENT_ID'] = os.getenv('KEYCLOAK_CLIENT_ID', "wireguard-admin-app")
app.config['KEYCLOAK_CLIENT_SECRET'] = os.getenv('KEYCLOAK_CLIENT_SECRET', "OPQArB2tjIgDmb5SBKE2DQwKWyTqCBu8")
app.config['KEYCLOAK_SCOPES'] = os.getenv('KEYCLOAK_SCOPES', "openid profile email")
app.config['KEYCLOAK_CLIENT_REDIRECT_URIS'] = [
    "http://192.168.56.101:5000/oidc/callback",
    "http://10.0.2.15:5000/oidc/callback",
    "http://127.0.0.1:5000/oidc/callback"
]

# --- WireGuard Configuration ---
app.config['WG_SERVER_PUBLIC_KEY'] = os.getenv('WG_SERVER_PUBLIC_KEY', 'dummy_server_public_key_replace_me')
app.config['WG_SERVER_PRIVATE_KEY'] = os.getenv('WG_SERVER_PRIVATE_KEY', 'dummy_server_private_key_replace_me')
app.config['WG_SERVER_ENDPOINT'] = os.getenv('WG_SERVER_ENDPOINT', '192.168.56.101:51820')
app.config['WG_INTERNAL_NETWORK'] = os.getenv('WG_INTERNAL_NETWORK', '10.8.0.0/24')
app.config['WG_DNS_SERVERS'] = os.getenv('WG_DNS_SERVERS', '8.8.8.8,8.8.4.4')
app.config['WG_ALLOWED_IPS'] = os.getenv('WG_ALLOWED_IPS', '0.0.0.0/0')
app.config['WG_CONFIG_PATH'] = os.getenv('WG_CONFIG_PATH', '/etc/wireguard/wg0.conf')
app.config['WG_PUBLIC_INTERFACE'] = os.getenv('WG_PUBLIC_INTERFACE', 'enp0s3')
app.config['WG_SERVER_LISTEN_PORT'] = os.getenv('WG_SERVER_LISTEN_PORT', 51820)
app.config['WG_SERVER_ADDRESS_CIDR'] = os.getenv('WG_SERVER_ADDRESS_CIDR', '10.8.0.1/24')

# --- Add WG_PEER_INACTIVITY_THRESHOLD_DAYS to your app config ---
app.config['WG_PEER_INACTIVITY_THRESHOLD_DAYS'] = os.getenv('WG_PEER_INACTIVITY_THRESHOLD_DAYS', 90)

# --- Scheduler Configuration ---
class SchedulerConfig:
    SCHEDULER_API_ENABLED = False # Disable API for security if not needed
    SCHEDULER_JOBSTORES = {
        'default': {'type': 'sqlalchemy', 'url': app.config['SQLALCHEMY_DATABASE_URI']}
    }
    SCHEDULER_EXECUTORS = {
        'default': {'type': 'threadpool', 'max_workers': 20}
    }
    SCHEDULER_JOB_DEFAULTS = {
        'coalesce': False,
        'max_instances': 1
    }
app.config.from_object(SchedulerConfig()) # Load scheduler config
scheduler = APScheduler() # Initialize scheduler
# --- End Scheduler Configuration ---


# --- Database Initialization ---
db.init_app(app)
migrate = Migrate(app, db)
# --- END Database Initialization ---

# --- Flask-Login Initialization ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Route name for login page
# --- END Flask-Login Initialization ---

# --- Flask-Login user_loader callback ---
@login_manager.user_loader
def load_user(user_id):
    """
    Required by Flask-Login.
    Given a user ID, return the user object.
    """
    logger.debug(f"Flask-Login: Loading user with ID: {user_id}")
    return User.query.get(user_id)
# --- END Flask-Login user_loader ---

# --- OIDC Client Initialization (using Authlib library) ---
oauth = OAuth(app)
# --- MOVE THIS REGISTRATION HERE ---
try:
    keycloak_oauth = oauth.register(
        name='keycloak',
        client_id=app.config['KEYCLOAK_CLIENT_ID'],
        client_secret=app.config['KEYCLOAK_CLIENT_SECRET'],
        server_metadata_url=f"{app.config['KEYCLOAK_SERVER_URL']}/.well-known/openid-configuration",
        client_kwargs={
            'scope': app.config['KEYCLOAK_SCOPES'],
            'redirect_uris': app.config['KEYCLOAK_CLIENT_REDIRECT_URIS']
        }
    )
    logger.info("Authlib Keycloak client registered successfully.")
except Exception as e:
    logger.error(f"Error during Authlib Keycloak client registration: {e}", exc_info=True)
# --- END MOVE ---

# --- New functions for peer activity and inactivity check ---
def update_peer_activity_status():
    """
    Periodically updates the last_connected_at for peers based on wg show dump.
    """
    with app.app_context(): # Ensure this runs within the Flask app context
        logger.info("Starting scheduled job: Updating WireGuard peer activity status.")
        peer_activity = get_wireguard_peer_activity()
        updated_count = 0
        for public_key, last_handshake_dt in peer_activity.items():
            peer = WireGuardPeer.query.filter_by(public_key=public_key).first()
            if peer and (peer.last_connected_at is None or peer.last_connected_at < last_handshake_dt):
                peer.last_connected_at = last_handshake_dt
                db.session.add(peer) # Add to session for update
                updated_count += 1
        db.session.commit()
        logger.info(f"Finished scheduled job: Updated activity status for {updated_count} peers.")

def disable_inactive_peers():
    """
    Disables WireGuard peers that have been inactive for a configured period.
    """
    with app.app_context(): # Ensure this runs within the Flask app context
        logger.info("Starting scheduled job: Disabling inactive WireGuard peers.")
        inactivity_threshold_days = app.config.get('WG_PEER_INACTIVITY_THRESHOLD_DAYS', 90) # Default 90 days
        inactive_cutoff_date = datetime.utcnow() - timedelta(days=inactivity_threshold_days)

        # Find enabled peers that haven't connected since the cutoff date
        inactive_peers = WireGuardPeer.query.filter(
            WireGuardPeer.enabled == True,
            (WireGuardPeer.last_connected_at == None) | (WireGuardPeer.last_connected_at < inactive_cutoff_date)
        ).all()

        disabled_count = 0
        for peer in inactive_peers:
            peer.enabled = False
            db.session.add(peer) # Add to session for update
            disabled_count += 1
            logger.info(f"Disabled inactive peer: {peer.keycloak_username} (ID: {peer.id}, Public Key: {peer.public_key})")

        if disabled_count > 0:
            db.session.commit()
            if update_current_wg_config():
                logger.info(f"Successfully disabled {disabled_count} inactive peers and updated WireGuard config.")
                flash(f"Automatically disabled {disabled_count} inactive WireGuard peers.", "info")
            else:
                db.session.rollback()
                logger.error(f"Failed to update WireGuard config after disabling {disabled_count} peers. Rolling back changes.")
                flash("Error: Failed to update WireGuard config after disabling inactive peers.", "danger")
        else:
            logger.info("No inactive peers found to disable.")
# --- END New functions ---


# Helper function for admin check (now uses current_user directly)
def is_admin_check():
    if current_user.is_authenticated and hasattr(current_user, 'get_roles'):
        return 'admin' in current_user.get_roles()
    return False

# --- Context Processor to make current_user and is_admin_status available in all templates ---
@app.context_processor
def inject_user_and_roles():
    return dict(current_user=current_user, is_admin_status=is_admin_check())

# --- Custom Decorators (now using Flask-Login's login_required) ---
# Rename your custom login_required to avoid conflict with flask_login_required
# We will use flask_login_required instead.
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not is_admin_check():
            flash("Admin access required.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if current_user.is_authenticated: # Use Flask-Login's current_user
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login')
def login():
    redirect_uri = url_for('oidc_callback', _external=True)
    logger.info(f"Initiating login redirect to Keycloak. Redirect URI: {redirect_uri}")
    return keycloak_oauth.authorize_redirect(redirect_uri) # keycloak_oauth is now defined

@app.route('/oidc/callback')
def oidc_callback():
    try:
        token_response = keycloak_oauth.authorize_access_token()
        logger.debug(f"Authlib token response: {token_response}")

        userinfo = token_response.get('userinfo')
        if not userinfo:
            userinfo = keycloak_oauth.fetch_userinfo()
            logger.debug(f"Userinfo from fetch_userinfo: {userinfo}")

        if not userinfo:
            logger.error("OIDC Callback Error: Could not retrieve user information (userinfo is None).")
            flash("Login failed: User information missing. Please try again.", "danger")
            return redirect(url_for('index'))

        logger.debug(f"Raw Userinfo: {userinfo}")

        user_roles_from_keycloak = []

        # 1. Check for 'realm_access' roles (common for realm roles)
        if 'realm_access' in userinfo and 'roles' in userinfo['realm_access']:
            user_roles_from_keycloak.extend(userinfo['realm_access']['roles'])
            logger.debug(f"Roles found in realm_access: {userinfo['realm_access']['roles']}")

        # 2. Check for 'resource_access' roles (common for client roles)
        client_id = app.config['KEYCLOAK_CLIENT_ID'] # "wireguard-admin-app"
        if 'resource_access' in userinfo and client_id in userinfo['resource_access'] and 'roles' in userinfo['resource_access'][client_id]:
            user_roles_from_keycloak.extend(userinfo['resource_access'][client_id]['roles'])
            logger.debug(f"Roles found in resource_access for client '{client_id}': {userinfo['resource_access'][client_id]['roles']}")

        # 3. Check for top-level 'roles' (as seen in your log is the actual source)
        if 'roles' in userinfo and isinstance(userinfo['roles'], list):
            user_roles_from_keycloak.extend(userinfo['roles'])
            logger.debug(f"Roles found at top-level 'roles' key: {userinfo['roles']}")

        # Ensure unique roles
        user_roles_from_keycloak = list(set(user_roles_from_keycloak))
        logger.debug(f"Final combined roles for user (before saving to DB): {user_roles_from_keycloak}")

        user_id = userinfo.get('sub')
        username = userinfo.get('preferred_username', userinfo.get('name', user_id))
        email = userinfo.get('email')

        user = User.query.filter_by(id=user_id).first()
        if user:
            user.username = username
            user.email = email
            user.set_roles(user_roles_from_keycloak) # This will now receive the correct roles
            user.last_login_at = datetime.utcnow()
            db.session.commit()
            logger.info(f"Existing user {user.username} ({user.id}) updated with roles {user.get_roles()} and logged in.")
        else:
            new_user = User(id=user_id, username=username, email=email)
            new_user.set_roles(user_roles_from_keycloak) # This will now receive the correct roles
            db.session.add(new_user)
            db.session.commit()
            user = new_user
            logger.info(f"New user {user.username} ({user.id}) created with roles {user.get_roles()} and logged in.")

        if not user:
            logger.error("OIDC Callback Error: User object is None after get/create operation.")
            flash("Login failed: Could not create or retrieve user record.", "danger")
            return redirect(url_for('index'))

        login_user(user) # This sets the user in the session for Flask-Login

        session['access_token'] = token_response.get('access_token')
        if 'expires_in' in token_response:
            session['expires_at'] = time.time() + token_response['expires_in']
        else:
            logger.warning("Access token 'expires_in' not found in Authlib response.")
            session['expires_at'] = time.time() + 3600
        if 'refresh_token' in token_response:
            session['refresh_token'] = token_response['refresh_token']
        if 'id_token' in token_response:
            session['id_token'] = token_response['id_token']
        logger.debug(f"Flask-Login current_user ID after login: {current_user.get_id()}")

        flash(f'Logged in as {user.username}', 'success')
        return redirect(url_for('dashboard'))

    except OAuthError as e:
        logger.error(f"Authlib OIDC Callback Error: {e.description}", exc_info=True)
        flash(f"Login failed: {e.description}. Please try again.", "danger")
        return redirect(url_for('index'))
    except Exception as e:
        db.session.rollback()
        logger.error(f"An unexpected error occurred during authorization: {e}", exc_info=True)
        flash('Login failed. An unexpected error occurred. Please try again.', 'danger')
        return redirect(url_for('index'))

@app.route('/logout')
@flask_login_required # Use Flask-Login's decorator
def logout():
    id_token = session.get('id_token')
    logout_user() # This clears the user from the Flask-Login session
    session.clear() # Clear all other session data as well
    flash("You have been logged out.", "info")
    # Redirect to Keycloak's logout endpoint for full OIDC session termination
    keycloak_logout_url = f"{app.config['KEYCLOAK_SERVER_URL']}/protocol/openid-connect/logout?"
    keycloak_logout_url += f"post_logout_redirect_uri={url_for('index', _external=True)}"
    if id_token:
        keycloak_logout_url += f"&id_token_hint={id_token}"
    else:
        app.logger.warning("No id_token found in session for Keycloak logout.")
    return redirect(keycloak_logout_url)

@app.route('/dashboard')
@flask_login_required # Use Flask-Login's decorator
def dashboard():
    user = current_user # Use Flask-Login's current_user directly
    all_user_peers = []

    generated_private_key = None
    generated_public_key = None
    generated_assigned_ip = None
    generated_client_config = None
    generated_qr_code_b64 = None

    if user:
        all_user_peers = user.wireguard_peers_collection

        if 'temp_private_key' in session:
            generated_private_key = session.pop('temp_private_key')
            generated_public_key = session.pop('temp_public_key', None)
            generated_assigned_ip = session.pop('temp_peer_ip', None)

            if generated_private_key and generated_assigned_ip:
                generated_client_config = generate_client_config(
                    app.config['WG_SERVER_PUBLIC_KEY'],
                    app.config['WG_SERVER_ENDPOINT'],
                    generated_private_key,
                    generated_assigned_ip,
                    app.config['WG_DNS_SERVERS'],
                    app.config['WG_ALLOWED_IPS']
                )
                generated_qr_code_b64 = generate_qr_code(generated_client_config)
                flash("Your new/regenerated WireGuard configuration is displayed below. Please save it immediately!", "success")
            else:
                flash("Error retrieving temporary key/IP for config display.", "danger")

        if not all_user_peers and not generated_private_key:
            flash("No WireGuard peers configured for your account. Click 'Create New Peer' to get started.", "info")

    return render_template(
        'dashboard.html',
        user=user,
        all_user_peers=all_user_peers,
        generated_private_key=generated_private_key,
        generated_public_key=generated_public_key,
        generated_assigned_ip=generated_assigned_ip,
        generated_client_config=generated_client_config,
        generated_qr_code_b64=generated_qr_code_b64,
    )

@app.route('/create_peer', methods=['POST'])
@flask_login_required
def create_peer():
    user = current_user
    if not user: # This check is technically redundant due to @flask_login_required but harmless
        flash("User not logged in.", "danger")
        return redirect(url_for('login'))

    existing_peer_for_user = WireGuardPeer.query.filter_by(keycloak_user_id=user.id).first()
    if existing_peer_for_user:
        flash("You already have a WireGuard peer configured. Please regenerate if you need a new config.", "warning")
        return redirect(url_for('dashboard'))

    try:
        private_key, public_key = generate_wireguard_keys()

        all_enabled_peers = WireGuardPeer.query.filter(WireGuardPeer.enabled == True).all()
        existing_ips = [p.assigned_ip for p in all_enabled_peers if p.assigned_ip]

        assigned_ip = get_next_available_ip(app.config['WG_INTERNAL_NETWORK'], existing_ips)
        if not assigned_ip:
            raise ValueError("Could not assign an IP address. Network might be full.")

        new_peer = WireGuardPeer(
            user_id=user.id,
            keycloak_user_id=user.id,
            keycloak_username=user.username,
            public_key=public_key,
            assigned_ip=assigned_ip,
            enabled=True,
            created_at=datetime.utcnow(),
            allowed_ips=app.config['WG_ALLOWED_IPS']
        )
        db.session.add(new_peer)
        db.session.commit()

        session['temp_private_key'] = private_key
        session['temp_peer_ip'] = assigned_ip
        session['temp_public_key'] = public_key

        update_current_wg_config()

        flash("WireGuard peer created successfully! Configuration shown below.", "success")
        return redirect(url_for('dashboard'))

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating peer: {e}", exc_info=True)
        flash(f"Error creating peer: {e}", "danger")
        return redirect(url_for('dashboard'))

@app.route('/regenerate_peer/<int:peer_id>', methods=['POST'])
@flask_login_required
def regenerate_peer(peer_id):
    user = current_user
    if not user:
        flash("User not logged in.", "danger")
        return redirect(url_for('login'))

    peer = WireGuardPeer.query.filter_by(id=peer_id, user_id=user.id).first()
    if not peer:
        flash("Peer not found or you do not have permission to modify it.", "danger")
        return redirect(url_for('dashboard'))

    try:
        private_key, public_key = generate_wireguard_keys()

        all_enabled_peers_except_current = WireGuardPeer.query.filter(
            WireGuardPeer.enabled == True, WireGuardPeer.id != peer_id
        ).all()
        existing_ips = [p.assigned_ip for p in all_enabled_peers_except_current if p.assigned_ip]

        assigned_ip = get_next_available_ip(app.config['WG_INTERNAL_NETWORK'], existing_ips)
        if not assigned_ip:
            raise ValueError("Could not assign a new IP address. Network might be full.")

        peer.public_key = public_key
        peer.assigned_ip = assigned_ip
        peer.last_connected_at = None
        db.session.commit()

        session['temp_private_key'] = private_key
        session['temp_public_key'] = public_key
        session['temp_peer_ip'] = assigned_ip

        update_current_wg_config()

        flash(f"Peer {peer.public_key} regenerated successfully! New configuration shown below.", "success")
        return redirect(url_for('dashboard'))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error regenerating peer {peer_id}: {e}", exc_info=True)
        flash(f"Error regenerating peer: {e}", "danger")
        return redirect(url_for('dashboard'))

@app.route('/delete_peer/<int:peer_id>', methods=['POST'])
@flask_login_required
def delete_peer(peer_id):
    user = current_user
    if not user:
        flash("User not logged in.", "danger")
        return redirect(url_for('login'))

    peer_to_delete = WireGuardPeer.query.filter_by(id=peer_id, user_id=user.id).first()
    if not peer_to_delete:
        flash("Peer not found or you do not have permission to delete it.", "warning")
        return redirect(url_for('dashboard'))

    try:
        db.session.delete(peer_to_delete)
        db.session.commit()

        update_current_wg_config()

        flash("WireGuard peer deleted successfully.", "success")

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting peer {peer_id} for user {user.id}: {e}", exc_info=True)
        flash(f"Error deleting peer: {e}", "danger")

    return redirect(url_for('dashboard'))

@app.route('/download_specific_config/<int:peer_id>')
@flask_login_required
def download_specific_config(peer_id):
    user = current_user
    if not user:
        flash("User not logged in.", "danger")
        return redirect(url_for('login'))

    peer = WireGuardPeer.query.filter_by(id=peer_id, user_id=user.id).first()
    if not peer:
        flash("Peer not found or you do not have permission to download its config.", "danger")
        return redirect(url_for('dashboard'))

    flash("Config download for existing peers is not available without regenerating the key pair for security. Please use 'Regenerate Peer' if you need a new configuration file.", "danger")
    return redirect(url_for('dashboard'))

def update_current_wg_config():
    try:
        all_enabled_peers = WireGuardPeer.query.filter(WireGuardPeer.enabled == True).all()
        peer_data_for_wg = [{
            'public_key': p.public_key,
            'assigned_ip': p.assigned_ip,
            'keycloak_username': p.keycloak_username,
            'enabled': p.enabled,
            'allowed_ips': p.allowed_ips
        } for p in all_enabled_peers]

        server_config_content = generate_server_config_string(
            peer_data_for_wg,
            app.config['WG_SERVER_PRIVATE_KEY'],
            app.config['WG_SERVER_ADDRESS_CIDR'],
            app.config['WG_SERVER_LISTEN_PORT'],
            app.config['WG_PUBLIC_INTERFACE']
        )

        wrapper_script_path = '/usr/local/bin/update_wg_config.sh'

        command = ['sudo', wrapper_script_path, server_config_content]

        app.logger.info(f"Attempting to run privileged WireGuard config update: {' '.join(command[:2])} ...")
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        app.logger.info(f"WireGuard config update script stdout: {result.stdout}")
        if result.stderr:
            app.logger.warning(f"WireGuard config update script stderr: {result.stderr}")

        flash("WireGuard server configuration updated and applied successfully!", "success")
        return True
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Error triggering WireGuard sync: Script failed. Command: {' '.join(e.cmd)}, Return Code: {e.returncode}, Stdout: {e.stdout}, Stderr: {e.stderr}")
        flash(f"Error: Could not apply WireGuard configuration on server. Details: {e.stderr.strip()}", "danger")
        return False
    except Exception as e:
        app.logger.error(f"Error updating WireGuard server config: {e}", exc_info=True)
        flash(f"Error: Server configuration update failed. Please contact support.", "danger")
        return False

# --- Admin Routes ---
@app.route('/admin')
@admin_required
def admin_dashboard():
    # Fetch all users
    all_users = User.query.options(db.joinedload(User.wireguard_peers_collection)).all()

    # Sort users: Admins first, then alphabetically by username
    def sort_key(user):
        is_admin_priority = 0 if 'admin' in user.get_roles() else 1
        return (is_admin_priority, user.username.lower())

    all_users.sort(key=sort_key)

    return render_template('admin.html', all_users=all_users)

@app.route('/admin/toggle_peer/<int:peer_id>', methods=['POST'])
@admin_required
def admin_toggle_peer(peer_id):
    peer = WireGuardPeer.query.filter_by(id=peer_id).first()
    if not peer:
        flash("Peer not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    peer.enabled = not peer.enabled
    db.session.commit()

    if update_current_wg_config():
        flash(f"Peer {peer.keycloak_username} (ID: {peer.id}) {'enabled' if peer.enabled else 'disabled'}.", "success")
    else:
        db.session.rollback()

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/create_peer_for_user/<string:user_id>', methods=['POST'])
@admin_required
def admin_create_peer_for_user(user_id):
    target_user = User.query.get(user_id)
    if not target_user:
        flash("Target user not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    try:
        private_key, public_key = generate_wireguard_keys()

        all_enabled_peers = WireGuardPeer.query.filter(WireGuardPeer.enabled == True).all()
        existing_ips = [p.assigned_ip for p in all_enabled_peers if p.assigned_ip]

        assigned_ip = get_next_available_ip(app.config['WG_INTERNAL_NETWORK'], existing_ips)
        if not assigned_ip:
            raise ValueError("Could not assign an IP address. Network might be full.")

        new_peer = WireGuardPeer(
            user_id=target_user.id,
            keycloak_user_id=target_user.id,
            keycloak_username=target_user.username,
            public_key=public_key,
            assigned_ip=assigned_ip,
            enabled=True,
            created_at=datetime.utcnow(),
            allowed_ips=app.config['WG_ALLOWED_IPS']
        )
        db.session.add(new_peer)
        db.session.commit()

        update_current_wg_config()
        flash(f"New WireGuard peer created for {target_user.username}. Private key (for admin's reference only): {private_key}", "success")

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating peer for user {target_user.username}: {e}", exc_info=True)
        flash(f"Error creating peer for {target_user.username}: {e}", "danger")

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/regenerate_peer/<int:peer_id>', methods=['POST'])
@admin_required
def admin_regenerate_peer(peer_id):
    peer = WireGuardPeer.query.filter_by(id=peer_id).first()
    if not peer:
        flash("Peer not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    try:
        private_key, public_key = generate_wireguard_keys()

        all_enabled_peers_except_current = WireGuardPeer.query.filter(
            WireGuardPeer.enabled == True, WireGuardPeer.id != peer_id
        ).all()
        existing_ips = [p.assigned_ip for p in all_enabled_peers_except_current if p.assigned_ip]

        assigned_ip = get_next_available_ip(app.config['WG_INTERNAL_NETWORK'], existing_ips)
        if not assigned_ip:
            raise ValueError("Could not assign a new IP address. Network might be full.")

        peer.public_key = public_key
        peer.assigned_ip = assigned_ip
        peer.last_connected_at = None
        db.session.commit()

        update_current_wg_config()
        flash(f"Peer for {peer.keycloak_username} (ID: {peer.id}) regenerated. New Private Key (for admin's reference only): {private_key}", "info")
        flash(f"Peer {peer.keycloak_username} regenerated successfully!", "success")

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error regenerating peer {peer_id} by admin: {e}", exc_info=True)
        flash(f"Error regenerating peer: {e}", "danger")

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_peer/<int:peer_id>', methods=['POST'])
@admin_required
def admin_delete_peer(peer_id):
    peer_to_delete = WireGuardPeer.query.filter_by(id=peer_id).first()
    if not peer_to_delete:
        flash("Peer not found.", "warning")
        return redirect(url_for('admin_dashboard'))

    try:
        db.session.delete(peer_to_delete)
        db.session.commit()

        update_current_wg_config()
        flash(f"WireGuard peer for {peer_to_delete.keycloak_username} deleted successfully.", "success")

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting peer {peer_id} by admin: {e}", exc_info=True)
        flash(f"Error deleting peer: {e}", "danger")

    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    #with app.app_context():
    #   db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)