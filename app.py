from flask import Flask, render_template, redirect, url_for, session, request, flash, send_file
from authlib.integrations.flask_client import OAuth
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from config import Config
from models import db, WireGuardPeer, User
from wireguard_utils import generate_wireguard_keys, get_next_available_ip, generate_client_config, update_wireguard_server_config_temp, generate_qr_code
import os
import subprocess
from functools import wraps
from netaddr import IPNetwork
import logging
from logging.handlers import RotatingFileHandler
from io import BytesIO
from sqlalchemy import func as sa
from authlib.common.security import generate_token

# Helper function to get the current logged-in user
def get_current_user():
    user_id = session.get('user_id')
    print(f"DEBUG: get_current_user - user_id from session: {user_id}")
    if user_id:
        user = User.query.get(user_id)
        print(f"DEBUG: get_current_user - fetched user: {user.username if user else 'None'}")
        return user # Assumes User model is defined
    print("DEBUG: get_current_user - No user_id in session.")
    return None

# Helper function to check if the current user is an admin
def is_admin(user=None):
    if user is None:
        user = get_current_user()
    if user and 'admin' in user.roles: # Assuming 'admin' is a role string
        return True
    return False

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
logger = logging.getLogger(__name__) # This line defines the 'logger' variable

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
oauth = OAuth(app)
migrate = Migrate(app, db) # Initialize Flask-Migrate

# Configure logging - This block needs to be after `app = Flask(__name__)`
if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    
    file_handler = RotatingFileHandler('logs/wireguard_app.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('WireGuard App startup')

# Example error handler
@app.errorhandler(500)
def internal_error(error):
    app.logger.exception('An internal server error occurred')
    db.session.rollback() # Ensure rollback on database errors
    return "Internal Server Error", 500 # Render a custom error page in production

# Register Keycloak OIDC client
oauth.register(
    'keycloak',
    client_id=app.config['KEYCLOAK_CLIENT_ID'],
    client_secret=app.config['KEYCLOAK_CLIENT_SECRET'], # Corrected typo: KEYCLOCK -> KEYCLOAK
    server_metadata_url=f"{app.config['KEYCLOAK_SERVER_URL']}/.well-known/openid-configuration",
    client_kwargs={'scope': app.config['KEYCLOAK_SCOPES']}
)

# --- Decorators for Authorization ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not get_current_user(): # This is the critical check
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login')) # Redirect to login page
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not get_current_user() or not is_admin():
            flash("Admin access required.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    session['nonce'] = generate_token()
    print(f"DEBUG: Flask generated redirect_uri: {redirect_uri}") # ADD THIS LINE
    logger.info(f"Redirecting for login to: {redirect_uri}") # Or this for logging
    return oauth.keycloak.authorize_redirect(redirect_uri, nonce=session['nonce'])

@app.route('/oidc/callback')
def authorize():
    try:
        nonce = session.pop('nonce', None)
        token = oauth.keycloak.authorize_access_token(nonce=nonce)
        print(f"DEBUG: Full token received: {token}")
        userinfo = token.get('userinfo')
        print(f"DEBUG: Userinfo from token: {userinfo}")

        if not userinfo:
            flash('Failed to get user info from Keycloak.', 'danger')
            return redirect(url_for('index'))

        user_id = userinfo['sub']
        username = userinfo.get('preferred_username', userinfo.get('name', user_id))
        email = userinfo.get('email')
        # Keycloak roles are often in 'realm_access.roles' or 'resource_access.<client_id>.roles'
        # Adjust based on how your Keycloak realm roles are mapped to tokens.
        # Assuming realm_access for now:
        user_roles = userinfo.get('realm_access', {}).get('roles', [])
        # If you have specific client roles, you might need:
        # client_roles = userinfo.get('resource_access', {}).get(app.config['KEYCLOAK_CLIENT_ID'], {}).get('roles', [])
        # combined_roles = list(set(realm_roles + client_roles))

        # For simplicity, let's use realm_roles for now:

        user = User.query.filter_by(id=user_id).first()

        if user:
            # Update existing user details if necessary
            user.username = username
            user.email = email
            user.roles = user_roles # Update roles
            db.session.commit() # <<< Commit updates to existing user
            logger.info(f"Existing user {user.username} ({user.id}) updated and logged in.")
        else:
            # Create a new user if they don't exist
            new_user = User(
                id=user_id,
                username=username,
                email=email,
                roles=user_roles
            )
            db.session.add(new_user)
            db.session.commit() # <<< Commit new user creation
            user = new_user # Set 'user' to the newly created user
            logger.info(f"New user {user.username} ({user.id}) created and logged in.")

        # If user object is still None here, it means something went wrong in creation/retrieval
        if not user:
            flash("Login failed: Could not create or retrieve user record.", "danger")
            return redirect(url_for('index'))
        
        session['user_id'] = user.id
        session['username'] = user.username
        session['roles'] = user.roles # Store roles in session

        # Removed the redundant flash and logger.info here, moved them inside if/else blocks
        print(f"DEBUG: Session user_id after login: {session.get('user_id')}")
        print(f"DEBUG: Session username after login: {session.get('username')}")

        flash(f'Logged in as {user.username}', 'success')
        return redirect(url_for('dashboard'))

    except Exception as e:
        db.session.rollback() # Ensure rollback on any error
        logger.error(f"Keycloak authorization failed: {e}", exc_info=True)
        flash('Login failed. Please try again.', 'danger')
        session.pop('nonce', None)
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('roles', None)
    session.pop('access_token', None)
    flash("You have been logged out.", "info")
    # Keycloak logout (optional, but good for SSO)
    # You might need to construct the Keycloak end_session_endpoint URL
    # with post_logout_redirect_uri.
    # See Keycloak documentation for proper OIDC logout.
    # E.g., return redirect(f"{app.config['KEYCLOAK_SERVER_URL']}/protocol/openid-connect/logout?post_logout_redirect_uri={url_for('index', _external=True)}")
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    print(f"DEBUG: User object in dashboard: {user}")
    
    if not user:
        # This block might still be needed if get_current_user fails after session has user_id
        flash('Please log in to view the dashboard.', 'warning')
        return redirect(url_for('index'))
    
    peer = WireGuardPeer.query.filter_by(keycloak_user_id=user.id).first()
    qr_code_b64 = None
    client_config = None
    
    if peer:
        if 'temp_private_key' in session:
            client_private_key = session.pop('temp_private_key')
            assigned_ip = session.pop('temp_peer_ip')
            
            client_config = generate_client_config(
                app.config['WG_SERVER_PUBLIC_KEY'],
                app.config['WG_SERVER_ENDPOINT'],
                client_private_key,
                assigned_ip,
                app.config['WG_DNS_SERVERS'],
                app.config['WG_ALLOWED_IPS']
            )
            qr_code_b64 = generate_qr_code(client_config)

    # Pass the user object to the template here!
    return render_template('dashboard.html', user=user, peer=peer, qr_code_b64=qr_code_b64, client_config=client_config)

@app.route('/create_peer', methods=['POST'])
@login_required
def create_peer():
    user_id = session.get('user_id') # Use .get() for safety
    username = session.get('username') # Use .get() for safety
    existing_peer = WireGuardPeer.query.filter_by(keycloak_user_id=user_id).first()
    
    if existing_peer:
        flash("You already have a WireGuard peer configured.", "warning")
        return redirect(url_for('dashboard'))
    
    try:
        # Generate keys
        private_key, public_key = generate_wireguard_keys()

        # Get existing IPs to avoid conflicts
        existing_ips = [p.assigned_ip for p in WireGuardPeer.query.filter_by(enabled=True).all()]
        assigned_ip = get_next_available_ip(app.config['WG_INTERNAL_NETWORK'], existing_ips)

        # Create new peer in DB
        new_peer = WireGuardPeer(
            keycloak_user_id=user_id,
            keycloak_username=username,
            public_key=public_key,
            # private_key is NOT stored in DB now based on security recommendations
            assigned_ip=assigned_ip,
            enabled=True
        )
        db.session.add(new_peer)
        db.session.commit()

        # Store the private_key temporarily in session to pass to dashboard
        # This is for IMMEDIATE display/download. DO NOT PERSIST.
        session['temp_private_key'] = private_key
        session['temp_peer_ip'] = assigned_ip # Also store IP for config generation

        # Update WireGuard server config immediately
        all_enabled_peers = WireGuardPeer.query.filter_by(enabled=True).all()
        peer_data_for_wg = [{
            'public_key': p.public_key,
            'assigned_ip': p.assigned_ip,
            'keycloak_username': p.keycloak_username,
            'enabled': p.enabled
        } for p in all_enabled_peers]

        update_wireguard_server_config_temp(
            peer_data_for_wg,
            app.config['WG_CONFIG_PATH'],
            os.getenv('WG_SERVER_PRIVATE_KEY'), # Retrieve securely!
            app.config['WG_INTERNAL_NETWORK'].split('/')[0] + '.1', # Server IP
            51820, # ListenPort
            os.getenv('WG_PUBLIC_INTERFACE', 'eth0') # Public interface
        )

        # Trigger the sync script on the server for the updated config
        try:
            subprocess.run(f"sudo /usr/local/bin/sync_wireguard.sh", check=True, shell=True)
            app.logger.info("WireGuard config update triggered successfully.")
        
        except subprocess.CalledProcessError as e:
            app.logger.error(f"Error triggering WireGuard sync: {e}", exc_info=True)
            flash(f"Error: Could not apply WireGuard configuration on server. Please contact support.", "danger")
            # Optionally revert DB change if sync fails critically
            db.session.rollback() # Consider if this is appropriate for your error handling
            return redirect(url_for('dashboard'))

        flash("WireGuard peer created successfully! Please download your configuration now.", "success")
        return redirect(url_for('dashboard')) # Redirect to dashboard to show config

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating peer: {e}", exc_info=True)
        flash(f"Error creating peer: {e}", "danger")
        return redirect(url_for('dashboard'))

@app.route('/delete_peer', methods=['POST'])
@login_required
def delete_peer():
    user_id = session['user']['id']
    peer = WireGuardPeer.query.filter_by(keycloak_user_id=user_id).first()

    if not peer:
        flash("No WireGuard peer found for your account.", "warning")
        return redirect(url_for('dashboard'))

    try:
        db.session.delete(peer)
        db.session.commit()

        # Update WireGuard server config to remove the peer
        all_enabled_peers = WireGuardPeer.query.filter_by(enabled=True).all()
        peer_data_for_wg = [{
            'public_key': p.public_key,
            'assigned_ip': p.assigned_ip,
            'keycloak_username': p.keycloak_username,
            'enabled': p.enabled
        } for p in all_enabled_peers]


        update_wireguard_server_config_temp(
            peer_data_for_wg,
            app.config['WG_CONFIG_PATH'],
            os.getenv('WG_SERVER_PRIVATE_KEY'),
            app.config['WG_INTERNAL_NETWORK'].split('/')[0] + '.1',
            51820,
            os.getenv('WG_PUBLIC_INTERFACE', 'eth0')
        )
        # Trigger the sync script on the server for the updated config
        try:
            subprocess.run(f"sudo /usr/local/bin/sync_wireguard.sh", check=True, shell=True)
            app.logger.info("WireGuard config update triggered successfully (delete).")
        except subprocess.CalledProcessError as e:
            app.logger.error(f"Error triggering WireGuard sync during delete: {e}", exc_info=True)
            flash(f"Error: Could not apply WireGuard configuration on server after delete. Please contact support.", "danger")
            # This is tricky: if DB deleted but WG not, manual intervention is needed.
            # For simplicity here, we proceed, but in real enterprise, you might queue for retry.
        flash("WireGuard peer deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting peer: {e}", exc_info=True)
        flash(f"Error deleting peer: {e}", "danger")
    return redirect(url_for('dashboard'))

@app.route('/download_config')
@login_required
def download_config():
    user_id = session.get('user_id') # Use .get() for safety
    peer = WireGuardPeer.query.filter_by(keycloak_user_id=user_id).first()

    if not peer:
        flash("No WireGuard configuration found.", "warning")
        return redirect(url_for('dashboard'))

    # If the private key is NOT stored, this route needs to change.
    # It cannot generate the config if it doesn't have the private key.
    # The user would have to *input* their private key to get the config,
    # or you'd rely solely on the initial download after creation.
    # Assuming for this corrected code that `temp_private_key` would be passed
    # from a new key regeneration function, or if user is prompted to input.
    # For now, this assumes peer.private_key exists, but it was removed from model.
    # This function will only work if the private key is held temporarily in session
    # after generation or regeneration.

    # This part needs to be revisited if you strictly do not store private_key.
    # For a client to download its config, it MUST have its private key.
    # If the private key is NOT stored in the DB, then:
    # 1. The initial config download happens immediately after peer creation (using temp_private_key in session).
    # 2. For subsequent downloads, the user MUST be prompted to provide their *own* private key
    #    (which they saved from the initial download) to generate the config for them.
    # This current `download_config` implementation assumes peer.private_key is available,
    # which contradicts the earlier removal from the model.

    # Let's adjust this. If `temp_private_key` is available, use that.
    # Otherwise, it implies the user needs to regenerate or manually provide their key.
    client_private_key = session.get('temp_private_key') # Try to get from session
    if not client_private_key:
        flash("Private key not available for download. Please regenerate your peer or contact support if you lost your key.", "danger")
        return redirect(url_for('dashboard'))

    client_config = generate_client_config(
        app.config['WG_SERVER_PUBLIC_KEY'],
        app.config['WG_SERVER_ENDPOINT'],
        client_private_key, # Use the private key from session
        peer.assigned_ip,
        app.config['WG_DNS_SERVERS'],
        app.config['WG_ALLOWED_IPS']
    )
    
    # Clear the temp_private_key from session after download
    session.pop('temp_private_key', None)
    session.pop('temp_peer_ip', None)

    # Return as a file download
    response = send_file(
        BytesIO(client_config.encode('utf-8')),
        mimetype='application/x-wireguard-conf',
        as_attachment=True,
        download_name=f"{peer.keycloak_username}.conf"
    )
    return response

# --- Admin Routes (Example) ---
@app.route('/admin')
@admin_required
def admin_dashboard():
    all_peers = WireGuardPeer.query.all()
    return render_template('admin.html', peers=all_peers)

@app.route('/admin/toggle_peer/<int:peer_id>', methods=['POST'])
@admin_required
def admin_toggle_peer(peer_id):
    peer = WireGuardPeer.query.get_or_404(peer_id)
    peer.enabled = not peer.enabled
    try:
        db.session.commit()
        # Re-apply WireGuard config after change
        all_enabled_peers = WireGuardPeer.query.filter_by(enabled=True).all()
        peer_data_for_wg = [{
            'public_key': p.public_key,
            'assigned_ip': p.assigned_ip,
            'keycloak_username': p.keycloak_username,
            'enabled': p.enabled
        } for p in all_enabled_peers]

        update_wireguard_server_config_temp(
            peer_data_for_wg,
            app.config['WG_CONFIG_PATH'],
            os.getenv('WG_SERVER_PRIVATE_KEY'),
            app.config['WG_INTERNAL_NETWORK'].split('/')[0] + '.1',
            51820,
            os.getenv('WG_PUBLIC_INTERFACE', 'eth0')
        )
        # Trigger the sync script on the server for the updated config
        try:
            subprocess.run(f"sudo /usr/local/bin/sync_wireguard.sh", check=True, shell=True)
            app.logger.info(f"WireGuard config update triggered successfully (toggle for {peer.keycloak_username}).")
        except subprocess.CalledProcessError as e:
            app.logger.error(f"Error triggering WireGuard sync during toggle: {e}", exc_info=True)
            flash(f"Error: Could not apply WireGuard configuration on server after toggle. Please contact support.", "danger")
            # Consider if rollback is needed here
        flash(f"Peer {peer.keycloak_username} {'enabled' if peer.enabled else 'disabled'}.", "success")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error toggling peer: {e}", exc_info=True)
        flash(f"Error toggling peer: {e}", "danger")
    return redirect(url_for('admin_dashboard'))

# --- Database Initialization (for development) ---
#@app.before_first_request
#def create_tables():
#    db.create_all()

if __name__ == '__main__':
    # Set environment variables for sensitive info in production
    # For development, you can set them here for testing:
    # os.environ['SECRET_KEY'] = 'your-flask-secret'
    # os.environ['KEYCLOAK_CLIENT_SECRET'] = 'your-keycloak-client-secret'
    # os.environ['WG_SERVER_PUBLIC_KEY'] = 'your-wg-server-public-key'
    # os.environ['WG_SERVER_PRIVATE_KEY'] = 'your-wg-server-private-key'
    # os.environ['WG_PUBLIC_INTERFACE'] = 'eth0' # or whatever your public interface is
    app.run(debug=True, ssl_context='adhoc') # For HTTPS during development (not for production)