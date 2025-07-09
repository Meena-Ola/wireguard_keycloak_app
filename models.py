import json
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin # Make sure UserMixin is imported

db = SQLAlchemy() # Make sure db is initialized somewhere or passed correctly

class User(UserMixin, db.Model):
    __tablename__ = 'users' # Good practice to define table name
    id = db.Column(db.String(36), primary_key=True) # Keycloak 'sub' is usually a UUID string
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    roles = db.Column(db.String(255), default='[]') # Stores JSON string of roles
    created_at = db.Column(db.DateTime, default=db.func.now())
    last_login_at = db.Column(db.DateTime)

    # Relationship to WireGuard peers
    wireguard_peers_collection = db.relationship(
        'WireGuardPeer', backref='user', lazy=True, cascade="all, delete-orphan"
    )

    # Flask-Login required properties/methods
    # These should NOT be @property decorators, but just methods
    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    # Custom methods for your application to handle roles
    def set_roles(self, roles_list):
        """Sets the user's roles from a list of strings, storing them as a JSON string."""
        if isinstance(roles_list, list):
            self.roles = json.dumps(roles_list)
        else:
            # Handle error or log a warning if roles_list is not a list
            print(f"Warning: set_roles received non-list input: {type(roles_list)}")
            self.roles = json.dumps([]) # Default to empty list

    def get_roles(self):
        """Retrieves the user's roles as a list of strings from the JSON string."""
        try:
            return json.loads(self.roles)
        except (json.JSONDecodeError, TypeError):
            return [] # Return empty list if roles string is invalid or None

    def is_admin(self):
        """Checks if the user has the 'admin' role."""
        return 'admin' in self.get_roles() # Make sure to call get_roles()

    def __repr__(self):
        return f'<User {self.username}>'

# Define WireGuardPeer model here as well if it's in the same file
class WireGuardPeer(db.Model):
    __tablename__ = 'wireguard_peers'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False) # Foreign key to User.id
    keycloak_user_id = db.Column(db.String(36), nullable=False, index=True) # Redundant but kept for clarity based on your code
    keycloak_username = db.Column(db.String(80), nullable=False)
    public_key = db.Column(db.String(255), unique=True, nullable=False, index=True)
    assigned_ip = db.Column(db.String(45), unique=True, nullable=False) # e.g., "10.8.0.2/32"
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    last_connected_at = db.Column(db.DateTime, nullable=True)
    allowed_ips = db.Column(db.String(255), default='0.0.0.0/0', nullable=False) # Client allowed IPs

    def __repr__(self):
        return f'<WireGuardPeer {self.assigned_ip} for {self.keycloak_username}>'