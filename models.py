from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json # You'll need this import for roles if storing as JSON
from sqlalchemy.types import TypeDecorator, Text # For storing roles as JSON text

db = SQLAlchemy()

class WireGuardPeer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    keycloak_user_id = db.Column(db.String(255), db.ForeignKey('user.id'), unique=True, nullable=False)
    keycloak_username = db.Column(db.String(255), nullable=False)
    public_key = db.Column(db.String(255), unique=True, nullable=False)
    # private_key = db.Column(db.String(255), nullable=False) # Store securely! Encrypt in production.
    assigned_ip = db.Column(db.String(15), unique=True, nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_connected_at = db.Column(db.DateTime)
    # Add fields for bandwidth usage, last handshake, etc., if you want advanced monitoring
    # For enterprise, consider a 'device_name' or 'description' field

    def __repr__(self):
        return f"<Peer {self.keycloak_username} - {self.assigned_ip}>"

class JSONText(TypeDecorator):
    impl = Text

    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            return json.loads(value)
        return value

class User(db.Model):
    id = db.Column(db.String(255), primary_key=True) # Keycloak 'sub' is usually a string UUID
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    roles = db.Column(JSONText) # Store roles as JSON (list of strings)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.username}>"