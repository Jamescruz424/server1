import os
import json
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
from werkzeug.security import generate_password_hash, check_password_hash

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configure CORS
cors_allowed_origins = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000")
CORS(app, resources={r"/*": {"origins": cors_allowed_origins}})

# Initialize Firebase
try:
    firebase_creds = os.getenv("FIREBASE_CREDENTIALS")
    if not firebase_creds:
        raise ValueError("FIREBASE_CREDENTIALS environment variable not set")
    cred_dict = json.loads(firebase_creds)
    cred = credentials.Certificate(cred_dict)
    firebase_admin.initialize_app(cred)
    logger.info("Firebase initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Firebase: {str(e)}")
    raise

# Firestore client
db = firestore.client()

# User class
class User:
    def __init__(self, doc_id, name, email, id, dept, password_hash, role='user'):
        self.doc_id = doc_id
        self.name = name
        self.email = email
        self.id = id
        self.dept = dept
        self.password_hash = password_hash
        self.role = role

    def to_dict(self):
        return {
            'name': self.name,
            'email': self.email,
            'id': self.id,
            'dept': self.dept,
            'password_hash': self.password_hash,
            'role': self.role
        }

    @staticmethod
    def from_dict(doc_id, data):
        return User(
            doc_id=doc_id,
            name=data['name'],
            email=data['email'],
            id=data['id'],
            dept=data['dept'],
            password_hash=data['password_hash'],
            role=data.get('role', 'user')
        )

# Check for existing user by email or ID
def check_existing_user(email, id):
    logger.debug(f"Checking if user exists with email: {email}, id: {id}")
    email_query = db.collection('users').where(filter=firestore.FieldFilter('email', '==', email.lower())).limit(1).stream()
    email_docs = list(email_query)
    if email_docs:
        logger.debug(f"Email '{email}' already exists with doc ID: {email_docs[0].id}")
        return "email", email_docs[0].id

    id_query = db.collection('users').where(filter=firestore.FieldFilter('id', '==', id)).limit(1).stream()
    id_docs = list(id_query)
    if id_docs:
        logger.debug(f"ID '{id}' already exists with doc ID: {id_docs[0].id}")
        return "id", id_docs[0].id

    logger.debug("No existing user found")
    return None, None

# Input validation helper
def validate_input(data, required_fields):
    for field in required_fields:
        if field not in data or not data[field]:
            return False, f"Missing or empty field: {field}"
    return True, None

# Registration endpoint
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        logger.debug(f"Received registration data: {data}")

        required_fields = ['name', 'email', 'id', 'dept', 'password']
        is_valid, error_message = validate_input(data, required_fields)
        if not is_valid:
            logger.error(error_message)
            return jsonify({'success': False, 'message': error_message}), 400

        name = data.get('name')
        email = data.get('email').lower()  # Normalize email to lowercase
        id = data.get('id')
        dept = data.get('dept')
        password = data.get('password')
        role = data.get('role', 'user')

        conflict_field, existing_user_id = check_existing_user(email, id)
        if conflict_field:
            message = f"{conflict_field.capitalize()} already exists"
            logger.error(message)
            return jsonify({'success': False, 'message': message}), 400

        if role not in ['user', 'admin']:
            logger.error("Invalid role selected")
            return jsonify({'success': False, 'message': 'Invalid role'}), 400

        password_hash = generate_password_hash(password)

        user_data = {
            'name': name,
            'email': email,  # Store email in lowercase
            'id': id,
            'dept': dept,
            'password_hash': password_hash,
            'role': role
        }
        logger.debug(f"Saving user data to Firestore: {user_data}")

        db.collection('users').document(id).set(user_data)
        logger.info(f"User {id} successfully saved to Firestore")

        return jsonify({'success': True, 'message': 'User registered successfully'}), 200

    except Exception as e:
        logger.error(f"Error during registration: {str(e)}")
        return jsonify({'success': False, 'message': f'Registration failed: {str(e)}'}), 500

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400

        required_fields = ['role', 'email', 'password']
        is_valid, error_message = validate_input(data, required_fields)
        if not is_valid:
            return jsonify({'success': False, 'message': error_message}), 400

        role = data.get('role')
        email = data.get('email').lower()  # Normalize email to lowercase
        password = data.get('password')

        if role not in ['user', 'admin']:
            return jsonify({'success': False, 'message': 'Invalid role selected'}), 400

        users_ref = db.collection('users').where(filter=firestore.FieldFilter('email', '==', email)).limit(1).stream()
        user = None
        for doc in users_ref:
            user_doc = doc.to_dict()
            user = User.from_dict(doc.id, user_doc)
            break

        if user:
            if not hasattr(user, 'password_hash') or not user.password_hash:
                return jsonify({'success': False, 'message': 'User data corrupted: missing password'}), 500
            if not check_password_hash(user.password_hash, password):
                return jsonify({'success': False, 'message': 'Invalid password'}), 401
            if user.role != role:
                return jsonify({'success': False, 'message': 'Role does not match'}), 400
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'role': user.role,
                'user': {'name': user.name, 'email': user.email, 'id': user.id, 'dept': user.dept}
            }), 200
        else:
            return jsonify({'success': False, 'message': 'User not found'}), 401

    except Exception as e:
        logger.error(f"Error in login endpoint: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

# Run the app
if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
