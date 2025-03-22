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

def check_existing_user(email, id):
    logger.debug(f"Checking if user exists with email: {email}, id: {id}")
    email_query = db.collection('users').where(filter=firestore.FieldFilter('email', '==', email)).limit(1).stream()
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

# Inventory class
class InventoryItem:
    def __init__(self, id, name, category, sku, quantity, unit_price, image_url=None):
        self.id = id
        self.name = name
        self.category = category
        self.sku = sku
        self.quantity = quantity
        self.unit_price = unit_price
        self.image_url = image_url

    def to_dict(self):
        return {
            'name': self.name,
            'category': self.category,
            'sku': self.sku,
            'quantity': self.quantity,
            'unit_price': self.unit_price,
            'image_url': self.image_url if self.image_url else None
        }

    @staticmethod
    def from_dict(doc_id, data):
        return InventoryItem(
            id=doc_id,
            name=data['name'],
            category=data['category'],
            sku=data['sku'],
            quantity=data['quantity'],
            unit_price=data['unit_price'],
            image_url=data.get('image_url', None)
        )

def check_existing_sku(sku, exclude_id=None):
    logger.debug(f"Checking existing SKU: {sku}")
    query = db.collection('inventory').where(filter=firestore.FieldFilter('sku', '==', sku)).stream()
    for doc in query:
        if exclude_id is None or doc.id != exclude_id:
            return doc.id
    return None

# Input validation helper
def validate_input(data, required_fields):
    for field in required_fields:
        if field not in data or not data[field]:
            return False, f"Missing or empty field: {field}"
    return True, None

# Routes
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
        email = data.get('email')
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
            'email': email,
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
        email = data.get('email')
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
        @app.route('/inventory', methods=['GET'])
def get_inventory():
    try:
        inventory_ref = db.collection('inventory').stream()
        items = [InventoryItem.from_dict(doc.id, doc.to_dict()) for doc in inventory_ref]
        return jsonify({
            'success': True,
            'items': [{'id': item.id, 'name': item.name, 'category': item.category, 'sku': item.sku, 'quantity': item.quantity, 'unit_price': item.unit_price, 'image_url': item.image_url} for item in items]
        }), 200
    except Exception as e:
        logger.error(f"Error fetching inventory: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/inventory', methods=['POST'])
def add_inventory():
    try:
        logger.debug("Received POST request to /inventory")
        data = request.json
        required_fields = ['name', 'category', 'sku', 'quantity', 'unit_price']
        is_valid, error_message = validate_input(data, required_fields)
        if not is_valid:
            logger.error(error_message)
            return jsonify({'success': False, 'message': error_message}), 400

        name = data.get('name')
        category = data.get('category')
        sku = data.get('sku')
        quantity = data.get('quantity')
        unit_price = data.get('unit_price')
        image_url = data.get('image_url')

        if check_existing_sku(sku):
            logger.error(f"SKU {sku} already exists")
            return jsonify({'success': False, 'message': 'SKU already exists'}), 400

        try:
            quantity = int(quantity)
            unit_price = float(unit_price)
        except ValueError as e:
            logger.error(f"Invalid quantity or unit_price: {str(e)}")
            return jsonify({'success': False, 'message': 'Invalid quantity or unit price'}), 400

        new_item = InventoryItem(None, name, category, sku, quantity, unit_price, image_url)
        item_ref = db.collection('inventory').document()
        new_item.id = item_ref.id
        item_ref.set(new_item.to_dict())
        logger.debug(f"Item saved to Firestore with ID: {new_item.id}")

        return jsonify({'success': True, 'message': 'Item added successfully', 'id': new_item.id}), 201

    except Exception as e:
        logger.exception("Error in add_inventory: %s", str(e))
        return jsonify({'success': False, 'message': f'Internal server error: {str(e)}'}), 500

@app.route('/inventory/<item_id>', methods=['PUT'])
def update_inventory(item_id):
    try:
        logger.debug(f"Received PUT request to /inventory/{item_id}")
        data = request.json
        required_fields = ['name', 'category', 'sku', 'quantity', 'unit_price']
        is_valid, error_message = validate_input(data, required_fields)
        if not is_valid:
            logger.error(error_message)
            return jsonify({'success': False, 'message': error_message}), 400

        name = data.get('name')
        category = data.get('category')
        sku = data.get('sku')
        quantity = data.get('quantity')
        unit_price = data.get('unit_price')
        image_url = data.get('image_url')

        existing_sku_id = check_existing_sku(sku, exclude_id=item_id)
        if existing_sku_id:
            logger.error(f"SKU {sku} already exists for another item")
            return jsonify({'success': False, 'message': 'SKU already exists'}), 400

        try:
            quantity = int(quantity)
            unit_price = float(unit_price)
        except ValueError as e:
            logger.error(f"Invalid quantity or unit_price: {str(e)}")
            return jsonify({'success': False, 'message': 'Invalid quantity or unit price'}), 400

        item_ref = db.collection('inventory').document(item_id)
        item = item_ref.get()
        if not item.exists:
            logger.error(f"Item {item_id} not found")
            return jsonify({'success': False, 'message': 'Item not found'}), 404

        updated_item = InventoryItem(item_id, name, category, sku, quantity, unit_price, image_url)
        item_ref.set(updated_item.to_dict())
        logger.debug(f"Item {item_id} updated in Firestore")

        return jsonify({'success': True, 'message': 'Item updated successfully'}), 200

    except Exception as e:
        logger.exception("Error in update_inventory: %s", str(e))
        return jsonify({'success': False, 'message': f'Internal server error: {str(e)}'}), 500

@app.route('/inventory/<item_id>', methods=['DELETE'])
def delete_inventory(item_id):
    try:
        item_ref = db.collection('inventory').document(item_id)
        item = item_ref.get()
        if not item.exists:
            return jsonify({'success': False, 'message': 'Item not found'}), 404
        item_ref.delete()
        return jsonify({'success': True, 'message': 'Item deleted successfully'}), 200
    except Exception as e:
        logger.exception("Error in delete_inventory: %s", str(e))
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/requests', methods=['POST'])
def create_request():
    try:
        logger.debug("Received POST request to /requests")
        data = request.json
        required_fields = ['userId', 'productId', 'productName', 'timestamp']
        is_valid, error_message = validate_input(data, required_fields)
        if not is_valid:
            logger.error(error_message)
            return jsonify({'success': False, 'message': error_message}), 400

        user_id = data.get('userId')
        product_id = data.get('productId')
        product_name = data.get('productName')
        timestamp = data.get('timestamp')
        status = data.get('status', 'Pending')

        user_ref = db.collection('users').where(filter=firestore.FieldFilter('id', '==', user_id)).limit(1).stream()
        user_exists = any(doc.exists for doc in user_ref)
        if not user_exists:
            logger.error(f"User {user_id} not found")
            return jsonify({'success': False, 'message': 'User not found'}), 404

        product_ref = db.collection('inventory').document(product_id)
        if not product_ref.get().exists:
            logger.error(f"Product {product_id} not found")
            return jsonify({'success': False, 'message': 'Product not found'}), 404

        request_data = {
            'userId': user_id,
            'productId': product_id,
            'productName': product_name,
            'timestamp': timestamp,
            'status': status,
        }

        request_ref = db.collection('requests').document()  # Fixed typo: 'users' -> 'requests'
        request_ref.set(request_data)
        logger.debug(f"Request saved to Firestore with ID: {request_ref.id}")

        return jsonify({'success': True, 'message': 'Request created successfully', 'requestId': request_ref.id}), 201
    except Exception as e:
        logger.exception("Error in create_request: %s", str(e))
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/requests', methods=['GET'])
def get_requests():
    try:
        requests_ref = db.collection('requests').stream()
        requests = []
        for doc in requests_ref:
            req = doc.to_dict()
            req['requestId'] = doc.id
            user_ref = db.collection('users').where(filter=firestore.FieldFilter('id', '==', req['userId'])).limit(1).stream()
            requester_name = next((u.to_dict()['name'] for u in user_ref), 'Unknown')
            req['requester'] = requester_name
            requests.append(req)
        return jsonify({'success': True, 'requests': requests}), 200
    except Exception as e:
        logger.error(f"Error fetching requests: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/requests/<request_id>', methods=['PUT'])
def update_request(request_id):
    try:
        data = request.json
        if 'status' not in data or not data['status']:
            return jsonify({'success': False, 'message': 'Status is required'}), 400

        status = data.get('status')
        request_ref = db.collection('requests').document(request_id)
        if not request_ref.get().exists:
            return jsonify({'success': False, 'message': 'Request not found'}), 404

        request_ref.update({'status': status})
        return jsonify({'success': True, 'message': f'Request {status} successfully'}), 200
    except Exception as e:
        logger.error(f"Error updating request: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/requests/<request_id>', methods=['DELETE'])
def delete_request(request_id):
    try:
        data = request.json or {}
        user_id = data.get('userId')
        if not user_id:
            return jsonify({'success': False, 'message': 'User ID is required'}), 400

        request_ref = db.collection('requests').document(request_id)
        request_doc = request_ref.get()
        if not request_doc.exists:
            return jsonify({'success': False, 'message': 'Request not found'}), 404

        request_data = request_doc.to_dict()
        if request_data['userId'] != user_id:
            return jsonify({'success': False, 'message': 'You can only delete your own requests'}), 403

        request_ref.delete()
        return jsonify({'success': True, 'message': 'Request deleted successfully'}), 200
    except Exception as e:
        logger.error(f"Error deleting request: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/dashboard', methods=['GET'])
def get_dashboard_data():
    try:
        inventory_ref = db.collection('inventory').stream()
        inventory_items = [InventoryItem.from_dict(doc.id, doc.to_dict()) for doc in inventory_ref]
        total_items = len(inventory_items)
        total_value = sum(item.unit_price * item.quantity for item in inventory_items)
        low_stock_items = [item.to_dict() for item in inventory_items if item.quantity < 5]

        requests_ref = db.collection('requests').order_by('timestamp', direction=firestore.Query.DESCENDING).limit(5).stream()
        recent_orders = []
        total_orders = 0
        pending_orders = 0
        for doc in db.collection('requests').stream():
            total_orders += 1
            if doc.to_dict().get('status') == 'Pending':
                pending_orders += 1

        for doc in requests_ref:
            req = doc.to_dict()
            req['requestId'] = doc.id
            user_ref = db.collection('users').where(filter=firestore.FieldFilter('id', '==', req['userId'])).limit(1).stream()
            req['requester'] = next((u.to_dict()['name'] for u in user_ref), 'Unknown')
            recent_orders.append(req)

        return jsonify({
            'success': True,
            'data': {
                'total_items': total_items,
                'total_value': round(total_value, 2),
                'low_stock_items': low_stock_items,
                'total_orders': total_orders,
                'pending_orders': pending_orders,
                'recent_orders': recent_orders
            }
        }), 200
    except Exception as e:
        logger.error(f"Error fetching dashboard data: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
