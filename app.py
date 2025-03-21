#python -m venv venv
#venv\Scripts\Activate
#pip install flask flask_sqlalchemy flask_jwt_extended pymysql python-dotenv werkzeug

import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config  # Import our configuration

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# ------------------- Database Models ------------------- #

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # User's full name
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Hashed password

class Product(db.Model):
    pid = db.Column(db.Integer, primary_key=True)
    pname = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Create tables (Run once)
with app.app_context():
    db.create_all()

# ------------------- API Endpoints ------------------- #

# User Signup: Register a new user
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if not data or not all(k in data for k in ("name", "username", "password")):
        return jsonify({'error': 'Missing data'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400

    hashed_password = generate_password_hash(data['password'])
    new_user = User(
        name=data['name'],
        username=data['username'],
        password=hashed_password
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

# User Login: Authenticate user and return a JWT token (valid for 10 minutes)
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not all(k in data for k in ("username", "password")):
        return jsonify({'error': 'Missing credentials'}), 400

    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        token = create_access_token(identity=str(user.id))
        return jsonify({'token': token}), 200

    return jsonify({'error': 'Invalid credentials'}), 401

# Update User: Only authorized users can update their details
@app.route('/users/<int:id>', methods=['PUT'])
@jwt_required()
def update_user(id):
    current_user_id = get_jwt_identity()
    if str(id) != current_user_id:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    user = User.query.get(id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if 'name' in data:
        user.name = data['name']
    if 'username' in data:
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already exists'}), 400
        user.username = data['username']
    if 'password' in data:
        user.password = generate_password_hash(data['password'])
    db.session.commit()
    return jsonify({'message': 'User updated successfully'}), 200

# Create a new product (Protected)
@app.route('/products', methods=['POST'])
@jwt_required()
def add_product():
    data = request.get_json()
    if not data or not all(k in data for k in ("pname", "price", "stock")):
        return jsonify({'error': 'Missing product data'}), 400

    new_product = Product(
        pname=data['pname'],
        description=data.get('description', ''),
        price=data['price'],
        stock=data['stock']
    )
    db.session.add(new_product)
    db.session.commit()
    return jsonify({
        'pid': new_product.pid,
        'pname': new_product.pname,
        'description': new_product.description,
        'price': str(new_product.price),
        'stock': new_product.stock,
        'created_at': new_product.created_at.isoformat()
    }), 201

# Retrieve all products (Protected)
@app.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    products = Product.query.all()
    result = []
    for prod in products:
        result.append({
            'pid': prod.pid,
            'pname': prod.pname,
            'description': prod.description,
            'price': str(prod.price),
            'stock': prod.stock,
            'created_at': prod.created_at.isoformat()
        })
    return jsonify(result), 200

# Retrieve a single product by ID (Protected)
@app.route('/products/<int:pid>', methods=['GET'])
@jwt_required()
def get_product(pid):
    prod = Product.query.get(pid)
    if not prod:
        return jsonify({'error': 'Product not found'}), 404
    return jsonify({
        'pid': prod.pid,
        'pname': prod.pname,
        'description': prod.description,
        'price': str(prod.price),
        'stock': prod.stock,
        'created_at': prod.created_at.isoformat()
    }), 200

# Update product details (Protected)
@app.route('/products/<int:pid>', methods=['PUT'])
@jwt_required()
def update_product(pid):
    data = request.get_json()
    prod = Product.query.get(pid)
    if not prod:
        return jsonify({'error': 'Product not found'}), 404

    if 'pname' in data:
        prod.pname = data['pname']
    if 'description' in data:
        prod.description = data['description']
    if 'price' in data:
        prod.price = data['price']
    if 'stock' in data:
        prod.stock = data['stock']
    db.session.commit()
    return jsonify({'message': 'Product updated successfully'}), 200

# Delete a product (Protected)
@app.route('/products/<int:pid>', methods=['DELETE'])
@jwt_required()
def delete_product(pid):
    prod = Product.query.get(pid)
    if not prod:
        return jsonify({'error': 'Product not found'}), 404

    db.session.delete(prod)
    db.session.commit()
    return jsonify({'message': 'Product deleted successfully'}), 200

if __name__ == '__main__':
    app.run(debug=True)
