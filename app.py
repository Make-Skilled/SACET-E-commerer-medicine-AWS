from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_cors import CORS
from flask_session import Session
import bcrypt
from datetime import datetime
import os
from werkzeug.utils import secure_filename
from config import Config
from utils.db import DynamoDB
import functools
import boto3
from botocore.exceptions import ClientError
import uuid
import json

app = Flask(__name__)
CORS(app)

# Session configuration
app.config['SECRET_KEY'] = Config.SECRET_KEY
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# File Upload Configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize AWS clients at startup
s3_client = boto3.client('s3',
)

textract_client = boto3.client('textract',
)

db = DynamoDB()

# Create tables on startup
db.create_tables()

# Check S3 bucket exists and configure permissions
try:
    s3_client.head_bucket(Bucket=Config.S3_BUCKET_NAME)
    print(f"Successfully connected to S3 bucket: {Config.S3_BUCKET_NAME}")
    
    # Set bucket policy to allow Textract access
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowTextractAccess",
                "Effect": "Allow",
                "Principal": {
                    "Service": "textract.amazonaws.com"
                },
                "Action": [
                    "s3:GetObject",
                    "s3:ListBucket"
                ],
                "Resource": [
                    f"arn:aws:s3:::{Config.S3_BUCKET_NAME}",
                    f"arn:aws:s3:::{Config.S3_BUCKET_NAME}/*"
                ]
            }
        ]
    }
    
    try:
        s3_client.put_bucket_policy(
            Bucket=Config.S3_BUCKET_NAME,
            Policy=json.dumps(bucket_policy)
        )
        print("Successfully updated bucket policy for Textract access")
    except Exception as policy_error:
        print(f"Error setting bucket policy: {str(policy_error)}")
        
except Exception as e:
    print(f"Error connecting to S3 bucket: {str(e)}")
    # Create bucket if it doesn't exist
    try:
        s3_client.create_bucket(
            Bucket=Config.S3_BUCKET_NAME,
            CreateBucketConfiguration={'LocationConstraint': Config.AWS_REGION}
        )
        print(f"Created S3 bucket: {Config.S3_BUCKET_NAME}")
        
        # Set bucket policy for new bucket
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowTextractAccess",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "textract.amazonaws.com"
                    },
                    "Action": [
                        "s3:GetObject",
                        "s3:ListBucket"
                    ],
                    "Resource": [
                        f"arn:aws:s3:::{Config.S3_BUCKET_NAME}",
                        f"arn:aws:s3:::{Config.S3_BUCKET_NAME}/*"
                    ]
                }
            ]
        }
        
        s3_client.put_bucket_policy(
            Bucket=Config.S3_BUCKET_NAME,
            Policy=json.dumps(bucket_policy)
        )
        print("Successfully set bucket policy for Textract access")
    except Exception as create_error:
        print(f"Error creating S3 bucket: {str(create_error)}")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Login required decorator11
def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in first', 'error')
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def hash_password(password):
    salt = bcrypt.gensalt(Config.SALT_ROUNDS)
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# Authentication Routes
@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        try:
            # Check if user already exists
            existing_user = db.get_item(Config.USERS_TABLE, {'email': request.form['email']})
            if existing_user:
                flash('Email already registered', 'error')
                return render_template('register.html')

            # Hash password
            hashed_password = hash_password(request.form['password'])
            
            # Create user object
            user = {
                'email': request.form['email'],
                'password': hashed_password.decode('utf-8'),
                'name': request.form['name'],
                'mobile': request.form['mobile'],
                'address': {
                    'street': request.form['street'],
                    'landmark': request.form.get('landmark', ''),
                    'city': request.form['city'],
                    'state': request.form['state'],
                    'pincode': request.form['pincode']
                },
                'created_at': datetime.utcnow().isoformat()
            }
            
            # Save to DynamoDB
            db.put_item(Config.USERS_TABLE, user)
            
            # Set session
            session['user'] = {
                'email': user['email'],
                'name': user['name']
            }
            
            flash('Registration successful!', 'success')
            return redirect(url_for('login_page'))

        except Exception as e:
            flash(str(e), 'error')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        try:
            email = request.form['email']
            password = request.form['password']

            if email == 'admin@medimart.com' and password == 'admin123':
                session['user'] = {
                    'email': 'admin@medimart.com',
                    'name': 'Admin'
                }
                return redirect(url_for('admin_dashboard'))


            # Get user from DynamoDB
            user = db.get_item(Config.USERS_TABLE, {'email': email})
            
            if not user:
                flash('User not found', 'error')
                return render_template('login.html')

            # Check password
            if not check_password(password, user['password']):
                flash('Invalid password', 'error')
                return render_template('login.html')

            # Set session
            session['user'] = {
                'email': user['email'],
                'name': user['name']
            }

            flash('Login successful!', 'success')
            return redirect(url_for('user_dashboard'))

        except Exception as e:
            flash(str(e), 'error')
            return render_template('login.html')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

# Frontend Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/shop')
@login_required
def shop():
    return render_template('shop.html')

@app.route('/products')
def products():
    try:
        # Get all products from DynamoDB
        products = db.scan(Config.PRODUCTS_TABLE)
        
        # Get filter parameters
        search_query = request.args.get('search', '').lower()
        category_filter = request.args.get('category', '')
        min_price = request.args.get('min_price', '')
        max_price = request.args.get('max_price', '')
        sort_by = request.args.get('sort', 'name')  # Default sort by name
        
        # Apply filters
        if search_query:
            products = [p for p in products if search_query in p['name'].lower() or 
                       search_query in p['generic_name'].lower() or 
                       search_query in p['description'].lower()]
        
        if category_filter:
            products = [p for p in products if p['category'] == category_filter]
        
        if min_price:
            try:
                min_price = float(min_price)
                products = [p for p in products if float(p['price']) >= min_price]
            except ValueError:
                pass
        
        if max_price:
            try:
                max_price = float(max_price)
                products = [p for p in products if float(p['price']) <= max_price]
            except ValueError:
                pass
        
        # Sort products
        if sort_by == 'price_low':
            products.sort(key=lambda x: float(x['price']))
        elif sort_by == 'price_high':
            products.sort(key=lambda x: float(x['price']), reverse=True)
        elif sort_by == 'name':
            products.sort(key=lambda x: x['name'])
        
        # Get unique categories for filter dropdown
        categories = sorted(list(set(p['category'] for p in products)))
        
        return render_template('products.html', 
                             products=products,
                             categories=categories,
                             current_category=category_filter,
                             current_search=search_query,
                             current_min_price=min_price,
                             current_max_price=max_price,
                             current_sort=sort_by)
                             
    except Exception as e:
        print("Error in products route:", str(e))
        flash('Error loading products', 'error')
        return render_template('products.html', products=[], categories=[])

@app.route('/cart')
@login_required
def cart():
    try:
        # Get cart items for the current user
        cart_items = db.query(
            Config.CART_TABLE,
            KeyConditionExpression='user_email = :email',
            ExpressionAttributeValues={':email': session['user']['email']}
        )
        
        # Calculate total price
        total_price = 0
        for item in cart_items:
            try:
                item_price = float(item.get('price', 0))
                item_quantity = int(item.get('quantity', 0))
                total_price += item_price * item_quantity
            except (ValueError, TypeError) as e:
                print(f"Error calculating price for item: {str(e)}")
                continue
        
        return render_template('cart.html', cart_items=cart_items, total_price=total_price)
    except Exception as e:
        print("Error fetching cart items:", str(e))
        flash('Error loading cart items', 'error')
        return render_template('cart.html', cart_items=[], total_price=0)

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    return render_template('user/dashboard.html')

@app.route('/user/orders')
@login_required
def user_orders():
    return render_template('user/orders.html')

# Admin Routes
@app.route('/admin')
@login_required
def admin_dashboard():
    if session.get('user', {}).get('email') not in Config.ADMIN_EMAILS:
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    return render_template('admin/dashboard.html')

@app.route('/admin/add-medicine', methods=['GET', 'POST'])
@login_required
def add_medicine():
    if session.get('user', {}).get('email') not in Config.ADMIN_EMAILS:
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            # Handle file upload
            if 'image' not in request.files:
                flash('No image file provided', 'error')
                return redirect(request.url)
            
            file = request.files['image']
            if file.filename == '':
                flash('No selected file', 'error')
                return redirect(request.url)
            
            if file and allowed_file(file.filename):
                # Secure the filename and save the file
                filename = secure_filename(file.filename)
                # Add timestamp to filename to make it unique
                timestamp = str(int(datetime.utcnow().timestamp()))
                filename = f"{timestamp}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                # Print form data for debugging
                print("Form Data:", request.form)
                
                try:
                    # Create medicine object with proper data types
                    medicine = {
                        'id': timestamp,  # Primary key must be a string
                        'name': request.form['name'],
                        'generic_name': request.form['generic_name'],
                        'category': request.form['category'],
                        'manufacturer': request.form['manufacturer'],
                        'price': str(float(request.form['price'])),  # Store as string
                        'stock': str(int(request.form['stock'])),    # Store as string
                        'expiry_date': request.form['expiry_date'],
                        'batch_number': request.form['batch_number'],
                        'description': request.form['description'],
                        'image_path': os.path.join('uploads', filename)
                    }
                    
                    print("Medicine object:", medicine)  # Debug print
                    
                    # Save to DynamoDB
                    response = db.put_item(Config.PRODUCTS_TABLE, medicine)
                    print("DynamoDB Response:", response)  # Debug print
                    
                    flash('Medicine added successfully!', 'success')
                    return redirect(url_for('view_products'))
                except Exception as e:
                    print("Error creating medicine object:", str(e))  # Debug print
                    raise
            else:
                flash('Invalid file type. Allowed types are: png, jpg, jpeg, gif', 'error')
                return redirect(request.url)
            
        except Exception as e:
            print("Error in add_medicine:", str(e))  # Debug print
            flash(str(e), 'error')
            return redirect(request.url)
            
    return render_template('admin/add_medicine.html')

@app.route('/admin/view-products')
@login_required
def view_products():
    if session.get('user', {}).get('email') not in Config.ADMIN_EMAILS:
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    try:
        # Get all products from DynamoDB
        products = db.scan(Config.PRODUCTS_TABLE)
        return render_template('admin/view_products.html', products=products)
    except Exception as e:
        flash(f'Error retrieving products: {str(e)}', 'error')
        return render_template('admin/view_products.html', products=[])

@app.route('/admin/orders')
@login_required
def view_orders():
    if session.get('user', {}).get('email') not in Config.ADMIN_EMAILS:
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    return render_template('admin/orders.html')

@app.route('/admin/edit-medicine/<product_id>', methods=['GET', 'POST'])
@login_required
def edit_medicine(product_id):
    if session.get('user', {}).get('email') not in Config.ADMIN_EMAILS:
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    try:
        # Get the product from DynamoDB
        product = db.get_item(Config.PRODUCTS_TABLE, {'id': product_id})
        
        if not product:
            flash('Product not found', 'error')
            return redirect(url_for('view_products'))
        
        if request.method == 'POST':
            try:
                # Handle file upload
                if 'image' in request.files and request.files['image'].filename:
                    file = request.files['image']
                    if file and allowed_file(file.filename):
                        # Delete old image if it exists
                        if product.get('image_path'):
                            old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(product['image_path']))
                            if os.path.exists(old_image_path):
                                os.remove(old_image_path)
                        
                        # Save new image
                        filename = secure_filename(file.filename)
                        timestamp = str(int(datetime.utcnow().timestamp()))
                        filename = f"{timestamp}_{filename}"
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(filepath)
                        image_path = os.path.join('uploads', filename)
                    else:
                        flash('Invalid file type', 'error')
                        return redirect(request.url)
                else:
                    image_path = product['image_path']
                
                # Update product in DynamoDB
                updated_product = {
                    'id': product_id,
                    'name': request.form['name'],
                    'generic_name': request.form['generic_name'],
                    'category': request.form['category'],
                    'manufacturer': request.form['manufacturer'],
                    'price': str(float(request.form['price'])),
                    'stock': str(int(request.form['stock'])),
                    'expiry_date': request.form['expiry_date'],
                    'batch_number': request.form['batch_number'],
                    'description': request.form['description'],
                    'image_path': image_path
                }
                
                db.put_item(Config.PRODUCTS_TABLE, updated_product)
                flash('Medicine updated successfully!', 'success')
                return redirect(url_for('view_products'))
                
            except Exception as e:
                print("Error updating medicine:", str(e))
                flash(str(e), 'error')
                return redirect(request.url)
        
        return render_template('admin/edit_medicine.html', product=product)
        
    except Exception as e:
        print("Error in edit_medicine:", str(e))
        flash(str(e), 'error')
        return redirect(url_for('view_products'))

@app.route('/admin/delete-product/<product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    if session.get('user', {}).get('email') not in Config.ADMIN_EMAILS:
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    try:
        # Get the product to delete its image
        product = db.get_item(Config.PRODUCTS_TABLE, {'id': product_id})
        
        if product:
            # Delete the image file if it exists
            if product.get('image_path'):
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(product['image_path']))
                if os.path.exists(image_path):
                    os.remove(image_path)
            
            # Delete from DynamoDB
            table = db.get_table(Config.PRODUCTS_TABLE)
            table.delete_item(Key={'id': product_id})
            
            flash('Product deleted successfully!', 'success')
        else:
            flash('Product not found', 'error')
            
    except Exception as e:
        print("Error deleting product:", str(e))
        flash(f'Error deleting product: {str(e)}', 'error')
    
    return redirect(url_for('view_products'))

@app.route('/api/add-to-cart/<product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    try:
        # Get the product details
        product = db.get_item(Config.PRODUCTS_TABLE, {'id': product_id})
        if not product:
            return {'success': False, 'message': 'Product not found'}, 404

        # Get the quantity from request (default to 1)
        quantity = int(request.form.get('quantity', 1))
        
        # Validate quantity
        if quantity <= 0:
            return {'success': False, 'message': 'Invalid quantity'}, 400
            
        # Check if product has enough stock
        if int(product['stock']) < quantity:
            return {'success': False, 'message': 'Not enough stock available'}, 400

        # Create cart item object with proper data types
        cart_item = {
            'user_email': session['user']['email'],  # Partition key
            'product_id': product_id,                # Sort key
            'quantity': str(quantity),               # Store as string
            'price': product['price'],              # Already stored as string
            'name': product['name'],                # Product details for cart display
            'image_path': product['image_path'],
            'category': product['category']
        }

        # Check if item already exists in cart
        existing_item = db.get_item(Config.CART_TABLE, {
            'user_email': session['user']['email'],
            'product_id': product_id
        })

        if existing_item:
            # Update quantity if item exists
            new_quantity = int(existing_item['quantity']) + quantity
            if int(product['stock']) < new_quantity:
                return {'success': False, 'message': 'Not enough stock available'}, 400
                
            cart_item['quantity'] = str(new_quantity)

        # Save to DynamoDB
        db.put_item(Config.CART_TABLE, cart_item)
        
        return {
            'success': True,
            'message': 'Product added to cart successfully',
            'cart_count': get_cart_count(session['user']['email'])
        }

    except ValueError as e:
        print("Validation error in add_to_cart:", str(e))
        return {'success': False, 'message': 'Invalid quantity'}, 400
    except Exception as e:
        print("Error in add_to_cart:", str(e))
        return {'success': False, 'message': str(e)}, 500

def get_cart_count(user_email):
    try:
        # Query cart items for the user
        items = db.query(
            Config.CART_TABLE,
            KeyConditionExpression='user_email = :email',
            ExpressionAttributeValues={':email': user_email}
        )
        return len(items)
    except Exception as e:
        print("Error getting cart count:", str(e))
        return 0

@app.route('/api/update-cart/<product_id>', methods=['POST'])
@login_required
def update_cart(product_id):
    try:
        # Get the new quantity from request
        quantity = int(request.form.get('quantity', 1))
        
        if quantity < 1:
            return {'success': False, 'message': 'Invalid quantity'}, 400

        # Get the product to check stock
        product = db.get_item(Config.PRODUCTS_TABLE, {'id': product_id})
        if not product:
            return {'success': False, 'message': 'Product not found'}, 404

        # Check if there's enough stock
        if int(product['stock']) < quantity:
            return {'success': False, 'message': 'Not enough stock available'}, 400

        # Get current cart item
        cart_item = db.get_item(Config.CART_TABLE, {
            'user_email': session['user']['email'],
            'product_id': product_id
        })

        if not cart_item:
            return {'success': False, 'message': 'Item not found in cart'}, 404

        # Update cart item
        cart_item['quantity'] = str(quantity)
        db.put_item(Config.CART_TABLE, cart_item)

        return {
            'success': True,
            'message': 'Cart updated successfully'
        }

    except ValueError as e:
        return {'success': False, 'message': 'Invalid quantity'}, 400
    except Exception as e:
        print("Error updating cart:", str(e))
        return {'success': False, 'message': str(e)}, 500

@app.route('/api/remove-from-cart/<product_id>', methods=['POST'])
@login_required
def remove_from_cart(product_id):
    try:
        # Delete the item from the cart table
        table = db.get_table(Config.CART_TABLE)
        table.delete_item(
            Key={
                'user_email': session['user']['email'],
                'product_id': product_id
            }
        )

        return {
            'success': True,
            'message': 'Item removed from cart'
        }

    except Exception as e:
        print("Error removing item from cart:", str(e))
        return {'success': False, 'message': str(e)}, 500

@app.route('/api/place-order', methods=['POST'])
@login_required
def place_order():
    try:
        # Get cart items
        cart_items = db.query(
            Config.CART_TABLE,
            KeyConditionExpression='user_email = :email',
            ExpressionAttributeValues={':email': session['user']['email']}
        )
        
        if not cart_items:
            return {'success': False, 'message': 'Cart is empty'}, 400
            
        # Generate order ID
        order_id = str(int(datetime.utcnow().timestamp()))
        
        # Create order items and update stock
        order_items = []
        total_amount = 0
        
        for item in cart_items:
            # Get product to check and update stock
            product = db.get_item(Config.PRODUCTS_TABLE, {'id': item['product_id']})
            if not product:
                return {'success': False, 'message': f'Product {item["name"]} no longer exists'}, 400
                
            # Check stock availability
            current_stock = int(product['stock'])
            order_quantity = int(item['quantity'])
            
            if current_stock < order_quantity:
                return {
                    'success': False, 
                    'message': f'Not enough stock for {item["name"]}. Available: {current_stock}'
                }, 400
            
            # Update product stock
            product['stock'] = str(current_stock - order_quantity)
            db.put_item(Config.PRODUCTS_TABLE, product)
            
            # Calculate item total
            item_total = float(item['price']) * order_quantity
            total_amount += item_total
            
            # Add to order items
            order_items.append({
                'product_id': item['product_id'],
                'name': item['name'],
                'quantity': str(order_quantity),
                'price': item['price'],
                'total': str(item_total)
            })
        
        # Create order
        order = {
            'id': order_id,
            'user_email': session['user']['email'],
            'items': order_items,
            'total_amount': str(total_amount),
            'status': 'pending',
            'payment_status': 'pending',
            'created_at': datetime.utcnow().isoformat(),
            'shipping_address': db.get_item(Config.USERS_TABLE, {'email': session['user']['email']})['address']
        }
        
        # Save order to DynamoDB
        db.put_item(Config.ORDERS_TABLE, order)
        
        # Clear cart
        table = db.get_table(Config.CART_TABLE)
        with table.batch_writer() as batch:
            for item in cart_items:
                batch.delete_item(
                    Key={
                        'user_email': session['user']['email'],
                        'product_id': item['product_id']
                    }
                )
        
        return {
            'success': True,
            'message': 'Order placed successfully!',
            'order_id': order_id
        }
        
    except Exception as e:
        print("Error placing order:", str(e))
        return {'success': False, 'message': str(e)}, 500

@app.route('/api/update-order-status/<order_id>', methods=['POST'])
@login_required
def update_order_status(order_id):
    if session.get('user', {}).get('email') not in Config.ADMIN_EMAILS:
        return {'success': False, 'message': 'Unauthorized access'}, 403
        
    try:
        # Get all orders and find the specific one
        all_orders = db.scan(Config.ORDERS_TABLE)
        order = next((o for o in all_orders if o['id'] == order_id), None)
        
        if not order:
            return {'success': False, 'message': 'Order not found'}, 404
            
        # Get new status from request
        data = request.get_json()
        new_status = data.get('status')
        
        if not new_status:
            return {'success': False, 'message': 'No status provided'}, 400
            
        # Update order status
        order['status'] = new_status
        db.put_item(Config.ORDERS_TABLE, order)
        
        return {
            'success': True,
            'message': f'Order status updated to {new_status}'
        }
        
    except Exception as e:
        print("Error updating order status:", str(e))
        return {'success': False, 'message': str(e)}, 500

@app.route('/api/user/orders', methods=['GET'])
@login_required
def get_user_orders():
    try:
        # Get all orders and filter for current user
        all_orders = db.scan(Config.ORDERS_TABLE) or []
        user_orders = [order for order in all_orders if order.get('user_email') == session['user']['email']]
        
        # Sort orders by creation date (newest first)
        user_orders.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        # Format order data
        formatted_orders = []
        for order in user_orders:
            try:
                formatted_order = {
                    'id': order['id'],
                    'created_at': order['created_at'],
                    'status': order['status'],
                    'payment_status': order.get('payment_status', 'pending'),
                    'total_amount': float(order['total_amount']),
                    'items': [],
                    'shipping_address': order['shipping_address']
                }
                
                # Format order items
                for item in order.get('items', []):
                    formatted_item = {
                        'product_id': item['product_id'],
                        'name': item['name'],
                        'quantity': int(item['quantity']),
                        'price': float(item['price']),
                        'total': float(item['total'])
                    }
                    formatted_order['items'].append(formatted_item)
                
                formatted_orders.append(formatted_order)
            except (ValueError, KeyError) as e:
                print(f"Error formatting order {order.get('id')}: {str(e)}")
                continue
        
        return {
            'success': True,
            'orders': formatted_orders
        }
        
    except Exception as e:
        print("Error fetching user orders:", str(e))
        return {
            'success': False,
            'message': 'Error fetching orders',
            'error': str(e)
        }, 500

@app.route('/api/admin/orders', methods=['GET'])
@login_required
def get_all_orders():
    if session.get('user', {}).get('email') not in Config.ADMIN_EMAILS:
        return {'success': False, 'message': 'Unauthorized access'}, 403
        
    try:
        # Get all orders from DynamoDB
        orders = db.scan(Config.ORDERS_TABLE) or []
        
        # Sort orders by creation date (newest first)
        orders.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        # Format order data
        formatted_orders = []
        for order in orders:
            try:
                formatted_order = {
                    'id': order['id'],
                    'user_email': order['user_email'],
                    'created_at': order['created_at'],
                    'status': order['status'],
                    'payment_status': order.get('payment_status', 'pending'),
                    'total_amount': float(order['total_amount']),
                    'items': [],
                    'shipping_address': order['shipping_address']
                }
                
                # Format order items
                for item in order.get('items', []):
                    formatted_item = {
                        'product_id': item['product_id'],
                        'name': item['name'],
                        'quantity': int(item['quantity']),
                        'price': float(item['price']),
                        'total': float(item['total'])
                    }
                    formatted_order['items'].append(formatted_item)
                
                formatted_orders.append(formatted_order)
            except (ValueError, KeyError) as e:
                print(f"Error formatting order {order.get('id')}: {str(e)}")
                continue
        
        return {
            'success': True,
            'orders': formatted_orders
        }
        
    except Exception as e:
        print("Error fetching all orders:", str(e))
        return {
            'success': False,
            'message': 'Error fetching orders',
            'error': str(e)
        }, 500

@app.route('/success')
@login_required
def payment_success():
    return render_template('success.html')

@app.route('/api/analyze-prescription', methods=['POST'])
@login_required
def analyze_prescription():
    try:
        if 'prescription' not in request.files:
            return {'success': False, 'message': 'No file uploaded'}, 400
            
        file = request.files['prescription']
        if file.filename == '':
            return {'success': False, 'message': 'No file selected'}, 400
            
        if not file or not allowed_file(file.filename):
            return {'success': False, 'message': 'Invalid file type'}, 400

        # Generate unique filename
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        unique_id = str(uuid.uuid4())[:8]
        filename = secure_filename(file.filename)
        unique_filename = f"{timestamp}_{unique_id}_{filename}"
        s3_key = f"prescriptions/{unique_filename}"

        try:
            # Read the file into bytes for Textract
            file_bytes = file.read()
            
            # Analyze with Textract directly
            print("Starting Textract analysis...")
            response = textract_client.detect_document_text(
                Document={
                    'Bytes': file_bytes
                }
            )
            
            # Extract text from Textract response
            extracted_text = ""
            for item in response['Blocks']:
                if item['BlockType'] == 'LINE':
                    extracted_text += item['Text'] + "\n"

            print("Successfully extracted text from image")

            # Reset file pointer for S3 upload
            file.seek(0)
            
            # Upload to S3
            print(f"Uploading file to S3: {s3_key}")
            s3_client.upload_fileobj(
                file,
                Config.S3_BUCKET_NAME,
                s3_key,
                ExtraArgs={'ContentType': file.content_type}
            )
            print(f"File uploaded successfully to S3: {s3_key}")

            # Save prescription record in DynamoDB
            prescription = {
                'id': str(uuid.uuid4()),
                'user_email': session['user']['email'],
                'filename': unique_filename,
                'uploaded_at': datetime.utcnow().isoformat(),
                'extracted_text': extracted_text,
                's3_path': s3_key
            }
            
            db.put_item(Config.PRESCRIPTIONS_TABLE, prescription)

            return {
                'success': True,
                'text': extracted_text,
                'message': 'Prescription analyzed successfully'
            }

        except Exception as e:
            print(f"Error processing prescription: {str(e)}")
            return {'success': False, 'message': 'Error processing prescription'}, 500

    except Exception as e:
        print(f"Error in analyze_prescription: {str(e)}")
        return {'success': False, 'message': str(e)}, 500

@app.route('/api/user/update-payment/<order_id>', methods=['POST'])
@login_required
def update_payment_status(order_id):
    try:
        # Get all orders and find the specific one that belongs to the current user
        all_orders = db.scan(Config.ORDERS_TABLE)
        order = next((o for o in all_orders if o['id'] == order_id and o['user_email'] == session['user']['email']), None)
        
        if not order:
            return {'success': False, 'message': 'Order not found'}, 404
            
        # Update payment status to completed
        order['payment_status'] = 'completed'
        db.put_item(Config.ORDERS_TABLE, order)
        
        return {
            'success': True,
            'message': 'Payment completed successfully'
        }
        
    except Exception as e:
        print("Error updating payment status:", str(e))
        return {'success': False, 'message': str(e)}, 500

if __name__ == '__main__':
    app.run(debug=False,host='0.0.0.0',port=5345) 
