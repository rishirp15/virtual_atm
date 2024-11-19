from flask import Flask, render_template, request, redirect, flash, url_for, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
import pytz
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///atm_database.db'
app.config['SECRET_KEY'] = '4d3c2b1a5e0f69b7f00e37a43e54b5c2' 
db = SQLAlchemy(app)

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    vid = db.Column(db.String(10), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  
    pin = db.Column(db.String(6), nullable=True)  

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    recipient_vid = db.Column(db.String(10), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Create the database tables
with app.app_context():
    db.create_all()

# Function to get current time in IST
def get_ist_time():
    utc_time = datetime.utcnow()
    ist_timezone = pytz.timezone('Asia/Kolkata')
    ist_time = utc_time.replace(tzinfo=pytz.utc).astimezone(ist_timezone)
    return ist_time.strftime('%Y-%m-%d %H:%M:%S')

# Decorator for user authentication
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

# Decorator for admin access
def admin_required(f):
    def wrapper(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Access denied: Admins only', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

# Route for the welcome page
@app.route('/')
def welcome():
    return render_template('welcome.html')

# Route for the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard') if user.is_admin else 'dashboard')

        flash('Login failed. Check your credentials.', 'danger')
    return render_template('login.html')

# Function to generate VID
def generate_vid(length=10):
    return ''.join(random.choices(string.digits, k=length))

# Route for the registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Ensure all form fields are present
        username = request.form.get('username')
        password = request.form.get('password')
        pin = request.form.get('pin')
        
        if not username or not password or not pin:
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))

        # Check if the username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        # Generate a unique Vid and hash the password
        vid = generate_vid()
        hashed_password = generate_password_hash(password)

        # Check if the username is "admin" to set admin rights
        is_admin = username.lower() == 'admin'
        
        # Create the new user instance
        new_user = User(username=username, password=hashed_password, vid=vid, balance=0.0, is_admin=is_admin, pin=pin)

        # Add user to the database
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            print(f"Error: {e}")
            return redirect(url_for('register'))

    return render_template('register.html')

# Route for the dashboard page
@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    user = User.query.get(user_id)
    current_time = get_ist_time()
    return render_template('dashboard.html', username=user.username, balance=user.balance, vid=user.vid, current_time=current_time)

# Route for the withdraw page
@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
def withdraw():
    user_id = session['user_id']
    user = User.query.get(user_id)

    if request.method == 'POST':
        try:
            amount = float(request.form['amount'])
            pin = request.form['pin']
            
            if pin != user.pin:
                flash('Invalid transaction PIN. Please try again.', 'danger')
            elif amount <= 0:
                flash('Please enter a valid amount.', 'danger')
            elif user.balance >= amount:
                user.balance -= amount
                transaction = Transaction(user_id=user.id, amount=-amount, description='Withdrawal')
                db.session.add(transaction)
                db.session.commit()
                flash('Withdrawal successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Insufficient balance! Please check your account balance and try again.', 'danger')
        except ValueError:
            flash('Invalid amount. Please enter a number.', 'danger')

    return render_template('withdraw.html')

# Route for the deposit page
@app.route('/deposit', methods=['GET', 'POST'])
@login_required
def deposit():
    user_id = session['user_id']
    
    if request.method == 'POST':
        try:
            amount = float(request.form['amount'])
            pin = request.form['pin']
            user = User.query.get(user_id)
            
            if pin != user.pin:
                flash('Invalid transaction PIN. Please try again.', 'danger')
            elif amount <= 0:
                flash('Please enter a valid amount.', 'danger')
            else:
                user.balance += amount
                transaction = Transaction(user_id=user.id, amount=amount, description='Deposit')
                db.session.add(transaction)
                db.session.commit()
                flash('Deposit successful!', 'success')
                return redirect(url_for('dashboard'))

        except ValueError:
            flash('Invalid amount. Please enter a number.', 'danger')

    return render_template('deposit.html')

# Route for the transfer page
@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    user_id = session['user_id']

    if request.method == 'POST':
        recipient_vid = request.form['vid']
        try:
            amount = float(request.form['amount'])
            pin = request.form['pin']
            user = User.query.get(user_id)
            recipient = User.query.filter_by(vid=recipient_vid).first()

            if recipient and user.balance >= amount:
                if pin == user.pin:  
                    user.balance -= amount
                    recipient.balance += amount

                    transaction_sender = Transaction(user_id=user.id, amount=-amount, description=f'Transfer to {recipient_vid}')
                    transaction_recipient = Transaction(user_id=recipient.id, amount=amount, description=f'Transfer from {user.vid}')

                    db.session.add(transaction_sender)
                    db.session.add(transaction_recipient)

                    db.session.commit()
                    flash('Transfer successful!', 'success')
                else:
                    flash('Invalid transaction PIN. Please try again.', 'danger')
            else:
                flash('Transfer failed. Check recipient VID or insufficient balance.', 'danger')
        except ValueError:
            flash('Invalid amount. Please enter a number.', 'danger')
        
        return redirect(url_for('dashboard'))
    
    return render_template('transfer.html')

# Route for the transaction history page
@app.route('/transaction_history')
@login_required
def transaction_history():
    user_id = session['user_id']
    transactions = Transaction.query.filter_by(user_id=user_id).all()
    return render_template('transaction_history.html', transactions=transactions, timedelta=timedelta)

# Admin route to view all transactions
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    transactions = Transaction.query.join(User).add_columns(User.username, User.vid).all()
    current_time = get_ist_time()
    flash('Welcome to the admin dashboard!', 'success')
    return render_template('admin_dashboard.html', transactions=transactions, timedelta=timedelta)

# Route for logging out
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('welcome'))

if __name__ == '__main__':
    app.run(debug=True)