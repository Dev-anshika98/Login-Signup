from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
import psycopg2

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# Database configuration
DB_HOST = 'localhost'
DB_NAME = 'Star'
DB_USER = 'postgres'
DB_PASS = 'shikucode'

def get_db_connection():
    conn = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )
    return conn

@app.route('/')
def index():
    return redirect(url_for('signup'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('retype_password')
        phone = request.form.get('phone')

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Invalid email address", 'danger')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash("Passwords do not match", 'danger')
            return redirect(url_for('signup'))

        if not re.match(r"^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", password):
            flash("Password must be at least 8 characters long, contain one uppercase letter, one digit, and one symbol", 'danger')
            return redirect(url_for('signup'))

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cur.fetchone()

        if existing_user:
            flash("Email already exists", 'danger')
            conn.close()
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        try:
            cur.execute(
                "INSERT INTO users (first_name, last_name, email, password, phone) VALUES (%s, %s, %s, %s, %s)",
                (first_name, last_name, email, hashed_password, phone)
            )
            conn.commit()
            flash('Account created successfully', 'success')
            return redirect(url_for('signin'))
        except Exception as e:
            conn.rollback()
            flash(f'Error creating account: {e}', 'danger')
        finally:
            conn.close()

    return render_template('signup.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user[4], password):  # Assuming password is the 5th column (index 4)
            session['user_id'] = user[0]  # Assuming id is the 1st column (index 0)
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
            return redirect(url_for('signin'))

    return render_template('signin.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard', 'danger')
        return redirect(url_for('signin'))

    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    conn.close()

    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('signin'))

if __name__ == '__main__':
    app.run(debug=True)
