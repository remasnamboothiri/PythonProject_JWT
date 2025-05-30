import os

from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-flask-secret'
JWT_SECRET = 'your-jwt-secret'

# Dummy credentials
USER = {
    "username": "user1",
    "password": "pass123"
}

# JWT token validation decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Support both browser session and Postman Authorization header
        if 'Authorization' in request.headers:
            auth = request.headers['Authorization']
            if auth.startswith("Bearer "):
                token = auth.split(" ")[1]
        else:
            token = session.get('token')

        if not token:
            return jsonify({'message': 'Token missing'}), 401

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            current_user = data['user']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/')
def home():
    return redirect(url_for('login'))

# Web login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == USER['username'] and password == USER['password']:
            token = jwt.encode({
                'user': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            }, JWT_SECRET, algorithm="HS256")
            session['token'] = token
            return redirect(url_for('add'))
        return "Invalid credentials!", 401

    return render_template('login.html')

# API login for Postman
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing username or password'}), 400

    if data['username'] == USER['username'] and data['password'] == USER['password']:
        token = jwt.encode({
            'user': data['username'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, JWT_SECRET, algorithm="HS256")
        return jsonify({'token': token})

    return jsonify({'message': 'Invalid credentials'}), 401

# HTML form to add numbers
@app.route('/add', methods=['GET', 'POST'])
@token_required
def add(current_user):
    result = None
    if request.method == 'POST':
        try:
            num1 = float(request.form['num1'])
            num2 = float(request.form['num2'])
            result = num1 + num2
        except ValueError:
            result = "Invalid input."
    return render_template('add.html', result=result, user=current_user)

# API route for Postman to add numbers
@app.route('/api/add', methods=['POST'])
@token_required
def api_add(current_user):
    data = request.get_json()
    try:
        num1 = float(data['num1'])
        num2 = float(data['num2'])
    except (KeyError, ValueError, TypeError):
        return jsonify({'error': 'Invalid input'}), 400

    result = num1 + num2
    return jsonify({
        'user': current_user,
        'num1': num1,
        'num2': num2,
        'result': result
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)

