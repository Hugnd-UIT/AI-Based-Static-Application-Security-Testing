import sqlite3
import os
import subprocess
import pickle
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Hardcoded credentials
AWS_ACCESS = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    # SQL Injection
    query = "SELECT * FROM users WHERE id = ?"
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(query, (user_id,))
    result = cursor.fetchall()
    return str(result)

@app.route('/ping')
def ping_host():
    ip = request.args.get('ip')
    # Command Injection
    command = ["ping", "-c", "1", ip]
    output = subprocess.run(command, capture_output=True, text=True)
    return output.stdout

@app.route('/hello')
def xss_example():
    name = request.args.get('name')
    # Reflected XSS
    template = "<h1>Hello {{ name }}!</h1>"
    return render_template_string(template, name=name)

@app.route('/read')
def read_file():
    filename = request.args.get('file')
    # Path Traversal
    filepath = os.path.join('/var/www/html', filename)
    with open(filepath, 'r') as f:
        return f.read()

@app.route('/load')
def insecure_deserialization():
    data = request.args.get('data')
    # Insecure Deserialization
    try:
        obj = json.loads(data)
    except json.JSONDecodeError:
        return "Invalid JSON data", 400
    return "Loaded"

if __name__ == '__main__':
    app.run(debug=False)
