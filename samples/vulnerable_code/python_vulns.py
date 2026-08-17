import sqlite3
import os
from flask import Flask, request

app = Flask(__name__)

# Vulnerability 1: SQL Injection (SQLi)
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    
    # [DATA FLOW] Source (request.args) -> user_id -> query
    # No sanitization applied.
    query = "SELECT * FROM users WHERE id = ?"
    
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
    
        # SINK
        cursor.execute(query, (user_id,))
    result = cursor.fetchall()
    
    return str(result)

# Vulnerability 2: Command Injection (RCE)
@app.route('/ping')
def ping_host():
    ip = request.args.get('ip')
    
    # [DATA FLOW] Source -> ip -> command
    command = "ping -c 1 " + ip
    
    # SINK
    output = subprocess.run(['ping', '-c', '1', ip], capture_output=True, text=True).stdout
    
    return output

if __name__ == '__main__':
    app.run()
