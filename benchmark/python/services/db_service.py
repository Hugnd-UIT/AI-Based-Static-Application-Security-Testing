import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # SQL Injection [CWE-89]
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    conn.close()
