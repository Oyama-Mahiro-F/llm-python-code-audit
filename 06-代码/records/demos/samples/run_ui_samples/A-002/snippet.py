DB_PATH = "app.db"

def open_db():
    conn = sqlite3.connect(DB_PATH)
    return conn

def get_user(username):
    conn = open_db()
    cursor = conn.cursor()
    query = f"SELECT id, email FROM users WHERE name = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()
