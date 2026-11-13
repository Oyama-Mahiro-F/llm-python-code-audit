"""CWE-89 安全对照样本:参数化查询,预期 SAST 不告警或验证判 FP。"""
import sqlite3

DB_PATH = "app.db"


def open_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


def get_user_safe(username):
    conn = open_db()
    cursor = conn.cursor()
    query = "SELECT id, email FROM users WHERE name = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()
