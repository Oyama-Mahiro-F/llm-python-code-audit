"""CWE-89 演示样本:SQL 注入(f-string 拼接,非参数化)。

用于验证 Extract-Mock-Test 流水线:sink 为 cursor.execute,
open_db 为同文件内被直接调用的辅助函数。
"""
import sqlite3

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
