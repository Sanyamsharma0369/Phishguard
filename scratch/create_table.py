import mysql.connector

try:
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="root1234"
    )
    cursor = conn.cursor()
    cursor.execute("CREATE DATABASE IF NOT EXISTS phishguard")
    cursor.execute("USE phishguard")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS processed_emails (
            message_id VARCHAR(500) PRIMARY KEY,
            processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    print("Table processed_emails created successfully.")
    cursor.close()
    conn.close()
except mysql.connector.Error as err:
    print(f"Error: {err}")
