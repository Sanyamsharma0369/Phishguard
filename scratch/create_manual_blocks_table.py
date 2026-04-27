import mysql.connector

try:
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="root1234",
        database="phishguard"
    )
    cursor = conn.cursor()
    
    # Create table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS manual_blocks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        domain VARCHAR(500) NOT NULL UNIQUE,
        reason VARCHAR(255) DEFAULT 'Manually blocked',
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    conn.commit()
    print("Manual blocks table created successfully.")
    
except Exception as e:
    print(f"Error: {e}")
finally:
    if 'conn' in locals() and conn.is_connected():
        cursor.close()
        conn.close()
