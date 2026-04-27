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
    CREATE TABLE IF NOT EXISTS whitelist (
        id INT AUTO_INCREMENT PRIMARY KEY,
        domain VARCHAR(500) NOT NULL UNIQUE,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reason VARCHAR(255) DEFAULT 'Manual whitelist'
    )
    """)
    
    # Seed data
    domains = [
        ('google.com', 'Trusted - Google'),
        ('gmail.com', 'Trusted - Gmail'),
        ('instagram.com', 'Trusted - Instagram'),
        ('facebook.com', 'Trusted - Facebook'),
        ('microsoft.com', 'Trusted - Microsoft'),
        ('github.com', 'Trusted - GitHub'),
        ('youtube.com', 'Trusted - YouTube')
    ]
    
    cursor.executemany("INSERT IGNORE INTO whitelist (domain, reason) VALUES (%s, %s)", domains)
    
    conn.commit()
    print("Whitelist table created and seeded successfully.")
    
except Exception as e:
    print(f"Error: {e}")
finally:
    if 'conn' in locals() and conn.is_connected():
        cursor.close()
        conn.close()
