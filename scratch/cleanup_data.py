import mysql.connector

try:
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="root1234",
        database="phishguard"
    )
    cursor = conn.cursor()
    
    print("Truncating incidents table...")
    cursor.execute("TRUNCATE TABLE incidents")
    
    print("Truncating processed_emails table...")
    cursor.execute("TRUNCATE TABLE processed_emails")
    
    conn.commit()
    print("Cleanup successful.")
    cursor.close()
    conn.close()
except mysql.connector.Error as err:
    print(f"Error: {err}")
