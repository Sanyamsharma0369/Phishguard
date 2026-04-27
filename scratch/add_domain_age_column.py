import mysql.connector
from mysql.connector import errorcode

config = {
  'user': 'root',
  'password': 'root1234',
  'host': '127.0.0.1',
  'database': 'phishguard',
}

try:
    cnx = mysql.connector.connect(**config)
    cursor = cnx.cursor()
    
    # Add domain_age column to incidents table
    try:
        print("Adding domain_age column to incidents table...")
        cursor.execute("ALTER TABLE incidents ADD COLUMN domain_age VARCHAR(50) DEFAULT 'Unknown' AFTER action_taken")
        print("Column added successfully.")
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_DUP_COLUMN_NAME:
            print("Column domain_age already exists.")
        else:
            print(f"Error adding column: {err.msg}")

    cnx.commit()
    cursor.close()
    cnx.close()
except mysql.connector.Error as err:
    print(f"Error: {err}")
