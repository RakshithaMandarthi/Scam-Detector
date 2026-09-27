import mysql.connector

try:
    connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="scam_detector"
    )

    if connection.is_connected():
        print("✅ Database connected successfully!")

except mysql.connector.Error as error:
    print("❌ Database connection failed:")
    print(error)

finally:
    if 'connection' in locals() and connection.is_connected():
        connection.close()
        print("Connection closed.")