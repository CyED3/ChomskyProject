import os

db_host = os.getenv("DB_HOST")
db_password = os.getenv("DB_PASSWORD")
api_key = os.getenv("API_KEY")

def connect():
    print("Connecting to database...")
    return db_host
