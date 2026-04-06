import os

# Good practice: env var reference
db_host = os.getenv("DB_HOST")

# Bad practice: hardcoded credential
password = "super_secret_123"

# Leak: printing the credential
print(password)
