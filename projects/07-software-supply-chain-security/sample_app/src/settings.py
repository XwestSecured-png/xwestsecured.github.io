"""Sample app settings: contains INTENTIONALLY planted fake secrets for the scanner demo.
All values are AWS's documented example credentials or random fakes and grant no access."""
import os

DEBUG = False

# BAD: hard-coded cloud credentials (AWS documentation example values)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# BAD: credentials embedded in a connection string
DATABASE_URL = "postgresql://app_user:Tr0ub4dor-and-3@db.internal.example:5432/clients"

# BAD: generic high-entropy API key
PAYMENT_API_KEY = "q8Zt3vR1xN6pL0wK9sJ2mH5dF7gB4cY1"

# GOOD: loaded from the environment / secrets manager at runtime
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# GOOD: obvious placeholders are ignored
EXAMPLE_TOKEN = "changeme"
password = "your_password_here"

# Accepted risk with justification (suppressed): public test key from vendor docs
PUBLIC_TEST_KEY = "pk_test_4eC39HqLyjWDarjtT1zdp7dc"  # nosecret: vendor-published test key
