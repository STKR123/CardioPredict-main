from app import app
from waitress import serve
import os

# Get the port assigned by Render, default to 5000 if not set
port = int(os.environ.get("PORT", 5000))

serve(app, host="0.0.0.0", port=port)