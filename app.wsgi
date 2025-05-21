# app.wsgi
import sys
import os

# Make sure Python can find app.py
sys.path.insert(0, '/var/www/store_app')

from app import app as application