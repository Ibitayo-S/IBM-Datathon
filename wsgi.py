"""Authenticated WSGI entry point for a server behind an HTTPS reverse proxy."""
from server import create_app
app = create_app()
