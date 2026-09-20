from waitress import serve

from app import create_app

serve(create_app(), listen="0.0.0.0:8080")
