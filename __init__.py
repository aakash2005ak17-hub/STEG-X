from flask import Flask
from .routes import bp

def create_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024
    app.register_blueprint(bp)
    return app
