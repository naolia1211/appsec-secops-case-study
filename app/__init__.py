from flask import Flask, jsonify, request


def create_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 4096

    @app.get("/health")
    def health():
        return jsonify(status="ok"), 200

    @app.get("/")
    def index():
        return jsonify(service="concung-demo", version="1.0.0")

    @app.get("/api/greeting")
    def greeting():
        name = request.args.get("name", "world").strip()
        if not name or len(name) > 80 or any(ord(c) < 32 for c in name):
            return jsonify(error="name must contain 1-80 characters without control characters"), 400
        return jsonify(message=f"Hello, {name}!")

    return app
