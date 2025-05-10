from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from db import get_db_connection
import os
import re
import functools
import logging

logging.basicConfig(level=logging.ERROR)
app = Flask(__name__)
CORS(app)

app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "super-secret")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
jwt = JWTManager(app)

# Health check route (RECOMMENDED for Render)
@app.route("/", methods=["GET"])
def index():
    return jsonify({"msg": "Flask backend is running"}), 200

# --- Error Handling Decorator ---
def handle_db_errors(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        conn = None
        try:
            conn = get_db_connection()
            return func(conn, *args, **kwargs)
        except Exception as e:
            logging.error(f"Error in {func.__name__}: {e}")
            if conn:
                conn.rollback()
            return jsonify({"msg": f"Internal server error: {str(e)}"}), 500
        finally:
            if conn:
                conn.close()
    return wrapper

# --- Routes ---
@app.route('/signup', methods=['POST'])
@handle_db_errors
def signup(conn):
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"msg": "Missing email or password"}), 400

    if not email.endswith("@goodyear"):
        return jsonify({"msg": "Email must end with @goodyear"}), 400

    if len(password) < 10 or not re.match(r"^[a-zA-Z0-9]*$", password):
        return jsonify({"msg": "Password must be at least 10 characters and alphanumeric only"}), 400

    hashed = generate_password_hash(password)
    username = email.split("@")[0]
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
    if cursor.fetchone():
        return jsonify({"msg": "Email already exists"}), 409

    try:
        cursor.execute(
            "INSERT INTO users (email, password_hash, username, created_at) VALUES (%s, %s, %s, %s)",
            (email, hashed, username, datetime.utcnow())
        )
        conn.commit()
        return jsonify({"msg": "User created successfully"}), 201
    except Exception as e:
        conn.rollback()
        logging.error(f"Signup error: {e}")
        return jsonify({"msg": f"Database error: {str(e)}"}), 500

@app.route('/login', methods=['POST'])
@handle_db_errors
def login(conn):
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    cursor = conn.cursor(dictionary=True)

    if not email or not password:
        return jsonify({"msg": "Missing email or password"}), 400

    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"msg": "Invalid credentials"}), 401

    token = create_access_token(identity=email)
    return jsonify(access_token=token), 200

@app.route('/calculate-child-model', methods=['POST'])
@jwt_required()
@handle_db_errors
def calculate_child_model(conn):
    data = request.get_json()
    model_type = data.get("model")
    input_data = data.get("input")
    owner_email = data.get("email")
    current_user_email = get_jwt_identity()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT id FROM users WHERE email = %s", (current_user_email,))
    user = cursor.fetchone()
    if not user:
        return jsonify({"msg": "User not found"}), 404

    cursor.execute(
        """
        INSERT INTO posts (owner_email, title, type, content, is_public, user_id, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (owner_email, f"{model_type} Calculation", model_type, input_data, True, user['id'], datetime.utcnow()),
    )
    post_id = cursor.lastrowid

    if model_type == "Findings":
        severity = data.get("severity", "Medium")
        impact = data.get("impact", "No impact provided.")

        cursor.execute(
            """
            INSERT INTO findings (post_id, severity, impact, created_at)
            VALUES (%s, %s, %s, %s)
            """,
            (post_id, severity, impact, datetime.utcnow()),
        )

    conn.commit()
    return jsonify({"msg": "Model data saved"}), 201

@app.route('/posts-by-owner', methods=['GET'])
@jwt_required()
@handle_db_errors
def get_posts_by_owner(conn):
    email = request.args.get("email")
    if not email:
        return jsonify({"msg": "Owner email is required"}), 400
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM posts WHERE owner_email = %s", (email,))
    posts = cursor.fetchall()
    return jsonify(posts), 200

@app.route('/public-posts', methods=['GET'])
@handle_db_errors
def get_public_posts(conn):
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM posts WHERE is_public = TRUE")
    posts = cursor.fetchall()
    return jsonify(posts), 200

@app.route('/my-posts', methods=['GET'])
@jwt_required()
@handle_db_errors
def get_my_posts(conn):
    email = get_jwt_identity()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT posts.* FROM posts
        JOIN users ON posts.user_id = users.id
        WHERE users.email = %s
        """,
        (email,),
    )
    posts = cursor.fetchall()
    return jsonify(posts), 200

# --- 🔧 Run with proper host/port for Render ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
