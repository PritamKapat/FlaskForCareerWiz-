import os
from datetime import datetime, timedelta  
import random
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from flask_mail import Mail, Message
import joblib
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables from .env
load_dotenv()

# ---------- Config ----------
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "test")
CA=os.getenv("CA", "test")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", None)
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")  # set specific origins in production
ACCESS_TOKEN_EXPIRES_HOURS = int(os.getenv("ACCESS_TOKEN_EXPIRES_HOURS", "6"))

MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")

if not JWT_SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY not set in environment (.env)")
if not MAIL_USERNAME or not MAIL_PASSWORD:
    raise RuntimeError("MAIL_USERNAME and MAIL_PASSWORD must be set in environment (.env)")

# ---------- App & Extensions ----------
app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=ACCESS_TOKEN_EXPIRES_HOURS)
app.config["JWT_TOKEN_LOCATION"] = ["headers"]  # Explicitly use headers
app.config["JWT_HEADER_NAME"] = "Authorization"
app.config["JWT_HEADER_TYPE"] = "Bearer"  # Matches frontend format

app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=MAIL_USERNAME,
    MAIL_PASSWORD=MAIL_PASSWORD,
    MAIL_DEFAULT_SENDER=MAIL_USERNAME
)

CORS(app, resources={
    r"/*": {
        "origins": CORS_ORIGINS.split(",") if "," in CORS_ORIGINS else CORS_ORIGINS,
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Authorization", "Content-Type"],
        "expose_headers": ["Authorization"],
        "supports_credentials": False  # Not needed for token-in-header
    }
})

jwt = JWTManager(app)
mail = Mail(app)

# ---------- Load ML model (your existing) ----------
model = joblib.load("career_recommender_model.pkl")
label_encoder = joblib.load("label_encoder.pkl")

# ---------- Helpers ----------
def get_db_connection():
    """
    Creates a new DB connection. Caller must close connection and cursor.
    """
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        autocommit=False,
        ssl_ca=CA
    )

def query_one(query, params=()):
    """
    Utility to execute a SELECT and fetch one row as dict.
    Returns dict or None.
    """
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params)
        row = cursor.fetchone()
        return row
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def execute_insert(query, params=()):
    """
    Utility to execute INSERT/UPDATE/DELETE and commit.
    Returns cursor.lastrowid for inserts.
    """
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params)
        conn.commit()
        return cursor.lastrowid
    except Exception:
        if conn:
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def send_otp_email(to_email, otp):
    msg = Message("Your OTP Code", recipients=[to_email])
    msg.body = f"Your OTP code is {otp}. It will expire in 10 minutes."
    mail.send(msg)

# ---------- Routes ----------
@app.route("/", methods=["GET"])
def home():
    return "✅ Flask server is running. Home page."

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json() or {}
    binary_array = data.get("binary_array")
    if not binary_array or len(binary_array) != len(model.feature_names_in_):
        return jsonify({"error": "Invalid input length"}), 400

    probabilities = model.predict_proba([binary_array])[0]
    top_indices = probabilities.argsort()[-3:][::-1]

    top_careers = []
    for idx in top_indices:
        career = label_encoder.inverse_transform([idx])[0]
        prob = round(float(probabilities[idx]), 4)
        top_careers.append({"career": career, "probability": prob})

    return jsonify({"top_careers": top_careers})

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json() or {}
    # Validate as you do now...

    email = data["email"].strip().lower()
    name = data["name"].strip()
    password = data["password"]
    age = int(data["age"])

    # Check existing email
    existing = query_one("SELECT id FROM users3 WHERE email = %s", (email,))
    if existing:
        return jsonify({"error": "Email already exists"}), 409

    password_hash = generate_password_hash(password)

    # Generate OTP and set expiry to 10 minutes from now
    otp_code = str(random.randint(100000, 999999))
    otp_expiry = datetime.utcnow() + timedelta(minutes=10)

    try:
        insert_query = (
            "INSERT INTO users3 (name, email, password_hash, age, otp_code, otp_expiry, is_verified) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)"
        )
        user_id = execute_insert(insert_query, 
            (name, email, password_hash, age, otp_code, otp_expiry, 0))
        
        # Send OTP email
        send_otp_email(email, otp_code)
        
        return jsonify({
            "message": "User created successfully. Please verify OTP sent to your email.",
            "user": {"id": user_id, "name": name, "email": email}
        }), 201
        
    except Exception as e:
        app.logger.error(f"Error during signup: {str(e)}")
        return jsonify({"error": "Failed to create user"}), 500

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    try:
        data = request.get_json()
        email = data.get("email")
        otp = data.get("otp")

        if not email or not otp:
            return jsonify({"error": "Email and OTP required"}), 400

        user = query_one("SELECT id, email, otp_code, otp_expiry, is_verified FROM users3 WHERE email = %s", (email,))
        if not user:
            return jsonify({"error": "User not found"}), 404

        if user["is_verified"]:
            return jsonify({"error": "User already verified"}), 400

        if user["otp_code"] != otp:
            return jsonify({"error": "Invalid OTP"}), 400

        if user["otp_expiry"] is None or user["otp_expiry"] < datetime.utcnow():
            return jsonify({"error": "OTP expired"}), 400

        # Mark user as verified and clear OTP
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users3 SET is_verified = 1, otp_code = NULL, otp_expiry = NULL WHERE email = %s",
            (email,)
        )
        conn.commit()
        cursor.close()
        conn.close()

        access_token = create_access_token(identity=str(user["id"]))
        return jsonify({
            "message": "OTP verified successfully",
            "access_token": access_token,
            "user": {"id": user["id"], "email": user["email"]}
        }), 200

    except Exception as e:
        app.logger.error(f"Error in /verify-otp: {e}")
        import traceback; traceback.print_exc()
        return jsonify({"error": "Server error"}), 500

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"success": False, "error": "Email and password required"}), 400

    try:
        user = query_one(
            "SELECT id, name, email, password_hash, is_verified FROM users3 WHERE email = %s",
            (email,)
        )
        if not user:
            return jsonify({"success": False, "error": "Invalid credentials"}), 401

        if not user["is_verified"]:
            return jsonify({"success": False, "error": "Email not verified. Please verify before login."}), 401

        if not check_password_hash(user["password_hash"], password):
            return jsonify({"success": False, "error": "Invalid credentials"}), 401

        access_token = create_access_token(identity=str(user["id"]))
        return jsonify({
            "success": True,
            "access_token": access_token,
            "user": {"id": user["id"], "name": user["name"], "email": user["email"]}
        }), 200
    except Error:
        app.logger.exception("Database error during login")
        return jsonify({"success": False, "error": "Database error"}), 500
    except Exception:
        app.logger.exception("Server error during login")
        return jsonify({"success": False, "error": "Server error"}), 500

@app.route("/me", methods=["GET"])
@jwt_required()
def me():
    user_id = int(get_jwt_identity())
    user = query_one("SELECT id, name, email, age FROM users3 WHERE id = %s", (user_id,))
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"user": user}), 200

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    uid = get_jwt_identity()
    return jsonify({"msg": "Token valid", "user_id": uid}), 200

@app.route("/save-careers", methods=["POST"])
@jwt_required()
def save_career():
    user_id = int(get_jwt_identity())
    data = request.get_json() or {}
    career_name = data.get("career_name")

    if not career_name:
        return jsonify({"error": "Career name is required"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO saved_careers (user_id, career_name, saved_at) VALUES (%s, %s, NOW())",
            (user_id, career_name)
        )
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"message": "Career saved successfully"}), 201
    except Error:
        app.logger.exception("Database error while saving career")
        return jsonify({"error": "Database error"}), 500

@app.route("/saved-careers", methods=["GET"])
@jwt_required()
def get_saved_careers():
    user_id = int(get_jwt_identity())
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, career_name, saved_at FROM saved_careers WHERE user_id = %s ORDER BY saved_at DESC",
            (user_id,)
        )
        careers = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({"saved_careers": careers})
    except Error:
        app.logger.exception("Database error while fetching saved careers")
        return jsonify({"error": "Database error"}), 500

@app.route("/saved-careers/<int:career_id>", methods=["DELETE"])
@jwt_required()
def delete_saved_career(career_id):
    user_id = int(get_jwt_identity())
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM saved_careers WHERE id = %s AND user_id = %s",
            (career_id, user_id)
        )
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"message": "Career removed from saved list"})
    except Error:
        app.logger.exception("Database error while deleting saved career")
        return jsonify({"error": "Database error"}), 500

# ---------- Run ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG", "1") == "1")
