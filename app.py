# === cleaned app.py ===
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from flask_dance.consumer.storage.session import SessionStorage

from flask_dance.consumer import oauth_authorized
from flask import session
from flask_login import login_user

import pandas as pd
import joblib
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = "siddhartha-super-secure-secret-key"  
app.config['SESSION_COOKIE_SECURE'] = False  # Only for localhost
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
app.config['SESSION_PERMANENT'] = False

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///health.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False



# === DB & Login Setup ===
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.session_protection = "strong"
login_manager.login_view = 'landing'

# === Google OAuth ===
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
google_bp = make_google_blueprint(
    client_id="386972702841-503gquvkkvi4r2s7kt7pvi2jmlnirj6i.apps.googleusercontent.com",
    client_secret="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",
    redirect_url="/login/google/authorized",
    scope=[
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "openid"
    ],
    storage=SessionStorage()  # ✅ this is key
)
app.register_blueprint(google_bp, url_prefix="/login")

# === Load ML Model and Data ===
model = joblib.load("model.joblib")
all_symptoms = joblib.load("symptoms.joblib")
precaution_df = pd.read_csv("precaution.csv")

recommendations = {
    "Diabetes": "Monitor sugar. Follow diabetic diet. Visit endocrinologist.",
    "Heart attack": "Call emergency. Take aspirin. Go to hospital.",
    "Common Cold": "Rest. Hydrate. Use steam. Visit doctor if needed.",
    "Covid-19": "Isolate. Monitor oxygen. Contact health professional."
}

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True, nullable=True)
    password = db.Column(db.String(150))

class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    symptoms = db.Column(db.String, nullable=False)
    disease = db.Column(db.String, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def landing():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    return render_template("landing.html")

@app.route("/signup", methods=["POST"])
def signup():
    username = request.form["username"]
    email = request.form["email"]
    password = request.form["password"]


    if User.query.filter_by(email=email).first():
        flash("Email already registered!")
        return redirect(url_for("landing"))

    hashed = generate_password_hash(password)
    new_user = User(username=username, email=email, password=hashed)
    db.session.add(new_user)
    db.session.commit()
    flash("Signup successful. Please login.")
    return redirect(url_for("landing"))


@app.route("/login", methods=["POST"])
def login():
    username_or_email = request.form["username"]  # input name from form
    password = request.form["password"]

    # Check by email first, then fallback to username
    user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()

    if user and check_password_hash(user.password, password):
        login_user(user)
        return redirect(url_for("home"))

    flash("Invalid username/email or password.")
    return redirect(url_for("landing"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("landing"))




@app.route("/login/google/authorized")
def google_login():
    if not google.authorized:
        # 🔁 Fix infinite redirect loop by clearing bad OAuth token from session
        token_key = f"{google_bp.name}_oauth_token"
        if token_key in session:
            del session[token_key]
        flash("Google login failed or cancelled.")
        return redirect(url_for("landing"))

    try:
        # ✅ Get user info
        resp = google.get("/oauth2/v2/userinfo")
        if not resp.ok:
            flash("Failed to fetch user info from Google.")
            return redirect(url_for("landing"))

        user_info = resp.json()
        email = user_info.get("email")
        name = user_info.get("name")

        if not email:
            flash("Google account has no email.")
            return redirect(url_for("landing"))

        # ✅ Check or create user
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(username=name, email=email, password="google")
            db.session.add(user)
            db.session.commit()

        login_user(user)
        return redirect(url_for("home"))

    except Exception as e:
        print("[Google Login Error]", e)
        flash("Something went wrong during Google login.")
        return redirect(url_for("landing"))

@app.route("/home")
@login_required
def home():
    return render_template("index.html", symptoms=all_symptoms)

@app.route("/predict", methods=["POST"])
@login_required
def predict():
    selected_symptoms = request.form.getlist("symptoms")
    if not selected_symptoms:
        return jsonify({"error": "Please select symptoms."}), 400
    input_data = [1 if symptom in selected_symptoms else 0 for symptom in all_symptoms]
    disease = model.predict([input_data])[0]
    suggestion = recommendations.get(disease, "Please consult a certified doctor.")
    precautions = get_precautions(disease)
    record = Prediction(user_id=current_user.id, symptoms=", ".join(selected_symptoms), disease=disease)
    db.session.add(record)
    db.session.commit()
    return jsonify({"disease": disease, "suggestion": suggestion, "precautions": precautions})

def get_precautions(disease):
    row = precaution_df[precaution_df['Disease'].str.lower() == disease.lower()]
    if not row.empty:
        return row.iloc[0, 1:].dropna().tolist()
    return ["No specific precautions found. Consult your doctor."]

@app.route("/history")
@login_required
def history():
    records = Prediction.query.filter_by(user_id=current_user.id).order_by(Prediction.timestamp.desc()).all()
    return render_template("history.html", records=records)

# === DB ===
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
