from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import pickle
import pandas as pd
from dotenv import load_dotenv
import os
from supabase import create_client, Client
import google.generativeai as genai  # Gemini API
from datetime import datetime

# ------------------------- SETUP -------------------------

# Load environment variables
load_dotenv()
print("Gemini API Key Loaded:", os.getenv("GEMINI_API_KEY"))

# ML model
model = pickle.load(open("model.pkl", "rb"))

# Supabase config (read from environment)
SUPABASE_URL = "https://idilkmmvtxoigwzubrlp.supabase.co"
SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImlkaWxrbW12dHhvaWd3enVicmxwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTY1NTk5MTEsImV4cCI6MjA3MjEzNTkxMX0.0_yfVBa9sx6YuYbdFf9sB7gbWR8VkPgZsgLcLUPu0Es"



supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Gemini API Config
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model_gemini = genai.GenerativeModel("gemini-1.5-flash")

# Label mapping
label_mapping = {
    0: "No Disease",
    1: "Angina",
    2: "Arrhythmia",
    3: "Heart Failure",
    4: "Myocardial Infarction",
    5: "General Heart Disease"
}

# ------------------------- HELPERS -------------------------

def current_user():
    """Return minimal user info from session, else None."""
    return session.get("user")

def require_user():
    if "user" not in session:
        return redirect(url_for("login"))
    return None

def get_profile(user_id: str):
    """Fetch profile from users table; returns {} if missing."""
    res = supabase.table("users").select("*").eq("id", user_id).limit(1).execute()
    rows = res.data or []
    return rows[0] if rows else {}

def ensure_profile(user_id: str, email: str, username: str = "User"):
    """Create profile row if not exists (id is auth.users.id)."""
    existing = supabase.table("users").select("id").eq("id", user_id).limit(1).execute()
    if not existing.data:
        supabase.table("users").insert({
            "id": user_id,
            "email": email,
            "username": username
        }).execute()

# ------------------------- ROUTES -------------------------

@app.route('/')
def main():
    return redirect(url_for('welcome'))

@app.route('/welcome')
def welcome():
    return render_template('welcome.html')

@app.route('/home')
def home():
    return render_template('home.html')

# ------------------------- AUTH (Supabase) -------------------------

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        try:
            auth_res = supabase.auth.sign_in_with_password({"email": email, "password": password})
            user = auth_res.user  # gotrue User
            if not user:
                flash("❌ Login failed. Please check your email and password.", "danger")
                return render_template("login.html")
            uid = user.id

            # profile
            prof = get_profile(uid)
            username = prof.get("username", "User") if prof else "User"
            ensure_profile(uid, email, username)

            session['user'] = {
                "uid": uid,
                "username": username,
                "email": email
            }
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for('home'))
        except Exception as e:
            print(f"Supabase Auth Error: {e}")
            return render_template("login.html", error=f"Login failed: {e}")
    return render_template('login.html')

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        username = request.form.get('username', 'User').strip() or "User"
        try:
            # Sign up (may require email confirmation depending on your Supabase auth settings)
            signup = supabase.auth.sign_up({"email": email, "password": password, "options": {"data": {"username": username}}})
            user = signup.user
            if not user:
                # If email confirm is ON, user may be None until they confirm
                flash("Check your email to confirm your account.", "info")
                return redirect(url_for('login'))

            uid = user.id
            ensure_profile(uid, email, username)

            session['user'] = {"uid": uid, "username": username, "email": email}
            flash("Registration successful! Welcome!", "success")
            return redirect(url_for('home'))
        except Exception as e:
            print(f"Supabase SignUp Error: {e}")
            return render_template("register.html", error=f"Registration failed: {e}")
    return render_template('register.html')

@app.route('/logout')
def logout():
    try:
        supabase.auth.sign_out()
    except Exception:
        pass
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('welcome'))

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get('email', '').strip()
        try:
            # Optional: set a redirect URL route in your app that handles resetting
            supabase.auth.reset_password_for_email(email)
            flash("Password reset email sent!", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Error: {e}", "danger")
    return render_template("forgotPassword.html")

# ------------------------- PREDICTION -------------------------

@app.route("/index", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        try:
            input_data = {
                'age': int(request.form['age']),
                'sex': int(request.form['sex']),
                'cp': int(request.form['cp']),
                'trestbps': float(request.form['trestbps']),
                'chol': float(request.form['chol']),
                'fbs': int(request.form['fbs']),
                'restecg': int(request.form['restecg']),
                'thalach': float(request.form['thalach']),
                'exang': int(request.form['exang']),
                'oldpeak': float(request.form['oldpeak']),
                'slope': int(request.form['slope']),
                'ca': float(request.form['ca']),
                'thal': int(request.form['thal'])
            }

            pred = model.predict(pd.DataFrame([input_data]))[0]
            prediction = label_mapping.get(pred, "Unknown")

            # Save to Supabase
            if 'user' in session:
                supabase.table("predictions").insert({
                    "user_id": session['user']['uid'],
                    "data": input_data,
                    "prediction": prediction,
                    "created_at": datetime.utcnow().isoformat() + "Z"
                }).execute()

            # Redirect to result page with query params
            return redirect(url_for('result', prediction=prediction, **{k: str(v) for k, v in input_data.items()}))

        except Exception as e:
            return render_template("index.html", prediction=f"Error: {e}")

    return render_template("index.html")

@app.route("/result")
def result():
    prediction = request.args.get('prediction')
    user_data = {k: request.args.get(k) for k in request.args if k != 'prediction'}

    prompt = f"""
    The user has the following health data:
    {user_data}
    The predicted heart disease type is: {prediction}.
    Explain ONLY the possible medical reason for this prediction based on the data with some emojis for better understanding.
    """

    try:
        ai_response = model_gemini.generate_content(prompt)
        reason = ai_response.text.strip()

        return render_template(
            "result.html",
            prediction_result=prediction,
            prediction_reason=reason,
            user_data=user_data
        )
    except Exception as e:
        return f"Gemini API Error: {e}"

# ------------------------- AI TOOLS -------------------------

@app.route("/get_precautions", methods=["POST"])
def get_precautions():
    data = request.get_json()
    prediction = data.get("prediction", "")
    user_data = data.get("user_data", {})

    prompt = f"""
    The user has the following health data:
    {user_data}
    The diagnosed heart disease type is: {prediction}.
    Provide the TOP 8 most important medical precautions step by step with some emojis for better understanding.
    """

    try:
        ai_response = model_gemini.generate_content(prompt)
        return jsonify({"precautions": ai_response.text.strip()})
    except Exception as e:
        return jsonify({"precautions": f"Error: {e}"})

@app.route("/generate_diet", methods=["POST"])
def generate_diet():
    data = request.get_json()
    reason = data.get("reason", "")
    health_issue = data.get("health_issue", "")

    prompt = f"""
    Based on this reason for heart disease:
    {reason}
    And considering this additional health issue: {health_issue},
    create a detailed, healthy diet plan with some emoji's to get user attraction and impression and better understanding.
    """

    try:
        ai_response = model_gemini.generate_content(prompt)
        return jsonify({"diet_plan": ai_response.text.strip()})
    except Exception as e:
        return jsonify({"diet_plan": f"Error: {e}"})

# ------------------------- MISC PAGES -------------------------

@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect(url_for("login"))
    uid = session["user"]["uid"]
    user_data = get_profile(uid) or {}
    return render_template("profile.html", user=user_data)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route("/todo")
def todo():
    return render_template("todo.html")

@app.route("/chatbot", methods=["GET", "POST"])
def chatbot():
    if request.method == "GET":
        return render_template("chatbot.html")
    elif request.method == "POST":
        data = request.get_json()
        user_message = data.get("message", "")

        if not user_message.strip():
            return jsonify({"reply": "Please type something so I can help you."})

        prompt = f"""
        You are CardioPredict's virtual heart health assistant.
        The user says: {user_message}.
        Answer clearly and helpfully about heart health, precautions, or diet.
        """

        try:
            ai_response = model_gemini.generate_content(prompt)
            return jsonify({"reply": ai_response.text.strip()})
        except Exception as e:
            return jsonify({"reply": f"Error: {e}"})

# ------------------------- RUN -------------------------

if __name__ == "__main__":

    app.run(debug=True)

