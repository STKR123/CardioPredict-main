from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import pickle
import pandas as pd
from dotenv import load_dotenv
import os
from supabase import create_client, Client
import google.generativeai as genai  # Gemini API
from datetime import datetime
import uuid
import sendgrid
from sendgrid.helpers.mail import Mail

# ------------------------- SETUP -------------------------
# Load env
load_dotenv()

# Flask
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Supabase
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_ANON_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ML model
model = pickle.load(open("model.pkl", "rb"))

# Gemini setup
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model_gemini = genai.GenerativeModel("gemini-1.5-flash")

# SendGrid setup
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
FROM_EMAIL = "cardiopredict12@gmail.com"
sg = sendgrid.SendGridAPIClient(SENDGRID_API_KEY)
print("SendGrid API Key:", SENDGRID_API_KEY)


# Labels
label_mapping = {
    0: "No Disease",
    1: "Angina",
    2: "Arrhythmia",
    3: "Heart Failure",
    4: "Myocardial Infarction",
    5: "General Heart Disease"
}

# ------------------------- HELPERS -------------------------
def send_email(to_email, subject, html_content):
    """Send email using SendGrid"""
    message = Mail(from_email=FROM_EMAIL, to_emails=to_email, subject=subject, html_content=html_content)
    try:
        sg.send(message)
        return True
    except Exception as e:
        print("Email error:", e)
        return False

def get_profile(user_id: str):
    res = supabase.table("users").select("*").eq("id", user_id).limit(1).execute()
    return res.data[0] if res.data else {}

def ensure_profile(user_id: str, email: str, username: str = "User"):
    existing = supabase.table("users").select("id").eq("id", user_id).limit(1).execute()
    if not existing.data:
        supabase.table("users").insert({"id": user_id, "email": email, "username": username}).execute()

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

# ---------- AUTH ----------
@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        try:
            auth_res = supabase.auth.sign_in_with_password({"email": email, "password": password})
            user = auth_res.user

            if not user:
                # This usually means invalid credentials
                flash("❌ Invalid email or password.", "danger")
                return render_template("login.html")

            # Check if email is verified
            if not getattr(user, "email_confirmed_at", None):
                flash("⚠️ Email not verified. Please check your inbox.", "warning")
                return render_template("login.html")

            # Successful login
            uid = user.id
            prof = get_profile(uid)
            username = prof.get("username", "User") if prof else "User"
            ensure_profile(uid, email, username)

            session['user'] = {"uid": uid, "username": username, "email": email}
            flash(f"✅ Welcome back, {username}!", "success")
            return redirect(url_for('home'))

        except Exception as e:
            # Here, it’s truly unexpected
            print("Login error:", e)
            flash("❌ Login failed due to an internal error. Please try again later.", "danger")
            return render_template("login.html")

    return render_template('login.html')



@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        username = request.form.get('username', 'User').strip() or "User"
        try:
            signup = supabase.auth.sign_up({"email": email, "password": password})
            user = signup.user
            if user:
                uid = user.id
                ensure_profile(uid, email, username)

                # Send verification email
                verification_link = f"http://localhost:5000/verify/{uid}"
                send_email(
                    email,
                    "Verify your CardioPredict Account",
                    f"<p>Hello {username},</p><p>Click below to verify your account:</p><a href='{verification_link}'>Verify Email</a>"
                )
                flash("✅ Registration successful! Check your inbox to verify your email.", "success")
                return redirect(url_for('login'))
            else:
                flash("❌ Registration failed. Please check your email or try again.", "danger")

        except Exception as e:
            print("Register error:", e)
            flash(f"❌ Registration failed due to an internal error: {e}", "danger")
    return render_template('register.html')


@app.route('/verify/<user_id>')
def verify(user_id):
    flash("✅ Your email has been verified!", "success")
    return redirect(url_for("login"))

# ------------------ FORGOT PASSWORD ------------------
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        try:
            # Sends password reset email via Supabase
            response = supabase.auth.reset_password_for_email(email)
            print("Supabase reset response:", response)  # debug

            flash(
                "Password reset email sent! Check your inbox (or spam folder).",
                "info"
            )
            return redirect(url_for("login"))
        except Exception as e:
            print("Forgot password error:", e)
            flash("Error sending reset email. Make sure the email is registered.", "danger")
    return render_template("forgotPassword.html")


# ------------------ RESET PASSWORD ------------------
@app.route("/reset-password/<access_token>", methods=["GET", "POST"])
def reset_password(access_token):
    """
    Supabase sends a reset link like:
    https://your-app-url/reset-password?access_token=<token>
    Use this token to verify and update password.
    """
    if request.method == "POST":
        new_password = request.form.get("password", "").strip()
        try:
            # Update password using access token from email link
            res = supabase.auth.update_user(
                {"password": new_password}, 
                access_token=access_token
            )
            print("Password reset response:", res)
            flash("Password reset successful! Please log in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            print("Reset password error:", e)
            flash("Failed to reset password. Try again.", "danger")

    return render_template("resetPassword.html", access_token=access_token)



@app.route('/logout')
def logout():
    try:
        supabase.auth.sign_out()
    except Exception:
        pass
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('welcome'))

# ---------- PREDICTION ----------
@app.route("/index", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        try:
            input_data = {k: float(request.form[k]) if k not in ['sex', 'cp', 'fbs', 'restecg', 'exang', 'slope', 'thal']
                          else int(request.form[k]) for k in request.form}
            pred = model.predict(pd.DataFrame([input_data]))[0]
            prediction = label_mapping.get(pred, "Unknown")

            if 'user' in session:
                supabase.table("predictions").insert({
                    "user_id": session['user']['uid'],
                    "data": input_data,
                    "prediction": prediction,
                    "created_at": datetime.utcnow().isoformat() + "Z"
                }).execute()

            return redirect(url_for('result', prediction=prediction, **{k: str(v) for k, v in input_data.items()}))
        except Exception as e:
            return render_template("index.html", prediction=f"Error: {e}")
    return render_template("index.html")

@app.route("/result")
def result():
    prediction = request.args.get('prediction')
    user_data = {k: request.args.get(k) for k in request.args if k != 'prediction'}
    prompt = f"""
    User data: {user_data}
    Predicted disease: {prediction}.
    Explain only possible medical reason with emojis.
    """
    try:
        ai_response = model_gemini.generate_content(prompt)
        return render_template("result.html", prediction_result=prediction, prediction_reason=ai_response.text.strip(), user_data=user_data)
    except Exception as e:
        return f"Gemini API Error: {e}"

# ---------- AI TOOLS ----------
@app.route("/get_precautions", methods=["POST"])
def get_precautions():
    data = request.get_json()
    prediction = data.get("prediction", "")
    user_data = data.get("user_data", {})
    prompt = f"""
    User data: {user_data}
    Disease: {prediction}.
    Provide top 8 precautions with emojis.
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
    Reason: {reason}
    Health issue: {health_issue}
    Give detailed diet plan with emojis.
    """
    try:
        ai_response = model_gemini.generate_content(prompt)
        return jsonify({"diet_plan": ai_response.text.strip()})
    except Exception as e:
        return jsonify({"diet_plan": f"Error: {e}"})

# ---------- PROFILE / CHATBOT / TODO ----------
@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect(url_for("login"))
    uid = session["user"]["uid"]
    return render_template("profile.html", user=get_profile(uid) or {})

@app.route('/about')
def about():
    return render_template('about.html')

reminders_db = {}
@app.route("/todo", methods=["GET", "POST"])
def todo():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))
    user_id = user["uid"]
    reminders_db.setdefault(user_id, [])
    if request.method == "POST":
        task = request.form.get("task")
        time = request.form.get("time")
        if task and time:
            reminder = {"id": str(uuid.uuid4()), "task": task, "time": time,
                        "formatted_time": datetime.strptime(time, "%H:%M").strftime("%I:%M %p")}
            reminders_db[user_id].append(reminder)
        return redirect(url_for("todo"))
    return render_template("todo.html", reminders=reminders_db[user_id])

@app.route("/delete_reminder/<rem_id>", methods=["POST"])
def delete_reminder(rem_id):
    user = session.get("user")
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = user["uid"]
    reminders_db[user_id] = [r for r in reminders_db.get(user_id, []) if r["id"] != rem_id]
    return jsonify({"success": True})

@app.route("/chatbot", methods=["GET", "POST"])
def chatbot():
    if request.method == "GET":
        return render_template("chatbot.html")
    data = request.get_json()
    user_message = data.get("message", "")
    if not user_message.strip():
        return jsonify({"reply": "Please type something."})
    prompt = f"""
    You are CardioPredict's virtual assistant.
    User says: {user_message}.
    Reply with helpful info about heart health, diet, precautions.
    """
    try:
        ai_response = model_gemini.generate_content(prompt)
        return jsonify({"reply": ai_response.text.strip()})
    except Exception as e:
        return jsonify({"reply": f"Error: {e}"})

# ------------------------- RUN -------------------------
if __name__ == "__main__":
    app.run(debug=True)
