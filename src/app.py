"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import hashlib
import re
import os
from pathlib import Path
import sqlite3

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

DB_PATH = os.path.join(current_dir, "app.db")

DEFAULT_ACTIVITIES = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""CREATE TABLE IF NOT EXISTS activities (
        name TEXT PRIMARY KEY,
        description TEXT,
        schedule TEXT,
        max_participants INTEGER
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS participants (
        activity_name TEXT,
        email TEXT,
        PRIMARY KEY(activity_name,email),
        FOREIGN KEY(activity_name) REFERENCES activities(name) ON DELETE CASCADE
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        full_name TEXT,
        password_hash TEXT
    )""")

    for name, act in DEFAULT_ACTIVITIES.items():
        cur.execute(
            "INSERT OR IGNORE INTO activities (name, description, schedule, max_participants) VALUES (?, ?, ?, ?)",
            (name, act["description"], act["schedule"], act["max_participants"])
        )
        for participant in act["participants"]:
            cur.execute(
                "INSERT OR IGNORE INTO participants (activity_name, email) VALUES (?, ?)",
                (name, participant)
            )

    conn.commit()
    conn.close()


class SignupRequest(BaseModel):
    email: str
    full_name: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def is_password_valid(password: str) -> bool:
    # at least 8 chars, 1 upper, 1 lower, 1 digit, and 1 special char
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[^A-Za-z0-9]", password):
        return False
    return True


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.post("/auth/signup")
def auth_signup(payload: SignupRequest):
    conn = get_db_connection()
    cur = conn.cursor()

    existing = cur.execute("SELECT 1 FROM users WHERE email = ?", (payload.email,)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered")

    if not is_password_valid(payload.password):
        conn.close()
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters and include uppercase, lowercase, digit, and special character")

    password_hash = hash_password(payload.password)
    cur.execute("INSERT INTO users (email, full_name, password_hash) VALUES (?, ?, ?)",
                (payload.email, payload.full_name, password_hash))
    conn.commit()
    conn.close()

    return {"message": "Signup successful"}


@app.post("/auth/login")
def auth_login(payload: LoginRequest):
    conn = get_db_connection()
    cur = conn.cursor()

    user = cur.execute("SELECT password_hash FROM users WHERE email = ?", (payload.email,)).fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    if hash_password(payload.password) != user["password_hash"]:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid password")

    conn.close()
    return {"message": "Login successful"}


@app.post("/auth/change-password")
def auth_change_password(payload: LoginRequest, new_password: str):
    conn = get_db_connection()
    cur = conn.cursor()

    user = cur.execute("SELECT password_hash FROM users WHERE email = ?", (payload.email,)).fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    if hash_password(payload.password) != user["password_hash"]:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid current password")

    if not is_password_valid(new_password):
        conn.close()
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters and include uppercase, lowercase, digit, and special character")

    cur.execute("UPDATE users SET password_hash = ? WHERE email = ?", (hash_password(new_password), payload.email))
    conn.commit()
    conn.close()

    return {"message": "Password changed successfully"}


@app.get("/activities")
def get_activities():
    conn = get_db_connection()
    cur = conn.cursor()

    activities_data = {}
    activity_rows = cur.execute("SELECT * FROM activities").fetchall()

    for row in activity_rows:
        participants = [p[0] for p in cur.execute("SELECT email FROM participants WHERE activity_name = ?", (row["name"],)).fetchall()]
        activities_data[row["name"]] = {
            "description": row["description"],
            "schedule": row["schedule"],
            "max_participants": row["max_participants"],
            "participants": participants
        }

    conn.close()
    return activities_data


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(activity_name: str, email: str):
    conn = get_db_connection()
    cur = conn.cursor()

    activity = cur.execute("SELECT * FROM activities WHERE name = ?", (activity_name,)).fetchone()
    if not activity:
        conn.close()
        raise HTTPException(status_code=404, detail="Activity not found")

    existing = cur.execute("SELECT 1 FROM participants WHERE activity_name = ? AND email = ?", (activity_name, email)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Student is already signed up")

    count = cur.execute("SELECT COUNT(*) FROM participants WHERE activity_name = ?", (activity_name,)).fetchone()[0]
    if count >= activity["max_participants"]:
        conn.close()
        raise HTTPException(status_code=400, detail="Activity is full")

    cur.execute("INSERT INTO participants (activity_name, email) VALUES (?, ?)", (activity_name, email))
    conn.commit()
    conn.close()

    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(activity_name: str, email: str):
    conn = get_db_connection()
    cur = conn.cursor()

    activity = cur.execute("SELECT * FROM activities WHERE name = ?", (activity_name,)).fetchone()
    if not activity:
        conn.close()
        raise HTTPException(status_code=404, detail="Activity not found")

    existing = cur.execute("SELECT 1 FROM participants WHERE activity_name = ? AND email = ?", (activity_name, email)).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Student is not signed up for this activity")

    cur.execute("DELETE FROM participants WHERE activity_name = ? AND email = ?", (activity_name, email))
    conn.commit()
    conn.close()

    return {"message": f"Unregistered {email} from {activity_name}"}
