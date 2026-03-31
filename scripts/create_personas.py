import os
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

def create_personas():
    client = MongoClient(os.environ.get("MONGO_URI"))
    db = client.get_database()
    users = db.users

    personas = [
        {
            "username": "alice_dev",
            "email": "alice@example.com",
            "password": generate_password_hash("password123"),
            "bio": "Senior Software Architect & AI Researcher. Exploring the intersection of ethics and code.",
            "avatar_url": "https://ui-avatars.com/api/?name=Alice+Dev&background=6366f1&color=fff",
            "joined_at": datetime(2023, 5, 12, tzinfo=timezone.utc)
        },
        {
            "username": "bob_writes",
            "email": "bob@example.com",
            "password": generate_password_hash("password123"),
            "bio": "Philosophy student and digital nomad. Observations on slow living in a fast world.",
            "avatar_url": "https://ui-avatars.com/api/?name=Bob+Writes&background=ec4899&color=fff",
            "joined_at": datetime(2023, 8, 22, tzinfo=timezone.utc)
        },
        {
            "username": "clara_sci",
            "email": "clara@example.com",
            "password": generate_password_hash("password123"),
            "bio": "Science communicator and astrobiology enthusiast. Making complex science accessible.",
            "avatar_url": "https://ui-avatars.com/api/?name=Clara+Sci&background=10b981&color=fff",
            "joined_at": datetime(2024, 1, 5, tzinfo=timezone.utc)
        },
        {
            "username": "dan_fit",
            "email": "dan@example.com",
            "password": generate_password_hash("password123"),
            "bio": "Holistic wellness coach and ultra-marathoner. Focus on longevity and mental clarity.",
            "avatar_url": "https://ui-avatars.com/api/?name=Dan+Fit&background=f59e0b&color=fff",
            "joined_at": datetime(2023, 11, 30, tzinfo=timezone.utc)
        }
    ]

    for p in personas:
        if not users.find_one({"username": p["username"]}):
            users.insert_one(p)
            print(f"Created persona: {p['username']}")
        else:
            print(f"Persona {p['username']} already exists.")

if __name__ == "__main__":
    create_personas()
