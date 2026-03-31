"""
Replicates the exact query from app.py index route.
Run: python simulate_index.py
"""
from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()
db = MongoClient(os.environ["MONGO_URI"]).get_database()

query = {"is_draft": {"$ne": True}}
per_page = 5

print(f"Total posts matching query: {db.posts.count_documents(query)}")
print()

for page in [1, 2, 3]:
    skip = (page - 1) * per_page
    posts = list(
        db.posts.find(query, {"title":1,"author":1,"created_at":1})
        .sort("created_at", -1)
        .skip(skip)
        .limit(per_page)
    )
    print(f"=== PAGE {page} (skip={skip}) ===")
    for p in posts:
        print(f"  {str(p.get('created_at','?'))[:19]} | {p.get('author','?'):14} | {p.get('title','?')[:45]}")
    print()