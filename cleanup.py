"""
Cleanup script — removes bad seeded posts:
- Posts with content under 300 chars (shell/placeholder posts)
- Posts where likes is an integer instead of a list
- Keeps all original posts (the ones from Dec 2025 with proper content)
Run: python cleanup_posts.py
"""

from pymongo import MongoClient
from dotenv import load_dotenv
from bson import ObjectId
import os

load_dotenv()
client = MongoClient(os.environ["MONGO_URI"])
db = client.get_database()

print(f"DB: {db.name}")
print(f"Total posts before cleanup: {db.posts.count_documents({})}")

# Find all posts
all_posts = list(db.posts.find({}, {"_id": 1, "title": 1, "content": 1, "likes": 1, "created_at": 1}))

to_delete = []

for p in all_posts:
    content = str(p.get("content", ""))
    likes   = p.get("likes", [])
    title   = p.get("title", "")[:50]

    reasons = []

    # Bad: content is too short (shell post)
    if len(content) < 300:
        reasons.append(f"content too short ({len(content)} chars)")

    # Bad: likes is an integer, not a list
    if isinstance(likes, (int, float)):
        reasons.append(f"likes is {type(likes).__name__} not list")

    if reasons:
        to_delete.append(p["_id"])
        print(f"  DELETE: {title} — {', '.join(reasons)}")

if not to_delete:
    print("No bad posts found — DB looks clean.")
else:
    confirm = input(f"\nDelete {len(to_delete)} bad posts? (yes/no): ").strip().lower()
    if confirm == "yes":
        result = db.posts.delete_many({"_id": {"$in": to_delete}})
        print(f"Deleted {result.deleted_count} posts.")
    else:
        print("Aborted — nothing deleted.")

print(f"\nTotal posts after cleanup: {db.posts.count_documents({})}")