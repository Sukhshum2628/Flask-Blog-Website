from pymongo import MongoClient
from dotenv import load_dotenv
import os
from collections import Counter

load_dotenv()
db = MongoClient(os.environ["MONGO_URI"]).get_database()

print(f"Total posts: {db.posts.count_documents({})}")

# Date distribution
posts = list(db.posts.find({}, {"title":1, "created_at":1, "author":1, "is_draft":1, "content":1}))

print("\n=== DATE DISTRIBUTION ===")
months = Counter()
for p in posts:
    ca = p.get("created_at")
    if ca:
        months[ca.strftime("%Y-%m")] += 1
    else:
        months["NO DATE"] += 1
for month, count in sorted(months.items()):
    print(f"  {month}: {count} posts")

print("\n=== DRAFT STATUS ===")
drafts = sum(1 for p in posts if p.get("is_draft") == True)
not_draft = sum(1 for p in posts if p.get("is_draft") == False)
none_val = sum(1 for p in posts if p.get("is_draft") is None)
print(f"  is_draft=True:  {drafts}")
print(f"  is_draft=False: {not_draft}")
print(f"  is_draft=None:  {none_val}")

print("\n=== NEWEST 10 POSTS (what page 1 should show) ===")
newest = list(db.posts.find({}, {"title":1,"author":1,"created_at":1,"is_draft":1}).sort("created_at",-1).limit(10))
for p in newest:
    draft = p.get("is_draft")
    print(f"  {str(p.get('created_at','?'))[:19]} | {p.get('author','?'):12} | draft={draft} | {p.get('title','?')[:45]}")

print("\n=== CONTENT LENGTH SAMPLE (10 newest) ===")
for p in newest:
    clen = len(str(p.get("content", ""))) if "content" in p else "KEY MISSING"
    # refetch with content
    full = db.posts.find_one({"_id": p["_id"]}, {"content":1})
    clen = len(str(full.get("content",""))) if full else 0
    print(f"  {p.get('title','?')[:45]} — {clen} chars")