from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()
c = MongoClient(os.environ['MONGO_URI'])
db = c.get_database()

print("=== DB INFO ===")
print("DB name:", db.name)
print("Total posts:", db.posts.count_documents({}))

print("\n=== 5 NEWEST POSTS ===")
newest = list(db.posts.find({}, {'title':1, 'author':1, 'created_at':1, 'likes':1, 'read_time':1}).sort('created_at', -1).limit(5))
for p in newest:
    likes = len(p.get('likes', []))
    rt = p.get('read_time', 'MISSING')
    ca = p.get('created_at', 'MISSING')
    title = p.get('title', '?')[:50]
    author = p.get('author', '?')
    print(f"  [{author}] {title}")
    print(f"    created_at={ca} | likes={likes} | read_time={rt}")

print("\n=== 5 OLDEST POSTS ===")
oldest = list(db.posts.find({}, {'title':1, 'author':1, 'created_at':1}).sort('created_at', 1).limit(5))
for p in oldest:
    ca = p.get('created_at', 'MISSING')
    title = p.get('title', '?')[:50]
    author = p.get('author', '?')
    print(f"  [{author}] {title} | created_at={ca}")

print("\n=== FIELD AUDIT (first 3 seeded posts) ===")
sample = list(db.posts.find({'author': {'$in': ['alice_dev','bob_travels','sarah_ai','david_design']}}).limit(3))
for p in sample:
    print(f"\n  Title: {p.get('title','?')[:50]}")
    print(f"  Keys present: {list(p.keys())}")
    print(f"  created_at type: {type(p.get('created_at')).__name__}")
    print(f"  likes type: {type(p.get('likes')).__name__}")
    print(f"  content length: {len(str(p.get('content','')))} chars")