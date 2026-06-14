"""
One-off migration: store `read_time` on posts that don't have it yet.

New/edited posts now persist read_time at write time, but pre-existing docs
predate that. This backfills them so list pages never recompute (bleach) on
the request hot path.

Run once:  python scripts/backfill_read_time.py
Safe to re-run (only touches docs missing the field).
"""
import os
import sys
import math
import re
import bleach
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()


def reading_time(html):
    text = bleach.clean(html or "", tags=[], strip=True)
    return math.ceil(len(re.findall(r"\w+", text)) / 200)


def main():
    uri = os.environ.get("MONGO_URI", "mongodb://localhost:27017/blogDB")
    db = MongoClient(uri).get_default_database()
    cursor = db.posts.find({"read_time": {"$exists": False}}, {"content": 1})
    updated = 0
    for post in cursor:
        db.posts.update_one(
            {"_id": post["_id"]},
            {"$set": {"read_time": reading_time(post.get("content", ""))}},
        )
        updated += 1
    print(f"Backfilled read_time on {updated} post(s).")


if __name__ == "__main__":
    main()
