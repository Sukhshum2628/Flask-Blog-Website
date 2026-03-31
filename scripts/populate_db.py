import os
import time
import re
import random
import json
from datetime import datetime, timedelta, timezone
from pymongo import MongoClient
from openai import OpenAI
from dotenv import load_dotenv
import bleach

load_dotenv()

# AI Configuration
AI_API_KEY = os.environ.get("AI_API_KEY")
AI_BASE_URL = "https://integrate.api.nvidia.com/v1"
AI_MODEL = "meta/llama-3.1-8b-instruct"

client = OpenAI(base_url=AI_BASE_URL, api_key=AI_API_KEY)

# MongoDB Configuration
mongo_client = MongoClient(os.environ.get("MONGO_URI"))
db = mongo_client.get_database()

# Personas matched to Atlas live DB
AUTHORS = ["alice_dev", "bob_travels", "sarah_ai", "david_design", "Sukhshum"]

# Category Mapping for Unsplash
CATEGORIES = {
    "Technology": ["coding", "ai", "hardware", "cybersecurity", "future"],
    "Philosophy": ["thoughts", "mind", "life", "stoicism"],
    "Science": ["space", "biology", "physics", "earth"],
    "Wellness": ["meditation", "fitness", "nutrition", "mentalhealth"],
    "Culture": ["art", "history", "travel", "food"]
}

TOPIC_BLUEPRINTS = [
    # Tech
    "The Future of Web Development in the Age of Generative AI",
    "Why Rust is the Most Loved Language for Systems Programming",
    "Decentralized Finance: Is it the End of Traditional Banking?",
    "Building Sustainable Software: Reducing the Carbon Footprint of Code",
    "Artificial General Intelligence: A Timeline of Possibility",
    # Science
    "The Search for Life on Exoplanets: What We Know in 2026",
    "Quantum Entanglement Explained: Spooky Action at a Distance",
    "The James Webb Telescope's Most Groundbreaking Discoveries",
    "Bypassing Evolution: The Ethical Dilemma of CRISPR",
    "Neuroscience of Sleep: Why Rest is the Ultimate Performance Hack",
    # Philosophy/Culture
    "The Philosophy of Minimalism: How Less Becomes More",
    "Digital Nomadism: The Sociology of Remote Work in the 20s",
    "The Rise of Hyper-local Communities in a Globalized World",
    "Analyzing the Impact of Social Media on Modern Democracy",
    "The Stoic Guide to Navigating Uncertainty and Change",
    # Wellness
    "Biohacking for Longevity: Practical Steps to Living Longer",
    "The Science of Habit Formation: How to Design Your Day",
    "Mental Health in the Workplace: From Stigma to Strategy",
    "Functional Fitness: Training for the Real World",
    "Plant-Based Nutrition: Science vs Myths"
]

def generate_metadata(topic):
    prompt = (
        f"Generate metadata for a long-form article on: '{topic}'.\n"
        "Return JSON with: 'title', 'subtitle', 'tags' (list).\n"
        "Return ONLY the JSON."
    )
    try:
        completion = client.chat.completions.create(
            model=AI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
            max_tokens=200
        )
        raw = completion.choices[0].message.content
        start, end = raw.find('{'), raw.rfind('}')
        if start != -1 and end != -1:
            return json.loads(raw[start:end+1])
    except: return None

def generate_content(topic, title):
    prompt = (
        f"Write a 1000-word, high-quality, informative article titled '{title}' about '{topic}'.\n"
        "Requirements:\n"
        "- Use professional, 'Medium' style prose.\n"
        "- Include 4-5 detailed subheadings (<h3>).\n"
        "- Use <p>, <ul>, and <blockquote> where appropriate.\n"
        "- Provide actual facts, examples, or in-depth analysis.\n"
        "- Output ONLY the HTML body content (no <html>/<body> tags, no markdown)."
    )
    try:
        completion = client.chat.completions.create(
            model=AI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
            max_tokens=3000
        )
        return completion.choices[0].message.content.strip()
    except: return None

def seed_posts(count=10):
    print(f"Starting to seed {count} posts...")
    
    for i in range(count):
        topic = random.choice(TOPIC_BLUEPRINTS)
        author = random.choice(AUTHORS)
        
        print(f"[{i+1}/{count}] Processing '{topic}' by {author}...")
        
        meta = generate_metadata(topic)
        if not meta: continue
        
        content = generate_content(topic, meta['title'])
        if not content or len(content) < 500: continue
        
        blog_data = {
            "title": meta['title'],
            "subtitle": meta['subtitle'],
            "tags": meta['tags'],
            "content": content,
            "author": author,
            "is_draft": False,
            "created_at": datetime.now(timezone.utc) - timedelta(days=random.randint(0, 30)),
            "updated_at": datetime.now(timezone.utc)
        }
            
        # Add metadata
        category = "Culture" # Default
        for cat, keywords in CATEGORIES.items():
            if any(k.lower() in topic.lower() for k in keywords):
                category = cat
                break
                
        # Random Unsplash Image
        img_keyword = random.choice(CATEGORIES[category])
        blog_data["cover_url"] = f"https://images.unsplash.com/featured/?{img_keyword}"
        
        blog_data["author"] = author
        blog_data["is_draft"] = False
        blog_data["created_at"] = datetime.now(timezone.utc) - timedelta(days=random.randint(0, 30), minutes=random.randint(0, 1440))
        blog_data["updated_at"] = blog_data["created_at"]
        
        # Derived metadata
        clean_text = bleach.clean(blog_data["content"], tags=[], strip=True)
        blog_data["read_time"] = max(1, round(len(clean_text.split()) / 200))
        
        # Meta Fields for UI
        blog_data["intent"] = random.choice(["inform", "reflect", "document", "argue"])
        blog_data["freshness"] = random.choice(["current", "evergreen", "aging"])
        
        # Random reactions for Trending/Recommended
        reaction_types = ["like", "love", "insightful", "funny"]
        blog_data["likes"] = [f"user_{random.randint(1, 50)}" for _ in range(random.randint(5, 100))]
        blog_data["comment_count"] = random.randint(0, 20)
        blog_data["views"] = random.randint(50, 5000)
        
        # Insert
        db.posts.insert_one(blog_data)
        print(f"Successfully inserted: {blog_data['title']}")
        
        # Throttle to respect API limits
        time.sleep(3)

if __name__ == "__main__":
    # Seed 100 posts on Atlas for the final target.
    seed_posts(100)
