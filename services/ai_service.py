import os
import requests
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# Step-3.5-Flash Configuration (via NVIDIA)
AI_API_KEY = os.environ.get("AI_API_KEY")
AI_BASE_URL = "https://integrate.api.nvidia.com/v1"
AI_MODEL = "stepfun-ai/step-3.5-flash"

# Tavily Configuration
TAVILY_API_KEY = os.environ.get("TAVILY_API_KEY")

if not AI_API_KEY:
    print("WARNING: AI_API_KEY not found in environment.", flush=True)
if not TAVILY_API_KEY:
    print("WARNING: TAVILY_API_KEY not found in environment.", flush=True)

client = OpenAI(
    base_url=AI_BASE_URL,
    api_key=AI_API_KEY or "missing"
)

def summarize_text(text):
    """Generates a concise summary of the provided text."""
    if not text:
        return "No content to summarize."
    
    # Simple chunking if text is too long (Step-3.5-Flash has 16k tokens, but good to be safe)
    # For this blog, we'll just take the first 4000 words if it's huge.
    words = text.split()
    if len(words) > 4000:
        text = " ".join(words[:4000])

    try:
        completion = client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {"role": "system", "content": "You are a helpful assistant that summarizes blog articles concisely."},
                {"role": "user", "content": f"Please provide a concise summary of the following blog article:\n\n{text}"}
            ],
            temperature=0.7,
            max_tokens=500
        )
        return completion.choices[0].message.content
    except Exception as e:
        print(f"Error in summarize_text: {e}")
        return "Failed to generate summary."

def answer_question(context, question):
    """Answers a question based on the provided context (blog content)."""
    if not context or not question:
        return "I need both context and a question to provide an answer."

    try:
        completion = client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {"role": "system", "content": "You are a helpful assistant. Answer the user's question based ONLY on the provided blog content. If the answer is not in the content, say you don't know based on this article."},
                {"role": "user", "content": f"Context:\n{context}\n\nQuestion: {question}"}
            ],
            temperature=0.7,
            max_tokens=500
        )
        return completion.choices[0].message.content
    except Exception as e:
        print(f"Error in answer_question: {e}")
        return "Failed to get an answer from AI."

def research_topic(topic):
    """Uses Tavily to search the web and the LLM to summarize findings."""
    if not TAVILY_API_KEY:
        return {"error": "Tavily API key not configured."}

    try:
        # 1. Search Tavily
        tavily_url = "https://api.tavily.com/search"
        payload = {
            "api_key": TAVILY_API_KEY,
            "query": topic,
            "search_depth": "basic",
            "max_results": 5
        }
        response = requests.post(tavily_url, json=payload)
        search_results = response.json().get("results", [])

        if not search_results:
            return {"summary": "No research results found.", "sources": []}

        # 2. Prepare context for LLM
        sources_text = ""
        sources_list = []
        for result in search_results:
            sources_text += f"Snippet from {result['url']}: {result['content']}\n\n"
            sources_list.append({"title": result['title'], "url": result['url']})

        # 3. Summarize with LLM
        completion = client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {"role": "system", "content": "You are an AI research assistant. Summarize the research findings concisely for a writer."},
                {"role": "user", "content": f"Topic: {topic}\n\nSearch Results:\n{sources_text}\n\nPlease summarize these findings."}
            ],
            temperature=0.7,
            max_tokens=800
        )
        
        return {
            "summary": completion.choices[0].message.content,
            "sources": sources_list
        }
    except Exception as e:
        print(f"Error in research_topic: {e}")
        return {"error": "Research failed."}

def get_related_posts(current_post, all_posts_list, limit=3):
    """
    Suggests related posts based on tag overlap and title similarity.
    Keeping it lightweight without embeddings.
    """
    if not current_post:
        return []
    
    related = []
    current_tags = set(current_post.get('tags', []))
    current_title_words = set(re.findall(r'\w+', current_post.get('title', '').lower()))

    for post in all_posts_list:
        if str(post['_id']) == str(current_post['_id']):
            continue
        
        # Calculate score
        tag_overlap = len(current_tags.intersection(set(post.get('tags', []))))
        title_overlap = len(current_title_words.intersection(set(re.findall(r'\w+', post.get('title', '').lower()))))
        
        score = (tag_overlap * 2) + title_overlap
        
        if score > 0:
            post['relevance_score'] = score
            related.append(post)
    
    # Sort by relevance score, then by date
    related.sort(key=lambda x: (x['relevance_score'], x.get('created_at', datetime.min)), reverse=True)
    
    return related[:limit]

import re
from datetime import datetime
