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

def chunk_text(text):
    """Splits text into paragraphs and returns a numbered list of chunks."""
    # Split by newlines (paragraphs)
    paragraphs = [p.strip() for p in text.split('\n') if p.strip()]
    chunked = []
    for i, p in enumerate(paragraphs, 1):
        chunked.append(f"[{i}] {p}")
    return chunked

def answer_question(context, question):
    """Answers a question with grounded citations from the blog content."""
    if not context or not question:
        return "I need both context and a question to provide an answer."

    print(f"AI RESEARCH: Processing question '{question}'", flush=True)

    # 1. Chunk the blog context for grounded citations
    context_chunks = chunk_text(context)
    chunked_context_str = "\n".join(context_chunks)

    search_context = ""
    sources_list = []

    # 1. Perform a quick Tavily search for additional context if needed
    if TAVILY_API_KEY:
        try:
            tavily_url = "https://api.tavily.com/search"
            # Limit search for efficiency in chat
            payload = {
                "api_key": TAVILY_API_KEY,
                "query": f"{question} in context of {context[:100]}",
                "search_depth": "basic",
                "max_results": 3
            }
            response = requests.post(tavily_url, json=payload, timeout=5)
            search_results = response.json().get("results", [])
            
            for result in search_results:
                search_context += f"Web Snippet from {result['url']}: {result['content']}\n\n"
                sources_list.append(f"1. [{result['title']}]({result['url']})")
        except Exception as e:
            print(f"AI ERROR (Tavily): {e}", flush=True)

    # 2. Prepare the LLM prompt
    system_prompt = (
        "You are a helpful AI research assistant. Answer the user's question using the provided blog content "
        "(which is divided into numbered sections) and any relevant web search results. "
        "Strictly follow these rules:\n"
        "1. GROUNDING: Use the numbered sections from the blog post [1], [2], etc., to support your answer. "
        "Include the bracketed number immediately after the sentence it supports.\n"
        "2. STRUCTURE: Use the following headers:\n"
        "### Summary\n[Concise answer with bullet points and citations]\n\n"
        "### Additional Context\n[Short explanation with insights from research]\n\n"
        "### Relevant Sources\n[List of source titles with links if available]"
    )

    user_content = f"Blog Post Content (Numbered Sections):\n{chunked_context_str}\n\n"
    if search_context:
        user_content += f"Additional Web Research:\n{search_context}\n\n"
    
    user_content += f"Question: {question}"

    try:
        completion = client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            temperature=0.7,
            max_tokens=1024 # Increased token limit
        )
        
        answer = completion.choices[0].message.content
        
        # Append sources if LLM didn't include them properly
        if search_context and "### Relevant Sources" not in answer:
            answer += "\n\n### Relevant Sources\n" + "\n".join(sources_list)
            
        return answer
    except Exception as e:
        print(f"AI ERROR (LLM): {e}", flush=True)
        return "Failed to get an answer from AI. Please try again later."

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
