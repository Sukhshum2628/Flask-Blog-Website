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

import re

def summarize_text(text):
    """Generates a concise summary of the provided text with citations."""
    if not text:
        return {"summary": "No content to summarize.", "citations": []}
    
    # 1. Chunk the blog context for grounded citations
    context_chunks = chunk_text(text)
    chunked_context_str = "\n".join(context_chunks)
    max_chunk_id = len(context_chunks)

    system_prompt = (
        "You are a professional AI research assistant. Provide a structured, concise response "
        "derived from the provided blog content.\n"
        "Your response MUST strictly follow this exact format and headers:\n\n"
        "### SUMMARY\n"
        "• [Key point 1 with citation [1]]\n"
        "• [Key point 2 with citation [2]]\n\n"
        "### KEY INSIGHT\n"
        "[A short explanation of the main idea]\n\n"
        "### SOURCES (BLOG)\n"
        "[1] [Brief excerpt from section 1]\n"
        "[2] [Brief excerpt from section 2]\n\n"
        "### INTERNET SOURCES\n"
        "No external sources used.\n\n"
        "RULES:\n"
        "- ONLY use the exact provided section numbers (e.g., [1], [2]).\n"
        "- Do NOT invent or guess citations.\n"
        "- Do NOT generate citation ranges (e.g., avoid [4-10]). Cite each individually like [4] [5].\n"
        "- Only cite sections that match the provided text."
    )

    try:
        completion = client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"--- BLOG ARTICLE SECTIONS ---\n{chunked_context_str}"}
            ],
            temperature=0.7,
            max_tokens=800
        )
        
        answer = completion.choices[0].message.content
        
        # Backend Validation: Prevent citation ranges and clean invalid ones
        answer = re.sub(r'\[(\d+)\s*-\s*\d+\]', r'[\1]', answer)  # convert [4-14] to [4]
        
        def replace_invalid_citation(match):
            num = int(match.group(1))
            if 0 < num <= max_chunk_id:
                return f"[{num}]"
            return str(num) # remove brackets so frontend ignores it
            
        answer = re.sub(r'\[(\d+)\]', replace_invalid_citation, answer)
        
        # Extract validated citations
        citations = []
        matches = re.findall(r'\[(\d+)\]', answer)
        for m in matches:
            num = int(m)
            if num not in citations:
                citations.append(num)

        return {
            "summary": answer,
            "citations": citations
        }
    except Exception as e:
        print(f"Error in summarize_text: {e}")
        return {"summary": "Failed to generate summary.", "citations": []}

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
    max_chunk_id = len(context_chunks)

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
                sources_list.append({"title": result['title'], "url": result['url']})
        except Exception as e:
            print(f"AI ERROR (Tavily): {e}", flush=True)

    has_internet_sources = len(sources_list) > 0

    # 2. Prepare the LLM prompt
    system_prompt = (
        "You are a professional AI research assistant. Provide a structured, concise response "
        "derived from the provided blog content and web search findings.\n"
        "Your response MUST strictly follow this exact format and headers:\n\n"
        "### SUMMARY\n"
        "• [Key point 1 with citation [1]]\n"
        "• [Key point 2 with citation [2]]\n\n"
        "### KEY INSIGHT\n"
        "[A short explanation of the main takeaway in simple terms.]\n\n"
        "### SOURCES (BLOG)\n"
        "[1] [Brief excerpt from section 1]\n\n"
        "### INTERNET SOURCES\n"
        + ("*Please list internet sources as clickable Markdown links like `[Title](URL)`*\n" if has_internet_sources else "No external sources used.\n") +
        "\nRULES:\n"
        "- ONLY use the exact provided numbered blog citations (e.g., [1], [2]).\n"
        "- Do NOT invent or guess citations.\n"
        "- Do NOT generate citation ranges (e.g., avoid [4-10]). Cite each individually like [4] [5].\n"
        "- Only display internet sources if they are explicitly provided in the WEB SEARCH FINDINGS.\n"
        "- Keep the total length between 120 and 150 words.\n"
        "- Avoid long paragraphs; keep it crisp."
    )

    user_content = f"--- BLOG ARTICLE SECTIONS ---\n{chunked_context_str}\n\n"
    if search_context:
        user_content += f"--- WEB SEARCH FINDINGS ---\n{search_context}\n\n"
    
    user_content += f"USER QUESTION: {question}"

    try:
        completion = client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            temperature=0.7,
            max_tokens=1024
        )
        
        answer = completion.choices[0].message.content
        
        # Backend Validation: Prevent citation ranges and clean invalid ones
        answer = re.sub(r'\[(\d+)\s*-\s*\d+\]', r'[\1]', answer)
        
        def replace_invalid_citation(match):
            num = int(match.group(1))
            if 0 < num <= max_chunk_id:
                return f"[{num}]"
            return str(num)
            
        answer = re.sub(r'\[(\d+)\]', replace_invalid_citation, answer)
        
        return {
            "answer": answer,
            "sources": sources_list
        }
    except Exception as e:
        print(f"AI ERROR (LLM): {e}", flush=True)
        return {
            "answer": "### SUMMARY\n• Failed to generate answer.\n\n### KEY INSIGHT\nAn error occurred. Please try again.\n\n### INTERNET SOURCES\nNo external sources used.",
            "sources": []
        }

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
import json
from datetime import datetime

def improve_draft(draft_text):
    """Suggests improvements for a draft using AI and returns structured JSON."""
    if not draft_text or not draft_text.strip():
        return {"error": "Draft is empty."}
        
    system_prompt = (
        "You are an expert AI writing assistant. Your task is to improve the provided blog draft.\n"
        "Improve grammar, clarity, and structure while preserving the original meaning and tone.\n"
        "Do NOT output markdown format blocks like ```json. You MUST return your response as a valid, parsable JSON object with the exact following keys:\n"
        "{\n"
        '  "improved_text": "The fully improved text (can include HTML tags if the original had them)",\n'
        '  "changes": ["Changed X to Y for clarity", "Fixed grammar in paragraph 2"],\n'
        '  "insights": ["The tone is engaging.", "Consider adding an example in the second section."],\n'
        '  "sources": []\n'
        "}\n"
        "Respond ONLY with valid JSON."
    )
    
    try:
        completion = client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Here is the draft:\n\n{draft_text}"}
            ],
            temperature=0.7,
            max_tokens=2000
        )
        
        content = completion.choices[0].message.content.strip()
        
        # Clean up potential markdown formatting
        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
            
        result_data = json.loads(content.strip())
        return result_data
    except Exception as e:
        print(f"Error in improve_draft: {e}")
        return {"error": "Failed to improve draft. Ensure your input is valid."}
