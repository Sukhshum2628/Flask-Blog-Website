import os
import requests
import traceback
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# Llama 3 8B Instruct Configuration (via NVIDIA)
AI_API_KEY = os.environ.get("AI_API_KEY")
AI_BASE_URL = "https://integrate.api.nvidia.com/v1"
AI_MODEL = "meta/llama-3.1-8b-instruct"

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
    """Generates a concise summary of the provided text with a grounded prompt (no RAG)."""
    if not text:
        return {"summary": ["No content to summarize."], "insight": ""}
    
    system_prompt = (
        "You are a precise content analyst. Your only source of truth is the article text provided below.\n"
        "Do NOT use any outside knowledge. Do NOT reference other articles or the web.\n"
        "If something is not stated in the article, do not include it."
    )

    user_content = (
        "Analyze ONLY the following article and produce:\n"
        "1. A 3–5 point executive summary (each point: one clear sentence, grounded in a specific claim from the article)\n"
        "2. A \"Key Insight\" (1–2 sentences): What is the ONE non-obvious takeaway a reader should remember?\n\n"
        "Article:\n"
        "\"\"\"\n"
        f"{text}\n"
        "\"\"\"\n\n"
        "Return your response in this exact JSON format:\n"
        "{\n"
        "  \"summary_points\": [\"point 1\", \"point 2\", \"point 3\"],\n"
        "  \"key_insight\": \"insight here\"\n"
        "}\n"
        "Return ONLY the JSON. No preamble, no markdown fences."
    )

    try:
        completion = client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            temperature=0.1,
            max_tokens=800
        )
        raw_answer = completion.choices[0].message.content
        
        import json
        json_match = re.search(r'\{.*\}', raw_answer, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            return {
                "summary": data.get("summary_points", []),
                "insight": data.get("key_insight", ""),
                "sources": [], 
                "internet_sources": [],
                "citation_mapping": {}
            }
        
        return {
            "summary": [raw_answer.strip()],
            "insight": "",
            "sources": [],
            "internet_sources": [],
            "citation_mapping": {}
        }
    except Exception as e:
        print(f"Error in summarize_text: {e}")
        return {
            "summary": ["Failed to generate summary."], 
            "insight": str(e), 
            "sources": [], 
            "internet_sources": [],
            "citation_mapping": {}
        }
    except Exception as e:
        print(f"Error in summarize_text: {e}")
        print(traceback.format_exc())
        return {
            "summary": ["Failed to generate summary."], 
            "insight": "An error occurred.", 
            "sources": [], 
            "internet_sources": [],
            "citation_mapping": {}
        }

def _parse_llm_response(text, fallback_context=None):
    """Safely extracts summary points and insight from raw LLM text with contextual fallback."""
    summary_points = []
    insight = ""
    
    # Check for genuinely empty completion
    if not text or not text.strip():
        if fallback_context:
            fallback_text = fallback_context[:250].strip() + ("..." if len(fallback_context) > 250 else "")
            return [f"Summary generated from context: {fallback_text}"], "The AI model returned an empty response, but here is the blog's introductory context."
        return ["No response generated."], "The model returned an empty response."
        
    lines = [line.strip() for line in text.split('\n') if line.strip()]
    current_section = "SUMMARY"
    
    for line in lines:
        if "KEY INSIGHT" in line.upper():
            current_section = "INSIGHT"
            continue
        elif "SUMMARY" in line.upper():
            current_section = "SUMMARY"
            continue
            
        if current_section == "SUMMARY":
            if line.startswith('•') or line.startswith('-'):
                summary_points.append(re.sub(r'^[\•\-]\s*', '', line))
            elif line:
                summary_points.append(line)
        elif current_section == "INSIGHT":
            if line:
                insight += line + " "
                
    # If the LLM completely ignored formatting, use the raw text as the summary
    if not summary_points and not insight:
        summary_points = [text.strip()]
        insight = "Insight derived from raw summary: " + (text.strip()[:100] + "...")
    elif not summary_points:
        summary_points = [text.strip()]
    elif not insight:
        if summary_points:
            insight = f"Key takeaway: {summary_points[-1]}"
        else:
            insight = "Focus on the facts presented in the context."
            
    # Artificially construct bullets if the summary is just one long paragraph
    if len(summary_points) == 1 and len(summary_points[0]) > 100:
        sentences = re.split(r'(?<=[.!?])\s+', summary_points[0])
        bullets = [s.strip() for s in sentences if len(s.strip()) > 10]
        if len(bullets) >= 2:
            summary_points = bullets
        
    return summary_points, insight.strip()

def chunk_text(text):
    """Splits text into paragraphs and returns a list of chunks."""
    # Split by newlines (paragraphs)
    paragraphs = [p.strip() for p in text.split('\n') if p.strip()]
    return paragraphs

def _get_jaccard_similarity(str1, str2):
    """Calculates word overlap similarity between two strings."""
    a = set(re.findall(r'\w+', str1.lower()))
    b = set(re.findall(r'\w+', str2.lower()))
    if not a or not b:
        return 0.0
    intersection = a.intersection(b)
    union = a.union(b)
    return len(intersection) / len(union)

def _map_citations_to_text(llm_response, chunks):
    """Maps LLM sentences back to original chunks to append reliable exact citations (normalized 1, 2, 3..)."""
    if not llm_response:
        return "", [], {}
    if not chunks:
        return llm_response, [], {}

    lines = llm_response.split('\n')
    mapped_lines = []
    
    # mapping actual chunk indices to sequential display numbers
    # tracking order they appear in
    actual_to_display = {}
    display_to_actual = {} # frontend format {"1": 15}
    current_display_num = 1
    
    # We map list items or Insight sentences
    for line in lines:
        if line.startswith('•') or (len(line.strip()) > 20 and not line.startswith('###')):
            best_match_idx = -1
            best_score = 0
            # Test this sentence against all original chunks
            for i, chunk in enumerate(chunks):
                score = _get_jaccard_similarity(line, chunk)
                if score > best_score:
                    best_score = score
                    best_match_idx = i
            
            # If there's a reasonable overlap, cite it
            if best_score > 0.1 and best_match_idx != -1:
                chunk_num = best_match_idx + 1 # 1-indexed (actual)
                
                if chunk_num not in actual_to_display:
                    actual_to_display[chunk_num] = current_display_num
                    display_to_actual[str(current_display_num)] = chunk_num
                    current_display_num += 1
                
                display_num = actual_to_display[chunk_num]
                
                # Avoid double-citing if it's already at the end of the line somehow
                if not line.endswith(f"[{display_num}]"):
                    line = f"{line.strip()} [{display_num}]"
        
        mapped_lines.append(line)

    display_citations = sorted([int(k) for k in display_to_actual.keys()])
    return "\n".join(mapped_lines), display_citations, display_to_actual

def answer_question(context, question):
    """Answers a question with grounded citations from the blog content."""
    if not context or not question:
        return "I need both context and a question to provide an answer."

    print(f"AI RESEARCH: Processing question '{question}'", flush=True)

    # 1. Chunk the blog context for grounded citations
    context_chunks = chunk_text(context)
    
    import string
    alphabet = string.ascii_uppercase
    labeled_chunks = []
    for i, c in enumerate(context_chunks):
        label = alphabet[i % 26] if i < 26 else f"{alphabet[(i//26)-1]}{alphabet[i%26]}"
        labeled_chunks.append(f"Chunk {label}:\n{c}")
    chunked_context_str = "\n\n".join(labeled_chunks)
    
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
                "query": f"{question} based on {context[:100]}",
                "search_depth": "basic",
                "max_results": 3
            }
            response = requests.post(tavily_url, json=payload, timeout=10)
            search_results = response.json().get("results", [])
            for result in search_results:
                if result.get("url"):
                    sources_list.append({"title": result.get("title", "Source"), "url": result["url"]})
        except Exception as e:
            print(f"AI ERROR (Tavily): {e}", flush=True)

    has_internet_sources = len(sources_list)

    # 2. Prepare the LLM prompt
    system_prompt = (
        "You are a helpful assistant.\n"
        "Read the blog content and generate a meaningful answer to the user's question.\n"
        "Format your answer with exactly 3-5 concise bullet points. Avoid long paragraphs.\n"
        "Provide one KEY INSIGHT (1-2 sentences max) that interprets the broader meaning, rather than simply repeating the summary.\n"
        "Do NOT return 'No response generated'."
    )

    user_content = f"--- BLOG ARTICLE SECTIONS ---\n{chunked_context_str}\n\n"
    user_content += f"USER QUESTION: {question}"

    raw_answer = None
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content}
    ]

    try:
        for attempt in range(2):
            completion = client.chat.completions.create(
                model=AI_MODEL,
                messages=messages,
                temperature=0.7,
                max_tokens=1024
            )
            raw_answer = completion.choices[0].message.content
            
            if raw_answer and "No response generated" not in raw_answer.strip():
                break
                
            print(f"LLM failed on attempt {attempt+1}. Retrying...", flush=True)
            messages[0] = {"role": "system", "content": "Answer the question short and clearly. Do not refuse."}
            
        if not raw_answer or "No response generated" in raw_answer:
            fallback_text = context_chunks[0][:150].strip() + ("..." if len(context_chunks[0]) > 150 else "")
            raw_answer = f"### SUMMARY\n• Answer based on introduction: {fallback_text}\n\n### KEY INSIGHT\nAutomated fallback."

        print("RAW LLM RESPONSE:", raw_answer, flush=True)

        # Strip any rogue citations if the LLM hallucinated them despite the prompt
        raw_answer = re.sub(r'\[\d+(-\d+)?\]', '', raw_answer)
        
        # Map sentences to citations safely
        raw_answer_cited, display_citations, citation_mapping = _map_citations_to_text(raw_answer, context_chunks)

        parsed_summary, parsed_insight = _parse_llm_response(raw_answer_cited, fallback_context=context)
        
        # Deduplicate internet sources based on URL
        unique_net_sources = []
        seen_urls = set()
        for src in sources_list:
            if src['url'] not in seen_urls:
                unique_net_sources.append(src)
                seen_urls.add(src['url'])
        
        if not context_chunks:
            return {
                "summary": parsed_summary,
                "insight": parsed_insight,
                "sources": [],
                "internet_sources": unique_net_sources,
                "citation_mapping": {}
            }
        
        sources_data = []
        for display_num in display_citations:
            actual_num = citation_mapping[str(display_num)]
            excerpt = context_chunks[actual_num-1][:100].strip() + ("..." if len(context_chunks[actual_num-1]) > 100 else "")
            sources_data.append({
                "display_id": display_num,
                "text": excerpt,
                "internal_id": actual_num
            })
        
        return {
            "summary": parsed_summary,
            "insight": parsed_insight,
            "sources": sources_data,
            "internet_sources": unique_net_sources,
            "citation_mapping": citation_mapping
        }
    except Exception as e:
        print(f"AI ERROR (LLM): {e}", flush=True)
        print(traceback.format_exc(), flush=True)
        
        # Graceful fallback that preserves structure
        return {
            "summary": ["Failed to generate answer."],
            "insight": "An error occurred. Please try again.",
            "sources": [],
            "internet_sources": [],
            "citation_mapping": {}
        }

def research_topic(topic, draft_context=""):
    """Extracts specific 'writing ammunition' from web research results."""
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
        response = requests.post(tavily_url, json=payload, timeout=10)
        search_results = response.json().get("results", [])

        if not search_results:
            return {"ammunition": [], "summary": "No research results found."}

        # 2. Prepare context for LLM
        tavily_results_concatenated = ""
        for result in search_results:
            tavily_results_concatenated += f"Source: {result['url']}\nContent: {result['content']}\n\n"

        # 3. LLM Prompt
        system_prompt = (
            "You are a writing research assistant helping an author who is actively drafting a blog post.\n"
            "Your job is NOT to summarize web articles. Your job is to extract raw material that the author can USE.\n"
            "Think like a journalist pulling quotes and data for a story they are writing."
        )

        user_content = (
            f"The author is writing about: \"{topic}\"\n"
            f"Their current draft context: \"{draft_context[:500]}\"\n\n"
            "Here are web research results:\n"
            "\"\"\"\n"
            f"{tavily_results_concatenated}\n"
            "\"\"\"\n\n"
            "Extract exactly 4–6 \"writing ammunition\" items from these sources.\n"
            "Each item must be:\n"
            "- A specific fact, statistic, named expert opinion, or concrete example\n"
            "- Something that ADDS to the author's argument, not something that repeats the topic generally\n"
            "- Directly usable as a sentence or paragraph in a blog post\n\n"
            "Return ONLY a JSON array in this format:\n"
            "[\n"
            "  {\n"
            "    \"fact\": \"The specific claim or data point\",\n"
            "    \"source\": \"Source name or URL\",\n"
            "    \"suggested_use\": \"One sentence on how the author could work this into their draft\"\n"
            "  }\n"
            "]\n"
            "No preamble. No markdown. JSON only."
        )

        completion = client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            temperature=0.7,
            max_tokens=1024
        )
        
        raw_answer = completion.choices[0].message.content
        
        import json
        json_match = re.search(r'\[.*\]', raw_answer, re.DOTALL)
        if json_match:
            ammunition = json.loads(json_match.group())
            return {"ammunition": ammunition}
            
        return {"error": "Failed to parse writing ammunition."}
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
    """Suggests improvements for a draft using AI."""
    if not draft_text or not draft_text.strip():
        return {"error": "Draft is empty."}
        
    system_prompt = (
        "You are an expert AI writing assistant. Your task is to improve the provided blog draft.\n"
        "Improve grammar, clarity, and structure while preserving the original meaning and tone.\n"
        "Return ONLY the fully improved text. Do not provide commentary."
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
        
        # Strip potential rogue markdown formatting
        if content.startswith("```"):
            content = re.sub(r'^```[a-z]*\n', '', content)
            content = re.sub(r'\n```$', '', content)
            
        return {
            "improved_text": content.strip()
        }
    except Exception as e:
        print(f"Error in improve_draft: {e}", flush=True)
        return {"error": "Failed to improve draft."}

def stream_answer(context, question):
    """Streams a grounded answer to a user question using SSE."""
    if not context or not question:
        yield "data: [ERROR] Context and question required\n\n"
        return

    system_prompt = (
        "You are a helpful assistant. Use the blog content provided to answer the question.\n"
        "Keep it concise and grounded in the text."
    )
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"--- BLOG CONTENT ---\n{context}\n\nUSER QUESTION: {question}"}
    ]

    try:
        response = client.chat.completions.create(
            model=AI_MODEL,
            messages=messages,
            temperature=0.7,
            stream=True
        )
        for chunk in response:
            if chunk.choices[0].delta.content:
                yield f"data: {chunk.choices[0].delta.content}\n\n"
    except Exception as e:
        yield f"data: [ERROR] {str(e)}\n\n"
