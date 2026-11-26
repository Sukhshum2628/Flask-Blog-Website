import os
import requests
import traceback
import httpx
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# LLM & Embedding Configuration (via NVIDIA NIM or compatible OpenAI endpoint)
AI_API_KEY = os.environ.get("AI_API_KEY")
AI_BASE_URL = os.environ.get("AI_BASE_URL", "https://integrate.api.nvidia.com/v1")
AI_MODEL = os.environ.get("AI_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b")
EMBED_MODEL = os.environ.get("EMBED_MODEL", "nvidia/nemotron-3.5-embed-1b")

# Tavily Configuration
TAVILY_API_KEY = os.environ.get("TAVILY_API_KEY")

if not AI_API_KEY:
    print("WARNING: AI_API_KEY not found in environment.", flush=True)
if not TAVILY_API_KEY:
    print("WARNING: TAVILY_API_KEY not found in environment.", flush=True)

AI_TIMEOUT = float(os.environ.get("AI_TIMEOUT", "25.0"))

# Persistent HTTP transport to eliminate per-request TCP/TLS handshake latency
_http_client = httpx.Client(
    timeout=AI_TIMEOUT,
    limits=httpx.Limits(max_keepalive_connections=20, max_connections=50, keepalive_expiry=60.0)
)

client = OpenAI(
    base_url=AI_BASE_URL,
    api_key=AI_API_KEY or "missing",
    timeout=AI_TIMEOUT,
    max_retries=1,
    http_client=_http_client
)

RETRIEVAL_TOP_K = int(os.environ.get("RETRIEVAL_TOP_K", "4"))

def _format_ai_error(e):
    """Returns a clean, actionable user-facing error message from an API exception."""
    err_str = str(e)
    if "403" in err_str or "Forbidden" in err_str or "Authorization failed" in err_str:
        return "AI authorization failed. Please verify that your AI_API_KEY is active and valid in your settings."
    if "401" in err_str or "Unauthorized" in err_str:
        return "AI authentication failed. Invalid API key provided."
    if "410" in err_str or "Gone" in err_str:
        return f"Configured model '{AI_MODEL}' is no longer supported or reached end-of-life. Please update AI_MODEL in your environment settings."
    if "429" in err_str or "rate limit" in err_str.lower():
        return "AI request rate limit reached. Please wait a moment and try again."
    if "503" in err_str or "502" in err_str or "service unavailable" in err_str.lower():
        return "AI service is temporarily unavailable. Please try again shortly."
    return f"AI service error: {err_str[:120]}"

import re
import math
from search.fusion import fuse_rankings
from search.bm25_index import rank_local_chunks_bm25


from concurrent.futures import ThreadPoolExecutor

# ThreadPoolExecutor for concurrent passage embedding requests
_embed_pool = ThreadPoolExecutor(max_workers=4)


def _embed_single(text, input_type):
    """Embeds a single string with specific input_type."""
    resp = client.embeddings.create(
        model=EMBED_MODEL,
        input=[text],
        extra_body={"input_type": input_type, "truncate": "END"},
    )
    return resp.data[0].embedding


def _embed(texts, input_type):
    """
    Embed a list of strings via the NVIDIA endpoint concurrently.
    Uses concurrent single-text calls to prevent NVIDIA NIM asymmetric model batch 500 errors.
    """
    if not texts:
        return []
    if len(texts) == 1:
        return [_embed_single(texts[0], input_type)]
    # Concurrently fetch embeddings across the pool
    return list(_embed_pool.map(lambda t: _embed_single(t, input_type), texts))


def _cosine(a, b):
    """Cosine similarity between two equal-length vectors (pure Python, no numpy)."""
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def retrieve_chunks_semantic(question, chunks, top_k=RETRIEVAL_TOP_K):
    """
    Semantic-only top-k retrieval (Baseline). Embeds the question and every chunk,
    computes cosine similarity, and returns top_k chunks.
    """
    if not chunks:
        return []
    if len(chunks) <= top_k:
        return list(enumerate(chunks))

    try:
        q_vec = _embed([question], input_type="query")[0]
        chunk_vecs = _embed(chunks, input_type="passage")
        scored = [
            (i, _cosine(q_vec, chunk_vecs[i]))
            for i in range(len(chunks))
        ]
        scored.sort(key=lambda x: x[1], reverse=True)
        top_indices = [idx for idx, _score in scored[:top_k]]
        top_indices.sort()
        return [(idx, chunks[idx]) for idx in top_indices]
    except Exception as e:
        print(f"AI WARN (semantic retrieval failed, falling back to order): {e}", flush=True)
        return list(enumerate(chunks[:top_k]))


def retrieve_chunks_bm25(question, chunks, top_k=RETRIEVAL_TOP_K):
    """
    BM25-only top-k retrieval (Sparse baseline).
    Scores local chunks using BM25Okapi and returns the top_k chunks.
    """
    if not chunks:
        return []
    if len(chunks) <= top_k:
        return list(enumerate(chunks))

    sparse_ranked = rank_local_chunks_bm25(question, chunks)
    # sparse_ranked is list of (original_idx, chunk_text, score) sorted descending
    top_bm25 = [idx for (idx, _text, score) in sparse_ranked[:top_k]]
    top_indices = sorted(top_bm25)
    return [(idx, chunks[idx]) for idx in top_indices]


# In-memory cache for per-post chunk index (chunks, embeddings, BM25)
# Keyed by post_id (or post_id + updated_at timestamp)
_POST_CHUNK_CACHE = {}

def invalidate_post_chunk_cache(post_id=None):
    """Invalidates the in-memory chunk embedding/BM25 cache for a specific post or all posts."""
    global _POST_CHUNK_CACHE
    if post_id is not None:
        _POST_CHUNK_CACHE.pop(str(post_id), None)
    else:
        _POST_CHUNK_CACHE.clear()

def prewarm_post_chunk_cache(post_id, content, async_mode=True):
    """
    Chunks post content and pre-computes dense chunk embeddings into _POST_CHUNK_CACHE.
    If async_mode is True, executes in a background thread to prevent adding perceptible
    latency to user-facing publish/edit responses.
    """
    if not post_id or not content:
        return

    def _warm():
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(content, 'html.parser')
            clean_text = soup.get_text()
            chunks = chunk_text(clean_text)
            if not chunks:
                return
            
            # Short posts with <= RETRIEVAL_TOP_K chunks are short-circuited anyway
            if len(chunks) <= RETRIEVAL_TOP_K:
                _POST_CHUNK_CACHE[str(post_id)] = {
                    "chunks": chunks,
                    "chunk_vecs": None
                }
                return

            # Compute and store chunk vectors
            chunk_vecs = _embed(chunks, input_type="passage")
            _POST_CHUNK_CACHE[str(post_id)] = {
                "chunks": chunks,
                "chunk_vecs": chunk_vecs
            }
        except Exception as e:
            print(f"AI WARN (Failed to pre-warm chunk cache for post {post_id}): {e}", flush=True)

    if async_mode:
        _embed_pool.submit(_warm)
    else:
        _warm()

def retrieve_chunks(question, chunks, top_k=RETRIEVAL_TOP_K, post_id=None):
    """
    Hybrid (Dense Semantic + Sparse BM25) retrieval using Reciprocal Rank Fusion (RRF).
    Embeds the question and chunks, scores via BM25 lexical matching, fuses rankings,
    and returns the most relevant chunks as (original_index, chunk_text) pairs.
    Original indices are preserved so citations still point to the true position in the article.

    If post_id is provided, caches chunk embeddings and BM25 structures in memory so
    subsequent questions on the same post do not repeat the chunk embedding network call.

    Graceful fallback: if there are few chunks, or embeddings fail (quota/network),
    falls back to BM25-only or natural order so the pipeline never crashes.
    """
    if not chunks:
        return []

    # Not worth an embedding/fusion round-trip if everything fits anyway.
    if len(chunks) <= top_k:
        return list(enumerate(chunks))

    # Check cache for pre-computed chunk vectors and chunks
    cached_entry = _POST_CHUNK_CACHE.get(str(post_id)) if post_id else None
    if cached_entry and cached_entry.get("chunks") == chunks:
        chunk_vecs = cached_entry.get("chunk_vecs")
    else:
        chunk_vecs = None

    # 1. Lexical retrieval (BM25) over local chunks
    sparse_ranked = rank_local_chunks_bm25(question, chunks)
    sparse_results = [(idx, score) for (idx, _text, score) in sparse_ranked]

    # 2. Dense semantic retrieval via embeddings
    try:
        q_vec = _embed([question], input_type="query")[0]
        if chunk_vecs is None:
            chunk_vecs = _embed(chunks, input_type="passage")
            if post_id:
                _POST_CHUNK_CACHE[str(post_id)] = {
                    "chunks": chunks,
                    "chunk_vecs": chunk_vecs
                }

        dense_results = [
            (i, _cosine(q_vec, chunk_vecs[i]))
            for i in range(len(chunks))
        ]
        dense_results.sort(key=lambda x: x[1], reverse=True)

        # 3. Reciprocal Rank Fusion (RRF) with k=60
        fused = fuse_rankings(dense_results, sparse_results, k=60)
        top_indices = [idx for idx, _score in fused[:top_k]]

        # Keep natural order of appearance in article for reading flow and citation consistency
        top_indices.sort()
        return [(idx, chunks[idx]) for idx in top_indices]

    except Exception as e:
        print(f"AI WARN (dense retrieval failed, falling back to BM25 or order): {e}", flush=True)
        # Fall back to top BM25 matches
        if sparse_results and any(score > 0 for _, score in sparse_results):
            top_bm25 = [idx for idx, score in sparse_results if score > 0][:top_k]
            top_bm25.sort()
            return [(idx, chunks[idx]) for idx in top_bm25]
        return list(enumerate(chunks))


def summarize_text(text):
    """Generates a concise summary of the provided text with a grounded prompt (no RAG)."""
    if not text:
        return {"summary": ["No content to summarize."], "insight": ""}
    
    system_prompt = (
        "You are a precise content analyst. Your only source of truth is the article text provided below.\n"
        "Do NOT use any outside knowledge. Do NOT reference other articles or the web.\n"
        "If something is not stated in the article, do not include it.\n"
        "IMPORTANT: Return ONLY a valid, raw JSON object. Do NOT include any internal thoughts, analysis steps, preamble, explanation, or markdown fences."
    )

    user_content = (
        "Analyze the following article and return pure JSON with keys \"summary_points\" (array of 3-5 strings, each one clear sentence grounded in the article) and \"key_insight\" (one string: non-obvious takeaway):\n\n"
        "Article:\n"
        "\"\"\"\n"
        f"{text}\n"
        "\"\"\"\n\n"
        "Format:\n"
        "{\n"
        "  \"summary_points\": [\"point 1\", \"point 2\", \"point 3\"],\n"
        "  \"key_insight\": \"insight here\"\n"
        "}\n"
        "Output ONLY the JSON object. No other text."
    )

    try:
        completion = client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            temperature=0.1,
            max_tokens=1500
        )
        if not completion.choices:
            return {
                "summary": ["The AI model returned no choices."],
                "insight": "",
                "sources": [],
                "internet_sources": [],
                "citation_mapping": {}
            }
        raw_answer = completion.choices[0].message.content or ""
        
        # 1. Try direct JSON parsing
        import json
        json_match = re.search(r'\{.*\}', raw_answer, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group())
                points = data.get("summary_points", [])
                insight = data.get("key_insight", "")
                if points and isinstance(points, list):
                    return {
                        "summary": points,
                        "insight": insight,
                        "sources": [], 
                        "internet_sources": [],
                        "citation_mapping": {}
                    }
            except Exception:
                pass

        # 2. Strip thinking/reasoning prefixes if present
        clean_text = raw_answer
        if "```json" in clean_text:
            json_block = re.search(r'```json\s*(\{.*?\})\s*```', clean_text, re.DOTALL)
            if json_block:
                try:
                    data = json.loads(json_block.group(1))
                    return {
                        "summary": data.get("summary_points", []),
                        "insight": data.get("key_insight", ""),
                        "sources": [],
                        "internet_sources": [],
                        "citation_mapping": {}
                    }
                except Exception:
                    pass

        # 3. Use _parse_llm_response as robust fallback for non-JSON text
        pts, ins = _parse_llm_response(clean_text, fallback_context=text)
        # Filter out internal thinking process lines if any leaked into points
        cleaned_pts = [p for p in pts if not p.lower().startswith("here's a thinking process") and not p.lower().startswith("1. **analyze")]
        if not cleaned_pts:
            cleaned_pts = pts

        return {
            "summary": cleaned_pts,
            "insight": ins,
            "sources": [],
            "internet_sources": [],
            "citation_mapping": {}
        }
    except Exception as e:
        print(f"Error in summarize_text: {e}", flush=True)
        print(traceback.format_exc(), flush=True)
        user_err = _format_ai_error(e)

        # Smart Extractive Fallback: if LLM call fails, extract key sentences from the text so reader gets a summary
        fallback_bullets = []
        if text:
            # Split into sentences
            raw_sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+', text) if len(s.strip()) > 35]
            # Take up to 4 strong leading sentences across paragraphs
            for sent in raw_sentences[:4]:
                clean_sent = re.sub(r'\s+', ' ', sent).strip()
                if clean_sent:
                    fallback_bullets.append(clean_sent)

        if fallback_bullets:
            return {
                "summary": fallback_bullets,
                "insight": "Key points extracted from article text (AI synthesis temporarily unavailable).",
                "sources": [],
                "internet_sources": [],
                "citation_mapping": {},
                "warning": user_err,
                "is_fallback": True
            }

        return {
            "summary": [f"Unable to generate summary: {user_err}"],
            "insight": "Please check your AI service credentials and model configuration.",
            "sources": [],
            "internet_sources": [],
            "citation_mapping": {},
            "error": user_err
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
    # Note: if the model gave no distinct insight, leave it empty rather than
    # echoing the last bullet. Duplicating a point adds no information and drags
    # down answer-relevancy (the answer looks padded/repetitive).

    # Drop near-duplicate bullets and any "the article does not say..." non-answers
    # that pad the response without addressing the question.
    cleaned = []
    seen = set()
    for p in summary_points:
        norm = re.sub(r'\s+', ' ', p.lower()).strip(' .')
        if not norm or norm in seen:
            continue
        if re.search(r'\b(does not|doesn\'t|not stated|not mentioned|not specif|is missing|no information)\b', norm):
            continue
        seen.add(norm)
        cleaned.append(p)
    if cleaned:
        summary_points = cleaned
            
    # Artificially construct bullets if the summary is just one long paragraph
    if len(summary_points) == 1 and len(summary_points[0]) > 100:
        sentences = re.split(r'(?<=[.!?])\s+', summary_points[0])
        bullets = [s.strip() for s in sentences if len(s.strip()) > 10]
        if len(bullets) >= 2:
            summary_points = bullets
        
    return summary_points, insight.strip()

def chunk_text(text):
    """
    Splits text into chunks on paragraph boundaries (blank lines), NOT on every
    newline. Splitting on single newlines fragments wrapped paragraphs mid-
    sentence, which causes the retriever to grab half a thought and the LLM to
    miss information that lives in the other half.
    """
    if not text:
        return []
    # Split on one-or-more blank lines (a "paragraph break").
    paragraphs = [p.strip() for p in re.split(r'\n\s*\n', text) if p.strip()]
    # Collapse any remaining internal single newlines so each chunk is clean prose.
    paragraphs = [re.sub(r'\s*\n\s*', ' ', p) for p in paragraphs]

    # Fallback: if the text had no blank-line breaks at all (one big blob),
    # fall back to single-newline splitting so we still get multiple chunks.
    if len(paragraphs) <= 1:
        paragraphs = [p.strip() for p in text.split('\n') if p.strip()]
    return paragraphs


def chunk_text_semantic(text, threshold: float = 0.45, min_words: int = 25, max_words: int = 250):
    """
    Splits text into semantically cohesive chunks using sentence-embedding similarity.
    Computes cosine similarity between consecutive sentences; cuts chunk boundary
    when similarity drops below threshold or max_words is exceeded.
    """
    if not text or not text.strip():
        return []

    # Clean multi-newlines and format
    clean = re.sub(r'\r\n', '\n', text.strip())
    # Split into candidate sentences
    raw_sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+', clean) if s.strip()]
    if not raw_sentences:
        return [clean]
    if len(raw_sentences) == 1:
        return raw_sentences

    try:
        # Embed sentences concurrently
        vecs = _embed(raw_sentences, input_type="passage")
    except Exception as e:
        print(f"Warn: embedding failed in chunk_text_semantic ({e}), falling back to paragraph chunking", flush=True)
        return chunk_text(text)

    chunks = []
    curr_sentences = [raw_sentences[0]]
    curr_words = len(raw_sentences[0].split())

    for i in range(1, len(raw_sentences)):
        s_next = raw_sentences[i]
        w_next = len(s_next.split())
        sim = _cosine(vecs[i - 1], vecs[i])

        # Decide whether to split:
        # 1. Similarity drops below threshold and buffer already has min_words
        # 2. Or adding next sentence exceeds max_words
        should_split = (sim < threshold and curr_words >= min_words) or (curr_words + w_next > max_words)

        if should_split:
            chunks.append(" ".join(curr_sentences))
            curr_sentences = [s_next]
            curr_words = w_next
        else:
            curr_sentences.append(s_next)
            curr_words += w_next

    if curr_sentences:
        chunks.append(" ".join(curr_sentences))

    return chunks

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

def answer_question(context, question, retriever_fn=None, chunker_fn=None):
    """Answers a question with grounded citations from the blog content."""
    if not context or not question:
        return "I need both context and a question to provide an answer."

    print(f"AI RESEARCH: Processing question '{question}'", flush=True)

    # 1. Chunk the blog, then RETRIEVE only the most relevant chunks for this
    #    question instead of feeding the whole article.
    if retriever_fn is None:
        retriever_fn = retrieve_chunks
    if chunker_fn is None:
        chunker_fn = chunk_text

    all_chunks = chunker_fn(context)
    retrieved = retriever_fn(question, all_chunks)  # [(orig_index, text), ...]
    context_chunks = [c for (_idx, c) in retrieved]

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
        "You are a precise assistant. Answer the question using ONLY the blog sections provided.\n"
        "Every claim in your answer must be directly supported by the text. If the article does "
        "not address the question, respond with exactly one short sentence stating that the content "
        "does not address the question; do NOT add outside knowledge and do NOT provide extra details "
        "about what the source does cover.\n"
        "Do NOT add preamble like 'Here are the points'. Start directly with the answer.\n"
        "Provide a clear, direct answer in as many complete declarative sentences as needed to cover "
        "the relevant facts, with no filler, that explicitly reference the question topic. Do not output "
        "single-word answers or incomplete fragments.\n"
        "If multiple points are needed, use concise bullets where each bullet is a full, self-contained sentence. "
        "Each point must explicitly connect back to what the question is asking, not just restate a fact from the text in isolation.\n"
        "Avoid long rambling paragraphs and do not speculate about methodology, causes, or implications "
        "that the article does not state.\n"
        "Then add one KEY INSIGHT (1-2 sentences) that connects the facts above - it must still "
        "be grounded in the article, not external opinion.\n"
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
                temperature=0.2,
                max_tokens=1024,
                extra_body={"reasoning_budget": 0}
            )
            if not completion.choices:
                print("AI ERROR: No choices returned by LLM", flush=True)
                break
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
            "citation_mapping": citation_mapping,
            "retrieved_chunks": context_chunks
        }
    except Exception as e:
        print(f"AI ERROR (LLM): {e}", flush=True)
        print(traceback.format_exc(), flush=True)
        user_err = _format_ai_error(e)
        return {
            "summary": [f"Failed to generate answer: {user_err}"],
            "insight": "Please check your AI service credentials and model configuration.",
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
            "    \"source\": \"The exact Source URL from the results above (must start with https:// or http://)\",\n"
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
        
        if not completion.choices:
             return {"error": "AI model returned an empty response. Please verify the AI model configuration."}
        raw_answer = completion.choices[0].message.content
        
        import json
        json_match = re.search(r'\[.*\]', raw_answer, re.DOTALL)
        if json_match:
            ammunition = json.loads(json_match.group())
            # Ensure every item has a valid absolute HTTP/HTTPS URL
            valid_urls = [r.get('url') for r in search_results if r.get('url')]
            for i, item in enumerate(ammunition):
                src = (item.get('source') or '').strip()
                if not (src.startswith('http://') or src.startswith('https://')):
                    # Fallback to the corresponding Tavily search result URL if LLM returned name or relative text
                    item['source'] = valid_urls[i % len(valid_urls)] if valid_urls else ''
            return {"ammunition": ammunition}
            
        return {"error": "Failed to parse writing ammunition from AI."}
    except Exception as e:
        print(f"Error in research_topic: {e}", flush=True)
        user_err = _format_ai_error(e)
        # Graceful fallback: if LLM fails but Tavily returned search results, provide raw facts from Tavily
        if 'search_results' in locals() and search_results:
            fallback_items = []
            for r in search_results[:4]:
                content_snippet = (r.get('content') or r.get('title') or '').strip()
                if content_snippet:
                    fallback_items.append({
                        "fact": content_snippet[:220] + ("..." if len(content_snippet) > 220 else ""),
                        "source": r.get('url', ''),
                        "suggested_use": "Direct snippet from web search (AI synthesis temporarily unavailable)."
                    })
            if fallback_items:
                return {
                    "ammunition": fallback_items,
                    "warning": user_err
                }
        return {"error": user_err}

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
        
        if not completion.choices:
            return {"error": "AI returned no improved text."}
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
        return {"error": _format_ai_error(e)}

def stream_answer(context, question):
    """Streams a grounded answer to a user question using SSE."""
    if not context or not question:
        yield "data: [ERROR] Context and question required\n\n"
        return

    system_prompt = (
        "You are a precise assistant. Answer the question using ONLY the blog content or sections provided.\n"
        "Every claim in your answer must be directly supported by the text. If the content does not address "
        "the question, respond with exactly one short sentence stating that the content does not address the question; "
        "do NOT add outside knowledge and do NOT provide extra details about what the source does cover.\n"
        "Keep the response concise, clear, and direct with no conversational filler or preambles."
    )
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"--- BLOG CONTENT ---\n{context}\n\nUSER QUESTION: {question}"}
    ]

    try:
        response = client.chat.completions.create(
            model=AI_MODEL,
            messages=messages,
            temperature=0.2,
            stream=True,
            extra_body={"reasoning_budget": 0}
        )
        for chunk in response:
            if chunk.choices and chunk.choices[0].delta.content:
                yield f"data: {chunk.choices[0].delta.content}\n\n"
    except Exception as e:
        err_msg = _format_ai_error(e)
        yield f"data: [ERROR] {err_msg}\n\n"
