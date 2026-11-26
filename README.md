# FlaskBlog — A Modern "Medium-like" Platform

A performance-optimized, AI-enhanced blogging platform built with Flask and MongoDB, designed for the Render Free Tier.

## 🚀 Features

### 🤖 AI-Native Writing Experience
- **Context-Grounded Summarization**: Bypasses RAG to provide precise, grounded executive summaries and key insights for every post.
- **AI Research Assistant**: Extracts "writing ammunition" (facts, stats, expert opinions) from the live web using Tavily & Llama 3.1 8B.
- **Intelligent Draft Improver**: Offers a visual diff view (Original vs. Improved) to help authors refine their prose.
- **Streaming Q&A**: Real-time SSE streaming for interactive chat with any blog post.

### 🎨 Modern UI/UX (Medium-Inspired)
- **Editorial Reading Experience**: 680px constrained text width, Merriweather serif typography, and a gradient reading progress bar.
- **Feed Card Hierarchy**: Two-column responsive card layout with author metadata and cover thumbnails.
- **Reading List**: AJAX-powered bookmarking system for saving stories for later.
- **Pulse Activity Feed**: Real-time site activity tracking with a subtle pulse animation.

### ⚡ Optimized for Render Free Tier
- **Non-blocking AI**: Offloads heavy LLM & Web Search tasks to background threads using `ThreadPoolExecutor`.
- **Downtime Protection**: Built-in `/ping` route and health checks to maintain up-time.
- **Smart Caching**: MongoDB-backed caching for AI summaries to reduce API costs and latency.
- **Resource Hygiene**: Lazy-loading for AI widgets using `IntersectionObserver`.

### 🔒 Security & Quality
- **Security Headers**: Implemented `X-Content-Type-Options`, `X-Frame-Options`, and `CSP`.
- **Rate Limiting**: Protected by `Flask-Limiter` to prevent abuse on free-tier infrastructure.
- **SEO Ready**: Dynamic `sitemap.xml` and semantic HTML5 structure.

## 🔬 RAG Pipeline: Evaluation-Driven Hybrid Retrieval

An empirical, evaluation-driven retrieval-augmented generation (RAG) pipeline power the post-level interactive assistant (`/api/chat/stream/<post_id>`), replacing ungrounded full-text context dumping with scoped, hybrid dense + sparse retrieval.

### Architecture & Production Design

- **Hybrid Retrieval Architecture**: Dense semantic embeddings (`nvidia/nemotron-3.5-embed-1b` in production) combined with lexical sparse search (`BM25Okapi`), fused via Reciprocal Rank Fusion (RRF, $k=60$) to select the top-4 most relevant sections.
- **Empirical Adoption Rationale**: Adopted after evaluation demonstrated **100.0% context recall** (68/68 queries) versus **98.53%** for dense semantic-only search, with equivalent faithfulness (0.9697 vs. 0.9634) and context precision (0.6156 vs. 0.6319) under clean prompt evaluation. Confidence-gated hybrid retrieval was evaluated but rejected because it inherited semantic-only recall dropouts (98.53%) and exhibited an unstable faithfulness anomaly (0.8692) ([results/final_comparison_2026-11-13.json](results/final_comparison_2026-11-13.json)).
- **Live Scoped Production Endpoint**: Wired into `/api/chat/stream/<post_id>` with per-post chunk index caching (`_POST_CHUNK_CACHE`). Articles with $\le 4$ chunks short-circuit directly to generation with zero retrieval latency.
- **Publish & Edit Pre-Warming**: Post creation (`/post/new`) and editing (`/post/<post_id>/edit`) asynchronously pre-warm chunk embeddings into memory using `ThreadPoolExecutor`, reducing long-post first-question Time-To-First-Token (TTFT) from a cold-start of **~2.4s–3.2s** down to **~0.36s–0.92s**, adding $<1\text{ ms}$ overhead to the HTTP publish redirect ([results/prewarmed_7post_benchmark.json](results/prewarmed_7post_benchmark.json)).

### Evaluation Methodology & Measurement Integrity

The pipeline was validated using a RAGAS-based evaluation framework across synthetic and manually curated adversarial datasets (negative controls, multi-post synthesis, and exact-entity lookups):

1. **Resolution of Compounding Measurement Bugs**:
   - *Dataset Construction Bug*: Early evaluations matched questions against single candidate chunks, inflating retrieval recall to 100% by construction. Fixed by evaluating retrieval against the complete multi-chunk post corpus.
   - *Judge Token Budget Exhaustion*: RAGAS LLM judges silently dropped incomplete evaluations (dropping valid samples to ~7% in early runs). The root cause was the reasoning judge model consuming its token limit on internal chain-of-thought; resolved by setting `extra_body={'reasoning_budget': 0}` directly on the judge client to disable internal reasoning tokens and enforce complete structured scoring outputs.
   - *Generation Client Reasoning-Budget Overflow*: Similarly, the generation client `client.chat.completions.create()` lacked `extra_body={'reasoning_budget': 0}`. The model exhausted output tokens on hidden chain-of-thought, returning empty content on Attempt 1 and triggering a fallback prompt (`"Answer the question short and clearly. Do not refuse."`) on **91.2%–97.1% of queries across every historical run**, silently stripping negative-grounding rules. Setting `reasoning_budget: 0` on generation eliminated these retries completely (reducing retry rate to **0.0%**) across all evaluation splits ([results/final_comparison_2026-11-13.json](results/final_comparison_2026-11-13.json)).

2. **Chunking Strategy Ablation (Paragraph vs. Semantic Chunking)**:
   - Evaluated on a 50-sample stratified benchmark ([results/chunking_stratified_ab_2026-11-23.json](results/chunking_stratified_ab_2026-11-23.json)).
   - Semantic chunking proved clearly advantageous for the dominant use case: on the well-powered chunk-grounded category ($N=38$), semantic chunking improved context precision (**0.7478 vs. 0.6550**, $+0.093$) and faithfulness (**0.9730 vs. 0.9370**).
   - However, edge-case categories ($N=4$ each for exact-entity and out-of-corpus) yielded mixed and inconclusive results: exact-entity recall dropped from $1.0000$ to $0.7500$ due to boundary boundary merging, though small sample sizes mean these differences could reflect variance rather than definitive trade-offs. While semantic chunking remains a compelling candidate for corpus-wide reindexing, paragraph chunking was maintained as the immediate production default to avoid risk until larger sample sizes are evaluated.

3. **Attribution Ablation: Scoped Retrieval vs. Grounding Prompt**:
   - A 4-way ablation on out-of-scope queries revealed that **scoped retrieval alone with a legacy prompt increased hallucination risk** (e.g., retrieving minimal context and answering from parametric memory: *"Paris. The provided blog content does not discuss this topic."*).
   - Deterministic 1-sentence refusal (*"The content does not address the question."*) was found to be **100% attributable to the strict grounded system prompt and temperature reduction ($0.2$)**, while retrieval scoping provides context compression and section targeting for long documents.

### Empirical Evaluation Metrics

#### 1. Retrieval Strategy Benchmark ($N=68$, Clean Post-Fix Evaluation)
Source: [results/final_comparison_2026-11-13.json](results/final_comparison_2026-11-13.json)

| Retrieval Strategy | Context Recall | Context Precision | Faithfulness | Answer Relevancy | Attempt 1 Retry Rate |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Dense Semantic-Only** | 98.53% | 0.6319 | 0.9634 | 0.5431 | 0.0% |
| **BM25-Only** | 91.04% | 0.5846 | 0.8956 | 0.5314 | 0.0% |
| **Unconditional Hybrid (Adopted)** | **100.00%** | **0.6156** | **0.9697** | **0.5317** | **0.0%** |
| **Confidence-Gated Hybrid** | 98.53% | 0.6319 | 0.8692 | 0.5401 | 0.0% |

#### 2. Chunking Strategy Paired Comparison ($N=50$ Stratified Sample)
Source: [results/chunking_stratified_ab_2026-11-23.json](results/chunking_stratified_ab_2026-11-23.json)

| Metric | Paragraph Chunking | Semantic Chunking | Paired Delta ($\Delta$) | Majority Class Delta (Chunk-Grounded) |
| :--- | :---: | :---: | :---: | :---: |
| **Faithfulness** | 0.8781 | **0.8844** | $+0.0063$ | **$+0.0360$** ($0.9730$ vs. $0.9370$) |
| **Context Precision** | 0.5817 | **0.6867** | **$+0.1050$** | **$+0.0928$** ($0.7478$ vs. $0.6550$) |
| **Context Recall** | **0.9250** | 0.9190 | $-0.0060$ | $+0.0263$ ($1.0000$ vs. $0.9737$) |

#### 3. Live Streaming Latency Across Document Lengths
Source: [results/prewarmed_7post_benchmark.json](results/prewarmed_7post_benchmark.json)

| Document Category | Chunks | Cold-Start TTFT (1st Q) | Warm Cache TTFT (2nd Q) | Pre-Warmed TTFT (1st Q) |
| :--- | :---: | :---: | :---: | :---: |
| **Short (Mastering Flask Part 1)** | 3 | 0.448s | 0.521s | **0.401s** |
| **Short (Minimalist Design)** | 2 | 0.792s | 0.590s | **0.368s** |
| **Boundary (Mastering Flask Part 2)** | 4 | 0.665s | 0.520s | **0.365s** |
| **Boundary (Hyper-local Communities)** | 5 | 1.472s | 0.768s | **0.796s** |
| **Moderate (Functional Fitness)** | 7 | 1.473s | 0.743s | **0.877s** |
| **Long (Quantum Entanglement)** | 15 | 2.422s | 0.919s | **0.843s** |
| **Long (Decentralized Finance)** | 15 | 2.391s | 0.741s | **0.915s** |

## 🛠️ Tech Stack

- **Backend**: Python 3.12, Flask, MongoDB Atlas (Flask-PyMongo)
- **AI/LLM**: Llama 3.1 8B (via NVIDIA NIM), Tavily API
- **Email**: Brevo API (HTTP-based)
- **Frontend**: Bootstrap 5, AOS (Animate On Scroll), Trumbowyg Editor, Bleach
- **Deployment**: Gunicorn, Render

## ⚙️ Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Sukhshum2628/Flask-Blog-Website.git
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**:
   Create a `.env` file with:
   - `MONGO_URI`
   - `SECRET_KEY`
   - `AI_API_KEY` (NVIDIA NIM)
   - `TAVILY_API_KEY`
   - `BREVO_API_KEY`
   - `MAIL_USER` (Verified Sender)

4. **Run Locally**:
   ```bash
   flask run
   ```

## 📝 License
MIT License. Created by [Sukhshum](https://github.com/Sukhshum2628).
