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
