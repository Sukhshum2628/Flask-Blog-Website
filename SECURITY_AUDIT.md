# FlaskBlog — Baseline Security Audit & Vulnerability Assessment

**Date:** 2026-10-31  
**Branch:** `security/flaskblog-hardening`  
**Base Commit:** `4c12fbd`  
**Author:** Antigravity Security Pair Programmer

---

## 1. Executive Summary

A comprehensive architectural and security audit of the FlaskBlog repository was performed. The application is built on Flask 2.3.2, PyMongo, Flask-WTF, Bleach, Flask-Limiter, and OpenAI/Tavily client libraries, deployed on Render with MongoDB Atlas.

While the application features rate limiting and a nonce-based Content-Security-Policy (CSP), several critical and high-severity security vulnerabilities are present in session lifecycle management, authorization enforcement, background job isolation, CSRF protection, password recovery single-use guarantees, AI prompt handling, and regex searching.

---

## 2. Complete Endpoint Inventory & Security Classification

Total Application Endpoints: **34**

| Line | Methods | Path | View Function | Auth Enforced? | CSRF Exempt? | Rate Limited? | Mongo Access? | External Services |
|:---|:---|:---|:---|:---:|:---:|:---:|:---:|:---|
| 80 | `GET` | `/robots.txt` | `robots_txt` | No | No | No | No | None |
| 96 | `GET` | `/sitemap.xml` | `sitemap` | No | No | No | Yes (`posts`) | None |
| 229 | `GET` | `/test_email` | `test_email` | **No** (VULN) | No | No | No | Email / Brevo |
| 282 | `GET` | `/health` | `health_check` | No | No | No | No | None |
| 286 | `GET` | `/ping` | `ping` | No | No | No | No | None |
| 291 | `POST` | `/api/save_progress/<post_id>` | `save_progress` | Yes (manual) | **Yes** (VULN) | No | No | None |
| 499 | `GET` | `/search/suggestions` | `search_suggestions` | No | No | No | Yes (`posts`) | None |
| 521 | `GET` | `/` | `index` | No | No | No | Yes (`posts`, `users`) | None |
| 572 | `GET` | `/search` | `search` | No | No | No | Yes (`posts`, `users`) | None |
| 594 | `GET`, `POST` | `/register` | `register` | No | No | Yes (10/hr POST) | Yes (`users`) | None |
| 624 | `GET`, `POST` | `/login` | `login` | No | No | Yes (20/hr POST) | Yes (`users`) | None |
| 661 | `GET`, `POST` | `/reset_password` | `reset_request` | No | No | Yes (5/hr POST) | Yes (`users`) | Email / Brevo |
| 674 | `GET`, `POST` | `/reset_password/<token>` | `reset_token` | No | No | No | Yes (`users`) | None |
| 690 | `GET` | `/logout` | `logout` | Yes (manual) | **Yes (GET method)** | No | No | None |
| 697 | `GET`, `POST` | `/post/new` | `new_post` | Yes (manual) | No | Yes (20/hr POST) | Yes (`posts`) | None |
| 742 | `GET`, `POST` | `/post/<post_id>` | `view_post` | Partial (POST) | No | Yes (30/hr POST) | Yes (`posts`, `comments`) | AI Service |
| 860 | `POST` | `/post/<post_id>/bookmark` | `bookmark_post` | Yes (manual) | No | No | Yes (`users`) | None |
| 880 | `POST` | `/ai/summarize/<post_id>` | `ai_summarize` | No (Public) | **Yes** (VULN) | Yes (30/hr) | Yes (`posts`) | AI Service |
| 922 | `POST` | `/ai/ask/<post_id>` | `ai_ask` | No | **Yes** | No | No | None (redirect) |
| 929 | `GET` | `/api/chat/stream/<post_id>` | `ai_chat_stream` | No (Public) | No | Yes (60/hr) | Yes (`posts`) | AI Service |
| 947 | `POST` | `/ai/research` | `ai_research` | Yes (manual) | **Yes** (VULN) | Yes (20/hr) | Yes (`jobs`) | AI / Tavily |
| 981 | `GET` | `/api/job/<job_id>` | `get_job_status` | **No** (VULN) | No | No | Yes (`jobs`) | None |
| 994 | `POST` | `/ai/improve-draft` | `ai_improve_draft` | Yes (manual) | **Yes** (VULN) | Yes (30/hr) | No | AI Service |
| 1014 | `GET`, `POST` | `/post/<post_id>/edit` | `edit_post` | Yes (manual) | No | No | Yes (`posts`) | None |
| 1076 | `POST` | `/post/<post_id>/delete` | `delete_post` | Yes (manual) | No | No | Yes (`posts`) | None |
| 1093 | `POST` | `/post/<post_id>/react/<reaction_type>` | `react_post` | Yes (manual) | No | No | Yes (`posts`) | None |
| 1120 | `POST` | `/comment/<comment_id>/pin` | `pin_comment` | Yes (manual) | No | No | Yes (`comments`, `posts`) | None |
| 1139 | `GET` | `/dashboard` | `dashboard` | Yes (manual) | No | No | Yes (`posts`, `comments`) | None |
| 1162 | `GET` | `/profile/<username>` | `profile` | No | No | No | Yes (`users`, `posts`) | None |
| 1183 | `GET` | `/settings` | `settings` | Yes (manual) | No | No | No | None |
| 1189 | `GET`, `POST` | `/settings/profile` | `settings_profile` | Yes (manual) | No | No | Yes (`users`, `posts`) | None |
| 1211 | `GET`, `POST` | `/settings/account` | `settings_account` | Yes (manual) | No | No | Yes (`users`) | None |
| 1233 | `POST` | `/api/bookmark/<post_id>` | `toggle_bookmark` | Yes (manual) | **Yes** (VULN) | Yes (10/min) | Yes (`users`) | None |
| 1248 | `GET` | `/reading-list` | `reading_list` | Yes (manual) | No | No | Yes (`users`, `posts`) | None |

---

## 3. Vulnerability Findings & Remediation Roadmap

### Finding 1: Insecure Default SECRET_KEY & Missing Production Validation (Phase 1)
- **Location:** `app.py:26-31`
- **Issue:** Falls back to `"dev_secret_key_change_me"` if `SECRET_KEY` is not present in the environment. In production, an attacker who knows the default key can forge Flask session cookies and password reset tokens.
- **Remediation:** Enforce that in production or non-debug mode, startup strictly raises an error if `SECRET_KEY` is missing or set to the default.

### Finding 2: Insecure Session Cookie Configuration & Lifecycle (Phase 1)
- **Location:** `app.py` session defaults
- **Issue:** `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, and `SESSION_COOKIE_SAMESITE = 'Lax'` are not explicitly declared on `app.config`. Furthermore, sessions are not regenerated upon login or revoked upon password changes.
- **Remediation:** Configure hardened session cookie flags; clear/regenerate session state on authentication events.

### Finding 3: Background Job IDOR & Data Leakage (Phase 2)
- **Location:** `app.py:947-989` (`/ai/research`, `/api/job/<job_id>`)
- **Issue:** `/ai/research` inserts jobs into `mongo.db.jobs` without attaching the user's ID. `/api/job/<job_id>` is completely unauthenticated and returns research results/prompts to anyone who provides a `job_id`.
- **Remediation:** Bind `user_id` to every background job record; require authentication on `/api/job/<job_id>` and verify ownership before returning job results.

### Finding 4: Inconsistent Authentication & Authorization Checks (Phase 2)
- **Location:** Multiple endpoints (`/post/<post_id>/edit`, `/post/<post_id>/delete`, etc.)
- **Issue:** Authorization checks are performed ad-hoc via inline `if 'user' not in session:` rather than a consistent, reusable decorator.
- **Remediation:** Standardize login and ownership verification decorators.

### Finding 5: CSRF Exemptions on State-Changing Endpoints (Phase 3)
- **Location:** `/api/save_progress`, `/ai/research`, `/ai/improve-draft`, `/api/bookmark`
- **Issue:** Decorated with `@csrf.exempt`. Any authenticated user visiting a malicious site can be tricked into triggering research, improving drafts, or altering progress/bookmarks via forged cross-site requests.
- **Remediation:** Remove `@csrf.exempt` on state-changing endpoints; pass the CSRF token via `X-CSRFToken` headers in frontend AJAX/fetch calls.

### Finding 6: Logout Endpoint Uses GET Method (Phase 3)
- **Location:** `app.py:690` (`/logout`)
- **Issue:** State-changing logout action is triggered by a `GET` request. Can be triggered via image tags or prefetching.
- **Remediation:** Change `/logout` to `POST` with CSRF protection and update navigation templates.

### Finding 7: Password Reset Tokens Not Invalidated After Single Use (Phase 4)
- **Location:** `app.py:377-387`, `673-687`
- **Issue:** Uses `URLSafeTimedSerializer` with static payload `{'user_id': str(user_id)}`. Tokens remain valid until `max_age=1800` expires, even after the user has already changed their password.
- **Remediation:** Bind password reset tokens to a user-specific password hash fragment or reset token version stored in the user document to guarantee immediate single-use invalidation.

### Finding 8: Public Test Email Endpoint Abuse (Phase 5)
- **Location:** `app.py:228-243` (`/test_email`)
- **Issue:** Unauthenticated `GET /test_email` triggers real transactional emails via Brevo to `MAIL_USER`. Vulnerable to denial of service, API quota exhaustion, and spamming.
- **Remediation:** Remove from production routing or restrict strictly to authenticated administrators.

### Finding 9: AI Resource Exhaustion & Prompt Exposure in GET Query Parameters (Phase 6)
- **Location:** `app.py:929` (`/api/chat/stream/<post_id>?question=...`), `ai_service.py`
- **Issue:** Chat questions are transmitted as URL query parameters in `GET` requests (logged in server access logs and browser histories). Lack of strict character length caps permits excessive token consumption.
- **Remediation:** Migrate chat streaming input to POST or sanitize/limit input lengths; delimit untrusted external content.

### Finding 10: Unbounded Regex Search Denial of Service (Phase 7)
- **Location:** `app.py:506` (`/search/suggestions`)
- **Issue:** User-supplied string is directly passed to `re.compile(query, re.IGNORECASE)` without escaping or length capping, risking catastrophic backtracking (ReDoS) or unintended regex evaluation against MongoDB.
- **Remediation:** Escape user query with `re.escape()` and impose strict length limits.

### Finding 11: Security Headers Completeness (Phase 8)
- **Location:** `app.py:60-77`
- **Issue:** Existing headers include CSP, HSTS, X-Content-Type-Options, and X-Frame-Options. However, `Referrer-Policy` and `Permissions-Policy` are absent, and clickjacking protection can be hardened.
- **Remediation:** Add `Referrer-Policy: strict-origin-when-cross-origin` and restrictive `Permissions-Policy`.

### Finding 12: Dependency Vulnerabilities & Audit (Phase 9)
- **Location:** `requirements.txt`
- **Issue:** Packages (such as Flask 2.3.2, Werkzeug 2.3.4, Bleach 6.0.0) need auditing against current CVE advisories.
- **Remediation:** Run `pip-audit`, resolve known CVEs, and pin dependencies.

---

## 4. Baseline Test Results

Automated test execution (`tests/test_baseline.py`):
- `test_health_check`: PASSED
- `test_ping`: PASSED
- `test_index_page`: PASSED
- `test_login_get`: PASSED
- `test_register_get`: PASSED
- `test_reset_password_get`: PASSED
- `test_unauthenticated_protected_routes`: PASSED
- `test_search_suggestions_empty`: PASSED
- `test_security_headers_present`: PASSED

**Result:** 9 passed, 0 failed, 0 skipped.
MongoDB Atlas connection verified and operational.
