"""
Regression load test for the DEPLOYED FlaskBlog (Render free tier).

It simulates realistic read-heavy browsing: homepage, paginated feed, search,
search suggestions, and reading individual posts (URLs discovered from the live
sitemap). Only safe GET endpoints are hit - no writes, no AI calls (those cost
quota and are not representative of typical traffic).

USAGE (against the deployed site, never localhost):

    pip install locust

    # Headless ramp to find the breaking point:
    locust -f loadtest/locustfile.py \
        --host https://YOUR-APP.onrender.com \
        --headless -u 50 -r 5 -t 3m --csv loadtest/results

  -u 50  = peak concurrent users
  -r 5   = spawn 5 users/sec (ramp)
  -t 3m  = run 3 minutes
  --csv  = write results_stats.csv / _failures.csv / _stats_history.csv

To find the true ceiling, run a few times increasing -u (e.g. 25, 50, 100, 200)
and watch where p95 latency spikes and failure % climbs above ~1-2%.

NOTE: Render free tier sleeps after inactivity - the first request wakes it
(cold start can take 30-60s). Hit the site once in a browser before testing,
or treat the first few failures as the cold start.
"""

import random
from locust import HttpUser, task, between
from urllib.parse import urlparse
import re


def _discover_post_paths(client):
    """Pull real post URLs from /sitemap.xml so we exercise actual pages."""
    paths = []
    try:
        resp = client.get("/sitemap.xml", name="/sitemap.xml")
        for loc in re.findall(r"<loc>(.*?)</loc>", resp.text):
            path = urlparse(loc).path
            if path.startswith("/post/"):
                paths.append(path)
    except Exception:
        pass
    return paths


class BlogReader(HttpUser):
    # Think-time between actions, like a real reader.
    wait_time = between(1, 4)

    def on_start(self):
        self.post_paths = _discover_post_paths(self.client)

    @task(5)
    def homepage(self):
        self.client.get("/", name="/ (homepage)")

    @task(3)
    def read_post(self):
        if self.post_paths:
            self.client.get(random.choice(self.post_paths), name="/post/[id]")
        else:
            self.client.get("/", name="/ (homepage)")

    @task(2)
    def feed_pagination(self):
        page = random.randint(1, 3)
        self.client.get(f"/?page={page}", name="/?page=[n]")

    @task(2)
    def search(self):
        term = random.choice(["python", "remote", "ai", "flask", "design", "work"])
        self.client.get(f"/search?q={term}", name="/search")

    @task(1)
    def search_suggestions(self):
        term = random.choice(["py", "re", "ai", "fl", "de"])
        self.client.get(f"/search/suggestions?q={term}", name="/search/suggestions")

    @task(1)
    def health(self):
        self.client.get("/health", name="/health")
