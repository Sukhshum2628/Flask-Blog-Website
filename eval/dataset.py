"""
Your RAGAS evaluation set.

Each item ties a QUESTION to a specific blog ARTICLE (the `context`) and the
CORRECT answer you write by hand (`ground_truth`). Quality > quantity: aim for
15-20 solid items drawn from your actual blog posts.

HOW TO BUILD THIS:
  1. Pick a real article. Paste its plain-text body into `context`.
     (Use the raw text the LLM sees - strip HTML. Bullets/paragraphs are fine;
      chunk_text() splits on newlines, so keep paragraph breaks.)
  2. Write a question a reader might ask about THAT article.
  3. Write the ground_truth: the correct answer, in your own words, using only
     facts that appear in the article.

You can reuse the same `context` for several questions about one article.

TIP: To pull real article text instead of pasting, you can query MongoDB and
strip tags with bleach/BeautifulSoup - but inline text keeps the eval runnable
with no DB connection, which is what you want for reproducible scoring.
"""

# ---------------------------------------------------------------------------
# Example article (replace with your own). Keep paragraphs separated by blank
# lines so chunk_text() produces multiple chunks.
# ---------------------------------------------------------------------------
_SAMPLE_ARTICLE = """\
Remote work shifted from a perk to the default for many software teams after 2020.
Companies that adopted it early reported a 13% productivity increase in one Stanford study.

The history of distributed teams goes back decades, with early open-source projects
collaborating across continents long before video calls were common.

Office snack budgets and ping-pong tables were once seen as the pinnacle of perks,
a relic of the in-person startup culture of the 2010s.

The biggest hidden cost is not coordination but loneliness. Surveys show isolation,
not distraction, is the top reason remote employees quit within their first year.

Commuting times in major cities had been rising steadily for years, a separate trend
that made any flexible arrangement attractive regardless of productivity.

Asynchronous communication is the skill that separates teams that thrive remotely
from teams that merely survive. Writing clearly replaces hallway conversations.

Some companies experimented with four-day weeks during the same period, though that
is a distinct policy unrelated to where the work physically happens.
"""

EVAL_DATA = [
    {
        "question": "What did the article say about remote work productivity?",
        "context": _SAMPLE_ARTICLE,
        "ground_truth": (
            "The article cites a Stanford study reporting a 13% productivity "
            "increase for companies that adopted remote work early."
        ),
    },
    {
        "question": "Why do remote employees quit in their first year?",
        "context": _SAMPLE_ARTICLE,
        "ground_truth": (
            "According to the article, loneliness and isolation - not distraction - "
            "is the top reason remote employees quit within their first year."
        ),
    },
    {
        "question": "What skill does the article say distinguishes thriving remote teams?",
        "context": _SAMPLE_ARTICLE,
        "ground_truth": (
            "Asynchronous communication, especially clear writing that replaces "
            "in-person hallway conversations, distinguishes teams that thrive."
        ),
    },

    # ----------------------------------------------------------------------
    # ADD 12-17 MORE ITEMS BELOW using your real blog posts.
    # Template:
    # {
    #     "question": "...",
    #     "context": "...full article text...",
    #     "ground_truth": "...the correct answer in your words...",
    # },
    # ----------------------------------------------------------------------
]
