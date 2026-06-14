"""
Thin adapter that exposes your EXISTING FlaskBlog RAG pipeline in the shape
RAGAS expects: {question, answer, contexts}.

Your pipeline lives in services/ai_service.py:
  - chunk_text(context)        -> the "retrieved" chunks (paragraphs of the blog)
  - answer_question(context, q) -> grounded answer + citation mapping

RAGAS needs, per question:
  - answer   : a single string the LLM produced
  - contexts : a list[str] of the chunks the retriever returned

This file does NOT re-implement anything. It just calls your real code so the
evaluation measures the pipeline you actually ship.
"""

import os
import sys

# Make "services" importable when running this file directly from eval/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.ai_service import answer_question, chunk_text


def retrieve_and_answer(question: str, context: str) -> dict:
    """
    Run the live FlaskBlog RAG pipeline for one (question, blog-context) pair.

    Returns:
        {
          "answer":            str,        # flattened LLM answer
          "retrieved_chunks":  list[str],  # the chunks fed to the LLM
        }
    """
    # Run the real grounded-QA call. It now performs semantic top-k retrieval
    # internally and reports back exactly which chunks it used.
    result = answer_question(context, question)

    # The chunks the LLM actually saw (retrieved subset). Fall back to full
    # chunking only if an older code path didn't report them.
    retrieved_chunks = result.get("retrieved_chunks")
    if not retrieved_chunks:
        retrieved_chunks = chunk_text(context)

    # 3. answer_question returns a structured dict (summary points + insight).
    #    RAGAS wants ONE string, so flatten it the same way the UI renders it.
    summary_points = result.get("summary", []) or []
    insight = result.get("insight", "") or ""

    answer_parts = list(summary_points)
    if insight:
        answer_parts.append(insight)
    answer = "\n".join(p for p in answer_parts if p).strip()

    if not answer:
        answer = "No answer generated."

    return {
        "answer": answer,
        "retrieved_chunks": retrieved_chunks,
    }
