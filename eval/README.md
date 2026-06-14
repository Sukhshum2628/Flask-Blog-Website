# RAG Evaluation with RAGAS

Measures whether the FlaskBlog RAG pipeline (`services/ai_service.answer_question`)
actually works, using four [RAGAS](https://docs.ragas.io) metrics:

| Metric | Question it answers | Fix if low |
|---|---|---|
| **faithfulness** | Is the answer grounded in retrieved chunks, or hallucinated? | Tighten prompt to "answer only from context" |
| **answer_relevancy** | Does the answer address the question? | Sharpen the system prompt |
| **context_precision** | Are the retrieved chunks relevant (not noisy)? | Smaller chunks / better splitting |
| **context_recall** | Did retrieval get *all* the needed info? | Increase top-k / chunk overlap |

## Why this setup is different from the generic guide

The standard RAGAS tutorial assumes **OpenAI**. This project runs on **NVIDIA's
Llama endpoint**, so `ragas_eval.py` explicitly points RAGAS's judge LLM and
embeddings at NVIDIA using your existing `AI_API_KEY`. No OpenAI account needed.

The judge defaults to a **70B** model (`meta/llama-3.3-70b-instruct`) — bigger
than the 8B model that generates answers — so the grader is more trustworthy than
the thing it's grading.

## Files

- `rag_pipeline.py` — adapter calling your **real** pipeline; returns `{answer, retrieved_chunks}`
- `dataset.py` — your test questions + hand-written ground-truth answers (fill this in)
- `ragas_eval.py` — runs the pipeline, scores it, writes `ragas_results.csv`

## Run

```bash
pip install ragas datasets langchain-nvidia-ai-endpoints
python eval/ragas_eval.py
```

Optional overrides:

```bash
export RAGAS_JUDGE_MODEL="meta/llama-3.3-70b-instruct"
export RAGAS_EMBED_MODEL="nvidia/nv-embedqa-e5-v5"
```

## Workflow

1. Add 15–20 items to `EVAL_DATA` in `dataset.py` from your real blog posts.
2. Run the eval → get baseline scores.
3. Change one thing (prompt / chunk size / top-k).
4. Re-run, compare. Document before/after.

> "RAGAS faithfulness improved from 0.74 → 0.89 after tightening the system prompt"
> is the interview line this whole setup exists to earn.

## Notes & caveats

- The eval calls live APIs (NVIDIA + Tavily) — it costs quota and isn't free/instant.
- `answer_question` also fires a Tavily web search per question; that web context
  is **not** added to RAGAS `contexts`, so faithfulness/recall reflect the *blog*
  grounding only. If you want web grounding scored too, add those snippets to
  `retrieved_chunks` in `rag_pipeline.py`.
- Eval deps are commented out in `requirements.txt` so Render's production build
  stays lean — install them locally only.
```
