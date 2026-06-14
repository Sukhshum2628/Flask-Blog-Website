"""
RAGAS evaluation for the FlaskBlog RAG pipeline.

Runs your REAL pipeline (services/ai_service.answer_question) over the test set
in dataset.py, then scores it on four RAGAS metrics:

  faithfulness       - is the answer grounded in the retrieved chunks (no hallucination)?
  answer_relevancy   - does the answer actually address the question?
  context_precision  - are the retrieved chunks relevant (low noise)?
  context_recall     - did retrieval capture everything needed for the answer?

IMPORTANT - this project uses NVIDIA's Llama endpoint, NOT OpenAI. RAGAS defaults
to OpenAI for its "judge" LLM + embeddings, so we explicitly point it at NVIDIA
using your existing AI_API_KEY. No OpenAI account required.

Run:
    pip install ragas datasets langchain-nvidia-ai-endpoints
    python eval/ragas_eval.py
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dotenv import load_dotenv
load_dotenv()

from datasets import Dataset
from ragas import evaluate
from ragas.metrics import (
    faithfulness,
    answer_relevancy,
    context_precision,
    context_recall,
)
from ragas.llms import LangchainLLMWrapper
from ragas.embeddings import LangchainEmbeddingsWrapper
from langchain_nvidia_ai_endpoints import ChatNVIDIA, NVIDIAEmbeddings

from eval.dataset import EVAL_DATA
from eval.rag_pipeline import retrieve_and_answer

# --- Config -----------------------------------------------------------------
AI_API_KEY = os.environ.get("AI_API_KEY")

# The "judge" model that scores your pipeline. Use a STRONGER model than the one
# generating answers (8B) so the grader is more reliable. 70B is a good default.
JUDGE_MODEL = os.environ.get("RAGAS_JUDGE_MODEL", "meta/llama-3.3-70b-instruct")
EMBED_MODEL = os.environ.get("RAGAS_EMBED_MODEL", "nvidia/nv-embedqa-e5-v5")

RESULTS_CSV = os.path.join(os.path.dirname(__file__), "ragas_results.csv")


def build_eval_dataset() -> Dataset:
    """Run the live pipeline to fill in answers + retrieved contexts."""
    rows = {"question": [], "answer": [], "contexts": [], "ground_truth": []}

    for i, item in enumerate(EVAL_DATA, start=1):
        q = item["question"]
        print(f"[{i}/{len(EVAL_DATA)}] Running pipeline: {q}", flush=True)

        out = retrieve_and_answer(q, item["context"])

        rows["question"].append(q)
        rows["answer"].append(out["answer"])
        rows["contexts"].append(out["retrieved_chunks"])   # list[str], required shape
        rows["ground_truth"].append(item["ground_truth"])

    return Dataset.from_dict(rows)


def main():
    if not AI_API_KEY:
        raise SystemExit("AI_API_KEY not set. RAGAS needs it for the NVIDIA judge model.")
    if not EVAL_DATA:
        raise SystemExit("dataset.py EVAL_DATA is empty. Add test questions first.")

    # Point RAGAS's judge + embeddings at NVIDIA (not OpenAI).
    judge_llm = LangchainLLMWrapper(
        ChatNVIDIA(model=JUDGE_MODEL, api_key=AI_API_KEY, temperature=0)
    )
    judge_embeddings = LangchainEmbeddingsWrapper(
        NVIDIAEmbeddings(model=EMBED_MODEL, api_key=AI_API_KEY)
    )

    dataset = build_eval_dataset()

    print("\nScoring with RAGAS (this calls the judge model per metric)...\n", flush=True)
    result = evaluate(
        dataset,
        metrics=[faithfulness, answer_relevancy, context_precision, context_recall],
        llm=judge_llm,
        embeddings=judge_embeddings,
    )

    print("\n=== RAGAS scores ===")
    print(result)

    df = result.to_pandas()
    df.to_csv(RESULTS_CSV, index=False)
    print(f"\nPer-question breakdown saved to {RESULTS_CSV}")

    # Quick interpretation hints for acting on the numbers.
    print("\nHow to read low scores:")
    print("  faithfulness      low -> LLM hallucinates; tighten 'answer only from context' prompt")
    print("  answer_relevancy  low -> answers drift off-question; sharpen the system prompt")
    print("  context_precision low -> chunks are noisy; smaller chunks / better splitting")
    print("  context_recall    low -> missing chunks; increase top-k / chunk overlap")


if __name__ == "__main__":
    main()
