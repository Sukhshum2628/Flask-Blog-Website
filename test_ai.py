from services.ai_service import summarize_text, answer_question

sample_blog_content = """This is the first paragraph of an amazing blog post about artificial intelligence. AI is rapidly evolving and changing industries like healthcare and finance.

The second paragraph discusses machine learning specifically. Machine learning algorithms, such as neural networks, learn patterns from massive datasets without explicit programming.

Finally, the third paragraph touches on the ethical implications of AI. Bias in training data can lead to unfair outcomes, which means developers must carefully audit their models."""

print("--- TESTING SUMMARIZE ---")
res1 = summarize_text(sample_blog_content)
print("Summary Points:", res1['summary'])
print("Insight:", res1['insight'])
print("Sources:", res1['sources'])

print("\n--- TESTING ANSWER QUESTION ---")
res2 = answer_question(sample_blog_content, "What does the second paragraph say about machine learning?")
print("Summary Points:", res2['summary'])
print("Insight:", res2['insight'])
print("Sources list:", res2['sources'])
print("Internet Sources:", res2['internet_sources'])
