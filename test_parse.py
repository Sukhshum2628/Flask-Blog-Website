import re

def parse_llm_response(text):
    print(f"RAW: {text}")
    summary_points = []
    insight = ""
    
    if not text:
        return ["No response generated."], "The model returned an empty response."
        
    # Split the text
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
            # Extract bullet points if they exist
            if line.startswith('•') or line.startswith('-'):
                summary_points.append(re.sub(r'^[\•\-]\s*', '', line))
            elif line:
                # If no bullet, but it's in summary section
                summary_points.append(line)
        elif current_section == "INSIGHT":
            if line:
                insight += line + " "
                
    # Fallback if no layout was found
    if not summary_points and not insight:
        summary_points = [text]
        insight = "No specific insight provided."
    elif not summary_points:
        summary_points = ["No summary points found."]
    elif not insight:
        insight = "No specific insight provided."
        
    return summary_points, insight.strip()

texts = [
    "### SUMMARY\n• AI is cool.\n- It is fast.\n### KEY INSIGHT\nYes it is.",
    "Just a random paragraph about AI. It is very cool and fast. No bullets here.",
    "SUMMARY\nAI is cool.\nKEY INSIGHT\nYes."
]

for t in texts:
    s, i = parse_llm_response(t)
    print("S:", s)
    print("I:", i)
    print("---")
