"""
Reads app.py and prints the index route section.
Put this in your Flask project folder and run: python read_index_route.py
"""
import re

with open("app.py", "r", encoding="utf-8") as f:
    content = f.read()

# Find the index function
match = re.search(r"(@app\.route\('/'.*?)\ndef \w+\(", content, re.DOTALL)
# Better: find def index or the / route handler
lines = content.split("\n")

in_route = False
route_lines = []
brace_depth = 0

for i, line in enumerate(lines):
    # Find the / route
    if "@app.route('/')" in line or '@app.route("/")' in line:
        in_route = True
        route_lines.append(f"{i+1}: {line}")
        continue

    if in_route:
        route_lines.append(f"{i+1}: {line}")
        # Stop after 80 lines or when we hit the next route
        if len(route_lines) > 5 and ("@app.route" in line or "def " in line) and len(route_lines) > 10:
            break
        if len(route_lines) > 90:
            break

if route_lines:
    print("=== INDEX ROUTE ===")
    print("\n".join(route_lines))
else:
    print("Could not find index route automatically.")
    print("Searching for 'def index'...")
    for i, line in enumerate(lines):
        if "def index" in line:
            print(f"\nFound at line {i+1}:")
            for j in range(max(0, i-2), min(len(lines), i+80)):
                print(f"{j+1}: {lines[j]}")
            break