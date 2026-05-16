with open("backend/feed_service.py", "r") as f:
    content = f.read()

if "import itertools" not in content:
    content = content.replace("import json\n", "import json\nimport itertools\n")

with open("backend/feed_service.py", "w") as f:
    f.write(content)
