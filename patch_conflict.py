import re

with open("backend/feed_service.py", "r") as f:
    content = f.read()

# Instead of exact string replace, use regex since the indentation might be tricky
pattern = r"<<<<<<< HEAD\n\s*entries_with_dates = _preprocess_entries\(parsed_feed, feed_db_obj\.name\)\n=======\n.*?>>>>>>> origin/main"
content = re.sub(pattern, "    entries_with_dates = _preprocess_entries(parsed_feed, feed_db_obj.name)", content, flags=re.DOTALL)

with open("backend/feed_service.py", "w") as f:
    f.write(content)
print("Resolved!")
