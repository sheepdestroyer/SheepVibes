import re

with open("backend/feed_service.py", "r") as f:
    content = f.read()

conflict1 = r"<<<<<<< HEAD\n\s*existing_items_by_guid, existing_items_by_link = _get_existing_items_lookups\(\n\s*feed_db_obj\n=======\n.*?>>>>>>> origin/main"
content = re.sub(conflict1, "    existing_items_by_guid, existing_items_by_link = _get_existing_items_lookups(\n        feed_db_obj", content, flags=re.DOTALL)

conflict2 = r"<<<<<<< HEAD\n\s*entries_with_dates = _preprocess_entries\(parsed_feed, feed_db_obj\.name\)\n=======\n.*?>>>>>>> origin/main"
content = re.sub(conflict2, "    entries_with_dates = _preprocess_entries(parsed_feed, feed_db_obj.name)", content, flags=re.DOTALL)

with open("backend/feed_service.py", "w") as f:
    f.write(content)
print("Resolved!")
