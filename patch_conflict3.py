import re

with open("backend/feed_service.py", "r") as f:
    content = f.read()

# Make sure we use operator.itemgetter in our helper!
# And the list comprehension.
# That was what got merged into main.

helpers = """
def _preprocess_entries(parsed_feed, feed_name):
    \"\"\"Parses dates and sorts entries newest-first to preserve earliest duplicates.\"\"\"
    entries_with_dates = [
        (entry, parse_published_time(entry)) for entry in parsed_feed.entries
    ]

    try:
        entries_with_dates.sort(key=operator.itemgetter(1), reverse=True)
    except Exception:  # pylint: disable=broad-exception-caught
        logger.warning(
            "Failed to sort entries for feed %s", _sanitize_for_log(feed_name)
        )

    return entries_with_dates
"""

pattern = r'def _preprocess_entries\(parsed_feed, feed_name\):.*?(?=\n\n\ndef _process_single_entry)'
content = re.sub(pattern, helpers.strip(), content, flags=re.DOTALL)

with open("backend/feed_service.py", "w") as f:
    f.write(content)
print("Updated helper!")
