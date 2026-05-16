with open("backend/feed_service.py", "r") as f:
    content = f.read()

old_line = '    return "".join(ch for ch in text if ch.isprintable())[:200]'
new_line = '    return "".join(itertools.islice(filter(str.isprintable, text), 200))'
content = content.replace(old_line, new_line)

with open("backend/feed_service.py", "w") as f:
    f.write(content)
