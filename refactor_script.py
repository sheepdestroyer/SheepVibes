import sys

# Read the file
with open('backend/feed_service.py', 'r') as f:
    lines = f.readlines()

# Helper to find line index
def find_line_index(lines, search_str, start=0):
    for i in range(start, len(lines)):
        if search_str in lines[i]:
            return i
    return -1

# 1. Insert create_safe_opener function
fetch_feed_idx = find_line_index(lines, 'def fetch_feed(feed_url):')
if fetch_feed_idx == -1:
    print("Could not find fetch_feed definition")
    sys.exit(1)

new_function_code = [
    'def create_safe_opener(safe_ip):\n',
    '    """Creates a URL opener with custom handlers for SSRF/TOCTOU prevention."""\n',
    '    # Prevent TOCTOU: Use custom handlers to force connection to safe_ip\n',
    '\n',
    '    # Register BOTH handlers to ensure safety during redirects (HTTPS -> HTTP or HTTP -> HTTPS)\n',
    '    # Both handlers utilize ip pinning via  (and  for redirects).\n',
    '    http_handler = SafeHTTPHandler(safe_ip=safe_ip)\n',
    '    https_handler = SafeHTTPSHandler(safe_ip=safe_ip)\n',
    '    redirect_handler = SafeRedirectHandler()\n',
    '\n',
    '    # Build opener with all handlers\n',
    '    return urllib.request.build_opener(http_handler, https_handler, redirect_handler)\n',
    '\n',
    '\n'
]

# Insert before fetch_feed
lines[fetch_feed_idx:fetch_feed_idx] = new_function_code

# 2. Update fetch_feed to use create_safe_opener
# The index of fetch_feed has shifted
fetch_feed_idx += len(new_function_code)

try_idx = find_line_index(lines, 'try:', start=fetch_feed_idx)
if try_idx == -1:
    print("Could not find try block in fetch_feed")
    sys.exit(1)

# We want to replace the handler creation block
# It starts after 'try:' and ends before 'req = urllib.request.Request('
start_replace = try_idx + 1
end_replace = find_line_index(lines, 'req = urllib.request.Request(', start=start_replace)

if end_replace == -1:
    print("Could not find end of handler block")
    sys.exit(1)

replacement_code = [
    '        opener = create_safe_opener(safe_ip)\n'
]

lines[start_replace:end_replace] = replacement_code

# Write the file back
with open('backend/feed_service.py', 'w') as f:
    f.writelines(lines)

print("Refactoring complete.")
