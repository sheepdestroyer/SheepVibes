import xml.etree.ElementTree as ET
import listparser

def parse_opml(opml_content):
    """Parses OPML content and returns a list of feed dictionaries.

    Args:
        opml_content: A string containing the OPML XML data.

    Returns:
        A list of dictionaries, where each dictionary represents a feed
        and has the keys 'title', 'xmlUrl', and 'outline' (for tab/folder).
        Returns an empty list if parsing fails or no feeds are found.
    """
    try:
        parsed = listparser.parse(opml_content)
        feeds = []
        # listparser specific parsing
        if parsed.feeds:
            for feed_obj in parsed.feeds:
                outline_title = None
                # For listparser, feed_obj.meta.title often holds the category/outline.
                # It can sometimes be a list if there's deep nesting, we'll take the first non-empty string.
                if hasattr(feed_obj, 'meta') and feed_obj.meta and hasattr(feed_obj.meta, 'title') and feed_obj.meta.title:
                    if isinstance(feed_obj.meta.title, list):
                        for item_title in feed_obj.meta.title:
                            if isinstance(item_title, str) and item_title.strip():
                                outline_title = item_title.strip()
                                break
                    elif isinstance(feed_obj.meta.title, str) and feed_obj.meta.title.strip():
                        outline_title = feed_obj.meta.title.strip()

                if not feed_obj.title or not feed_obj.url:
                    continue

                feeds.append({
                    'title': feed_obj.title,
                    'xmlUrl': feed_obj.url,
                    'outline': outline_title if outline_title else "Imported Feeds"
                })
            return feeds # Prefer listparser results if any feeds were found

        # Fallback to ET parsing if listparser found no feeds.
        # This is crucial for OPMLs where feeds are directly nested under outlines with 'text'/'title'
        # which listparser might not always categorize as feed_obj.meta.title.
        # Reset feeds list as listparser path was not taken or returned empty.
        feeds = []
        try:
            root = ET.fromstring(opml_content)
            # Iterate through all 'outline' elements that have an 'xmlUrl' attribute (i.e., they are feeds)
            for feed_element in root.findall('.//outline[@xmlUrl]'):
                current_outline_title = "Imported Feeds" # Default
                parent = feed_element.getparent()
                temp_parent = parent
                # Traverse up to find the closest parent 'outline' that has a 'text' or 'title' attribute.
                # This parent outline represents the category/folder.
                while temp_parent is not None:
                    # We are looking for a parent <outline> that is NOT a feed itself (i.e., does not have xmlUrl)
                    # but DOES have a title/text to be considered a category.
                    if temp_parent.tag == 'outline' and temp_parent.get('xmlUrl') is None:
                        parent_title_attr = temp_parent.get('text', temp_parent.get('title'))
                        if parent_title_attr and parent_title_attr.strip():
                            current_outline_title = parent_title_attr.strip()
                            break # Found the category parent
                    # Stop if we hit the 'body' tag or go above it (e.g. opml tag).
                    if temp_parent.tag == 'body' or temp_parent.tag == 'opml':
                        break
                    temp_parent = temp_parent.getparent()

                feeds.append({
                    'title': feed_element.get('title', feed_element.get('text', feed_element.get('xmlUrl'))),
                    'xmlUrl': feed_element.get('xmlUrl'),
                    'outline': current_outline_title
                })
            return feeds
        except ET.ParseError:
            # If listparser also failed (returned empty feeds before this block),
            # and ET parsing fails, then we truly couldn't parse it.
            # The initial feeds list would be empty from listparser path.
            return [] # Return empty list as per original broad except clause
    except Exception: # Catch any other unexpected errors from listparser or general issues
        # Consider logging the error for debugging
        return []


def generate_opml(tabs_with_feeds):
    """Generates an OPML XML string from a list of Tab objects.

    Args:
        tabs_with_feeds: A list of Tab objects, where each Tab object
                         has a 'feeds' attribute containing a list of
                         Feed objects.

    Returns:
        A string containing the OPML XML.
    """
    opml = ET.Element('opml', version='2.0')
    head = ET.SubElement(opml, 'head')
    ET.SubElement(head, 'title').text = 'SheepVibes Feeds'
    body = ET.SubElement(opml, 'body')

    for tab in tabs_with_feeds:
        tab_outline = ET.SubElement(body, 'outline', text=tab.name, title=tab.name)
        for feed in tab.feeds:
            ET.SubElement(tab_outline, 'outline', type='rss',
                          text=feed.name, title=feed.name,
                          xmlUrl=feed.url, htmlUrl='')

    # ET.indent for pretty printing (Python 3.9+)
    if hasattr(ET, 'indent'):
        ET.indent(opml, space="  ")

    return ET.tostring(opml, encoding='unicode', method='xml')
