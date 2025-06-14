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
        if parsed.feeds:
            for feed_obj in parsed.feeds:
                # listparser stores outline path in feed_obj.meta.title
                # The actual feed title is in feed_obj.title
                # The feed URL is in feed_obj.url
                outline_title = None
                if hasattr(feed_obj, 'meta') and hasattr(feed_obj.meta, 'title'):
                    outline_title = feed_obj.meta.title

                # Ensure essential attributes are present
                if not feed_obj.title or not feed_obj.url:
                    # Potentially log a warning here if a feed is missing title or url
                    continue

                feeds.append({
                    'title': feed_obj.title,
                    'xmlUrl': feed_obj.url,
                    'outline': outline_title if outline_title else "Default" # Default to "Default" if no outline
                })

        # Handle OPMLs structured with <outline> tags directly
        # listparser might handle this, but this is a fallback/alternative
        if not feeds: # If listparser didn't find feeds in its usual way
            root = ET.fromstring(opml_content)
            for outline_element in root.findall('.//outline[@xmlUrl]'):
                outline_title = "Default" # Default tab name
                parent = outline_element.getparent()
                if parent is not None and parent.tag == 'outline' and parent.get('text'):
                    outline_title = parent.get('text')
                elif parent is not None and parent.tag == 'outline' and parent.get('title'):
                    outline_title = parent.get('title')


                # If the direct parent is not an outline with a title, check grandparents
                if outline_title == "Default":
                    grandparent = parent.getparent() if parent is not None else None
                    if grandparent is not None and grandparent.tag == 'outline' and grandparent.get('text'):
                         outline_title = grandparent.get('text')
                    elif grandparent is not None and grandparent.tag == 'outline' and grandparent.get('title'):
                         outline_title = grandparent.get('title')


                feeds.append({
                    'title': outline_element.get('title', outline_element.get('text', '')), # take title, fallback to text
                    'xmlUrl': outline_element.get('xmlUrl'),
                    'outline': outline_title
                })
        return feeds
    except Exception: # Broad exception for parsing errors
        # Consider logging the error
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
                          xmlUrl=feed.url, htmlUrl='') # htmlUrl is optional but common

    # ET.indent for pretty printing (Python 3.9+)
    if hasattr(ET, 'indent'):
        ET.indent(opml, space="  ")

    return ET.tostring(opml, encoding='unicode', method='xml')
