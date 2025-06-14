import unittest
import xml.etree.ElementTree as ET
from backend.opml_utils import parse_opml, generate_opml
# Minimal mock objects for Tab and Feed if needed by generate_opml directly
# If generate_opml expects actual SQLAlchemy models, this approach might need adjustment
# or tests for generate_opml might be better as integration tests with a test DB.

class MockFeed:
    def __init__(self, name, url):
        self.name = name
        self.url = url

class MockTab:
    def __init__(self, name, feeds=None):
        self.name = name
        self.feeds = feeds if feeds is not None else []

class TestOpmlUtils(unittest.TestCase):

    def test_parse_opml_empty_input(self):
        self.assertEqual(parse_opml(""), [])

    def test_parse_opml_invalid_xml(self):
        self.assertEqual(parse_opml("<opml><body"), []) # Malformed
        self.assertEqual(parse_opml("Just some random text"), [])

    def test_parse_opml_basic_structure(self):
        opml_content = """<?xml version="1.0" encoding="UTF-8"?>
        <opml version="2.0">
            <head><title>Test Feeds</title></head>
            <body>
                <outline text="Feed One" title="Feed One" type="rss" xmlUrl="http://example.com/feed1.xml" />
                <outline text="Category 1">
                    <outline text="Feed Two" title="Feed Two" type="rss" xmlUrl="http://example.com/feed2.xml" />
                </outline>
                <outline text="Feed Three No Category" title="Feed Three No Category" type="rss" xmlUrl="http://example.com/feed3.xml" />
                 <outline title="Feed Four Only Title" type="rss" xmlUrl="http://example.com/feed4.xml" />
            </body>
        </opml>"""
        expected = [
            {'title': 'Feed One', 'xmlUrl': 'http://example.com/feed1.xml', 'outline': 'Default'}, # listparser behavior might make this Default or None
            {'title': 'Feed Two', 'xmlUrl': 'http://example.com/feed2.xml', 'outline': 'Category 1'},
            {'title': 'Feed Three No Category', 'xmlUrl': 'http://example.com/feed3.xml', 'outline': 'Default'},
            {'title': 'Feed Four Only Title', 'xmlUrl': 'http://example.com/feed4.xml', 'outline': 'Default'},
        ]
        # Adjusting expectation based on current opml_utils.py logic for listparser
        # The listparser library tends to put top-level feeds without a parent outline into a "Default" category or similar.
        # And the fallback ET parsing also defaults to "Default".

        parsed = parse_opml(opml_content)
        self.assertEqual(len(parsed), 4)
        # Sort by xmlUrl for consistent comparison
        parsed.sort(key=lambda x: x['xmlUrl'])
        expected.sort(key=lambda x: x['xmlUrl'])

        for p, e in zip(parsed, expected):
            self.assertEqual(p['title'], e['title'])
            self.assertEqual(p['xmlUrl'], e['xmlUrl'])
            # For outline, listparser might set it to None if no explicit parent outline.
            # The custom ET parsing part defaults to "Default".
            # Let's be flexible or ensure opml_utils is consistent.
            # Current opml_utils.py: outline_title if outline_title else "Default"
            self.assertEqual(p['outline'], e['outline'])


    def test_parse_opml_no_feeds(self):
        opml_content = """<?xml version="1.0" encoding="UTF-8"?>
        <opml version="2.0">
            <head><title>No Feeds Test</title></head>
            <body>
                <outline text="Empty Category" />
            </body>
        </opml>"""
        self.assertEqual(parse_opml(opml_content), [])

    def test_parse_opml_with_special_chars(self):
        opml_content = """<?xml version="1.0" encoding="UTF-8"?>
        <opml version="2.0">
            <body>
                <outline text="Feed &amp; Fun" title="Feed &amp; Fun" type="rss" xmlUrl="http://example.com/feed&amp;id=1" />
                <outline text="Cat > Dogs">
                    <outline text="Feed 'Quotes'" title="Feed 'Quotes'" xmlUrl="http://example.com/quotes?q='test'" />
                </outline>
            </body>
        </opml>"""
        # XML parsing should handle unescaping of attributes automatically.
        # listparser should also handle this.
        expected = [
            {'title': 'Feed & Fun', 'xmlUrl': 'http://example.com/feed&id=1', 'outline': 'Default'},
            {'title': "Feed 'Quotes'", 'xmlUrl': "http://example.com/quotes?q='test'", 'outline': 'Cat > Dogs'},
        ]
        parsed = parse_opml(opml_content)
        self.assertEqual(len(parsed), 2)
        parsed.sort(key=lambda x: x['xmlUrl'])
        expected.sort(key=lambda x: x['xmlUrl'])
        self.assertListEqual(parsed, expected)


    def test_parse_opml_various_outline_levels(self):
        # This test checks how nested outlines are handled.
        # The current parse_opml implementation (both listparser and fallback ET) effectively flattens the structure,
        # using the immediate parent outline's title as the category. Deeper nesting is not preserved into complex outline paths.
        opml_content = """<?xml version="1.0" encoding="UTF-8"?>
        <opml version="2.0">
            <body>
                <outline text="Level 1A">
                    <outline text="Feed 1A1" xmlUrl="http://example.com/1a1" />
                    <outline text="Level 2A">
                        <outline text="Feed 2A1" xmlUrl="http://example.com/2a1" />
                    </outline>
                </outline>
                <outline text="Level 1B">
                     <outline text="Feed 1B1" xmlUrl="http://example.com/1b1" />
                </outline>
            </body>
        </opml>"""
        expected = [
            {'title': 'Feed 1A1', 'xmlUrl': 'http://example.com/1a1', 'outline': 'Level 1A'},
            {'title': 'Feed 2A1', 'xmlUrl': 'http://example.com/2a1', 'outline': 'Level 2A'}, # listparser uses immediate parent
            {'title': 'Feed 1B1', 'xmlUrl': 'http://example.com/1b1', 'outline': 'Level 1B'},
        ]
        parsed = parse_opml(opml_content)
        self.assertEqual(len(parsed), 3)
        parsed.sort(key=lambda x: x['xmlUrl'])
        expected.sort(key=lambda x: x['xmlUrl'])
        self.assertListEqual(parsed, expected)

    # --- Tests for generate_opml ---

    def test_generate_opml_no_tabs(self):
        opml_xml = generate_opml([])
        self.assertIn("<opml version=\"2.0\">", opml_xml)
        self.assertIn("<head>", opml_xml)
        self.assertIn("<title>SheepVibes Feeds</title>", opml_xml)
        self.assertIn("</head>", opml_xml)
        self.assertIn("<body>", opml_xml)
        self.assertIn("</body>", opml_xml)
        self.assertIn("</opml>", opml_xml)
        # Check that body is empty or contains no <outline> elements
        try:
            root = ET.fromstring(opml_xml)
            body = root.find('body')
            self.assertIsNotNone(body)
            self.assertEqual(len(list(body)), 0) # No child elements in body
        except ET.ParseError as e:
            self.fail(f"Generated OPML is not valid XML: {e}\n{opml_xml}")


    def test_generate_opml_with_tabs_and_feeds(self):
        tabs_data = [
            MockTab(name="Tech Blogs", feeds=[
                MockFeed(name="TechCrunch", url="http://techcrunch.com/feed/"),
                MockFeed(name="Ars Technica", url="http://arstechnica.com/feed/")
            ]),
            MockTab(name="News", feeds=[
                MockFeed(name="BBC News", url="http://feeds.bbci.co.uk/news/rss.xml")
            ])
        ]
        opml_xml = generate_opml(tabs_data)

        try:
            root = ET.fromstring(opml_xml)
            body = root.find('body')
            self.assertIsNotNone(body)

            tab_outlines = list(body)
            self.assertEqual(len(tab_outlines), 2)

            # Tech Blogs Tab
            self.assertEqual(tab_outlines[0].get('text'), "Tech Blogs")
            self.assertEqual(tab_outlines[0].get('title'), "Tech Blogs")
            tech_feeds = list(tab_outlines[0])
            self.assertEqual(len(tech_feeds), 2)
            self.assertEqual(tech_feeds[0].get('text'), "TechCrunch")
            self.assertEqual(tech_feeds[0].get('xmlUrl'), "http://techcrunch.com/feed/")
            self.assertEqual(tech_feeds[0].get('type'), "rss")
            self.assertEqual(tech_feeds[1].get('text'), "Ars Technica")
            self.assertEqual(tech_feeds[1].get('xmlUrl'), "http://arstechnica.com/feed/")

            # News Tab
            self.assertEqual(tab_outlines[1].get('text'), "News")
            news_feeds = list(tab_outlines[1])
            self.assertEqual(len(news_feeds), 1)
            self.assertEqual(news_feeds[0].get('text'), "BBC News")
            self.assertEqual(news_feeds[0].get('xmlUrl'), "http://feeds.bbci.co.uk/news/rss.xml")

        except ET.ParseError as e:
            self.fail(f"Generated OPML is not valid XML: {e}\n{opml_xml}")

    def test_generate_opml_tabs_no_feeds(self):
        tabs_data = [
            MockTab(name="Empty Tab", feeds=[]),
            MockTab(name="Another Empty Tab") # feeds is None
        ]
        opml_xml = generate_opml(tabs_data)

        try:
            root = ET.fromstring(opml_xml)
            body = root.find('body')
            self.assertIsNotNone(body)

            tab_outlines = list(body)
            self.assertEqual(len(tab_outlines), 2)

            self.assertEqual(tab_outlines[0].get('text'), "Empty Tab")
            self.assertEqual(len(list(tab_outlines[0])), 0) # No feeds under this tab

            self.assertEqual(tab_outlines[1].get('text'), "Another Empty Tab")
            self.assertEqual(len(list(tab_outlines[1])), 0) # No feeds under this tab

        except ET.ParseError as e:
            self.fail(f"Generated OPML is not valid XML: {e}\n{opml_xml}")

if __name__ == '__main__':
    unittest.main()
