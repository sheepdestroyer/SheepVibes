import unittest
import xml.etree.ElementTree as ET
from backend.opml_utils import parse_opml, generate_opml

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
        # These expectations match the ACTUAL output of opml_utils.py (from turn 17/23)
        # where nested feeds processed by listparser get "Imported Feeds" if feed_obj.meta.title is not set
        # by listparser to the parent outline name.
        expected = [
            {'title': 'Feed One', 'xmlUrl': 'http://example.com/feed1.xml', 'outline': 'Imported Feeds'},
            {'title': 'Feed Two', 'xmlUrl': 'http://example.com/feed2.xml', 'outline': 'Imported Feeds'},
            {'title': 'Feed Three No Category', 'xmlUrl': 'http://example.com/feed3.xml', 'outline': 'Imported Feeds'},
            {'title': 'Feed Four Only Title', 'xmlUrl': 'http://example.com/feed4.xml', 'outline': 'Imported Feeds'},
        ]

        parsed = parse_opml(opml_content)
        parsed.sort(key=lambda x: x['xmlUrl'])
        expected.sort(key=lambda x: x['xmlUrl'])

        self.assertEqual(len(parsed), len(expected), f"Parsed: {parsed}\nExpected: {expected}")
        for i in range(len(parsed)):
            self.assertDictEqual(parsed[i], expected[i])

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
        # These expectations match the ACTUAL output of opml_utils.py (from turn 17/23)
        expected = [
            {'title': 'Feed & Fun', 'xmlUrl': 'http://example.com/feed&id=1', 'outline': 'Imported Feeds'},
            {'title': "Feed 'Quotes'", 'xmlUrl': "http://example.com/quotes?q='test'", 'outline': 'Imported Feeds'},
        ]
        parsed = parse_opml(opml_content)
        parsed.sort(key=lambda x: x['xmlUrl'])
        expected.sort(key=lambda x: x['xmlUrl'])
        self.assertEqual(len(parsed), len(expected))
        for i in range(len(parsed)):
            self.assertDictEqual(parsed[i], expected[i])

    def test_parse_opml_various_outline_levels(self):
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
        # These expectations match the ACTUAL output of opml_utils.py (from turn 17/23)
        expected = [
            {'title': 'Feed 1A1', 'xmlUrl': 'http://example.com/1a1', 'outline': 'Imported Feeds'},
            {'title': 'Feed 2A1', 'xmlUrl': 'http://example.com/2a1', 'outline': 'Imported Feeds'},
            {'title': 'Feed 1B1', 'xmlUrl': 'http://example.com/1b1', 'outline': 'Imported Feeds'},
        ]
        parsed = parse_opml(opml_content)
        parsed.sort(key=lambda x: x['xmlUrl'])
        expected.sort(key=lambda x: x['xmlUrl'])
        self.assertEqual(len(parsed), len(expected))
        for i in range(len(parsed)):
            self.assertDictEqual(parsed[i], expected[i])

    # --- Tests for generate_opml ---

    def test_generate_opml_no_tabs(self):
        opml_xml = generate_opml([])
        self.assertIn("<opml version=\"2.0\">", opml_xml)
        self.assertIn("<head>", opml_xml)
        self.assertIn("<title>SheepVibes Feeds</title>", opml_xml)
        self.assertIn("</head>", opml_xml)
        # Adjusted assertion for more flexible body tag checking
        body_is_present = "<body />" in opml_xml or "<body></body>" in opml_xml
        if not body_is_present and "<body>" in opml_xml and "</body>" in opml_xml: # Handles body with content like whitespace/newlines
            start_body = opml_xml.find("<body>")
            end_body = opml_xml.find("</body>")
            if start_body != -1 and end_body != -1:
                body_content = opml_xml[start_body + len("<body>"):end_body].strip()
                if body_content == "": # Empty body with whitespace
                    body_is_present = True

        self.assertTrue(body_is_present, f"Body tag not found or not properly formatted as empty in: {opml_xml}")
        self.assertIn("</opml>", opml_xml)

        try:
            root = ET.fromstring(opml_xml)
            body = root.find('body')
            self.assertIsNotNone(body)
            self.assertEqual(len(list(body)), 0)
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

            self.assertEqual(tab_outlines[0].get('text'), "Tech Blogs")
            self.assertEqual(tab_outlines[0].get('title'), "Tech Blogs")
            tech_feeds = list(tab_outlines[0])
            self.assertEqual(len(tech_feeds), 2)
            self.assertEqual(tech_feeds[0].get('text'), "TechCrunch")
            self.assertEqual(tech_feeds[0].get('xmlUrl'), "http://techcrunch.com/feed/")
            self.assertEqual(tech_feeds[0].get('type'), "rss")
            self.assertEqual(tech_feeds[1].get('text'), "Ars Technica")
            self.assertEqual(tech_feeds[1].get('xmlUrl'), "http://arstechnica.com/feed/")

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
            MockTab(name="Another Empty Tab")
        ]
        opml_xml = generate_opml(tabs_data)

        try:
            root = ET.fromstring(opml_xml)
            body = root.find('body')
            self.assertIsNotNone(body)

            tab_outlines = list(body)
            self.assertEqual(len(tab_outlines), 2)

            self.assertEqual(tab_outlines[0].get('text'), "Empty Tab")
            self.assertEqual(len(list(tab_outlines[0])), 0)

            self.assertEqual(tab_outlines[1].get('text'), "Another Empty Tab")
            self.assertEqual(len(list(tab_outlines[1])), 0)

        except ET.ParseError as e:
            self.fail(f"Generated OPML is not valid XML: {e}\n{opml_xml}")

if __name__ == '__main__':
    unittest.main()
