<?php

declare(strict_types=1);

class GenericChangelogBridge extends BridgeAbstract
{
    const NAME = 'Generic Changelog & Release Bridge';
    const URI = 'https://github.com/sheepdestroyer/SheepVibes';
    const DESCRIPTION = 'Automatically extracts changelog and release entries from arbitrary web pages';
    const MAINTAINER = 'SheepVibes';
    const CACHE_TIMEOUT = 1800;

    const PARAMETERS = [[
        'url' => [
            'name' => 'Changelog Page URL',
            'type' => 'text',
            'required' => true,
            'exampleValue' => 'https://example.com/changelog',
        ],
    ]];

    public function collectData()
    {
        $url = $this->getInput('url');
        if (!$url) {
            throwClientException('Missing required "url" parameter');
        }

        $html = getSimpleHTMLDOM($url);
        if (!$html) {
            throwServerException('Could not load content from ' . $url);
        }

        // Try container-based entry extraction first
        $this->extractFromContainers($html, $url);

        // Fallback to heading-delimited extraction if no items were extracted
        if (empty($this->items)) {
            $this->extractFromHeadings($html, $url);
        }
    }

    private function extractFromContainers($html, string $baseUrl): void
    {
        $candidateSelectors = [
            'article.changelog-entry',
            'div[data-section-row]',
            'div.section-row-wrapper',
            'article[class*="changelog"]',
            'div[class*="changelog-entry"]',
            'div[class*="changelog-item"]',
            'div[class*="changelog__item"]',
            'div[class*="release-entry"]',
            'div[class*="release-item"]',
            'div[class*="release-card"]',
            'section[class*="changelog"]',
            'section[class*="release"]',
            'div[data-changelog-entry]',
            'main article',
            'article',
        ];

        foreach ($candidateSelectors as $selector) {
            $elements = $html->find($selector);
            if (empty($elements)) {
                continue;
            }

            $foundItems = [];
            foreach ($elements as $el) {
                $item = $this->parseContainerElement($el, $baseUrl);
                if ($item) {
                    $foundItems[] = $item;
                }
            }

            // If we successfully found valid entries from this selector, use them and stop
            if (!empty($foundItems)) {
                $this->items = $foundItems;
                return;
            }
        }
    }

    private function parseContainerElement($el, string $baseUrl): ?array
    {
        // Find title heading
        $headingEl = $el->find('h1, h2, h3, h4, h5, [class*="title"], [class*="heading"], [class*="version"]', 0);
        if (!$headingEl) {
            return null;
        }

        $title = trim($headingEl->plaintext);
        if (empty($title) || strlen($title) > 300) {
            return null;
        }

        // Check if there is an explicit version badge or link
        $versionEl = $el->find('a[class*="version"], span[class*="version"], div[class*="version"]', 0);
        $versionText = $versionEl ? trim($versionEl->plaintext) : '';
        if ($versionText && stripos($title, $versionText) === false && preg_match('/v?\d+(\.\d+)+/i', $versionText)) {
            $title = "[$versionText] $title";
        }

        // Extract date / timestamp
        $timestamp = $this->extractDate($el, $title);

        // Extract URI / Permalink
        $uri = $this->extractUri($el, $headingEl, $baseUrl, $title);

        // Extract Content
        $content = trim($el->innertext);
        if (empty($content)) {
            $content = htmlspecialchars($title);
        }

        return [
            'title' => $title,
            'uri' => defaultLinkTo($uri, $baseUrl),
            'timestamp' => $timestamp ?: time(),
            'content' => defaultLinkTo($content, $baseUrl),
            'uid' => defaultLinkTo($uri, $baseUrl),
        ];
    }

    private function extractFromHeadings($html, string $baseUrl): void
    {
        // Look for repeating h2 or h3 headings that resemble release/changelog titles
        foreach (['h2', 'h3'] as $tag) {
            $headings = $html->find($tag);
            if (empty($headings)) {
                continue;
            }

            $matchingHeadings = [];
            foreach ($headings as $h) {
                $text = trim($h->plaintext);
                if (preg_match('/(v?\d+\.\d+|\b(20\d\d[-/.][01]\d[-/.][0-3]\d)\b|release|changelog|update)/i', $text)) {
                    $matchingHeadings[] = $h;
                }
            }

            if (empty($matchingHeadings)) {
                continue;
            }

            foreach ($matchingHeadings as $idx => $h) {
                $title = trim($h->plaintext);
                $timestamp = $this->extractDate($h, $title);
                $uri = $this->extractUri($h, $h, $baseUrl, $title);

                // Collect content from sibling nodes until the next matching heading
                $content = '';
                $sibling = $h->next_sibling();
                while ($sibling && $sibling->tag !== $tag) {
                    $content .= $sibling->outertext;
                    $sibling = $sibling->next_sibling();
                }

                if (empty(trim($content))) {
                    $content = htmlspecialchars($title);
                }

                $this->items[] = [
                    'title' => $title,
                    'uri' => defaultLinkTo($uri, $baseUrl),
                    'timestamp' => $timestamp ?: time(),
                    'content' => defaultLinkTo($content, $baseUrl),
                    'uid' => defaultLinkTo($uri, $baseUrl),
                ];
            }

            if (!empty($this->items)) {
                return;
            }
        }
    }

    private function extractDate($el, string $title): ?int
    {
        // 1. Look for <time> tag
        $timeEl = $el->find('time', 0);
        if ($timeEl) {
            $dt = $timeEl->datetime ?: trim($timeEl->plaintext);
            $parsed = strtotime($dt);
            if ($parsed !== false) {
                return $parsed;
            }
        }

        // 2. Look for date-like classes
        $dateEl = $el->find('[class*="date"], [class*="time"], [class*="published"]', 0);
        if ($dateEl) {
            $dt = trim($dateEl->plaintext);
            $parsed = strtotime($dt);
            if ($parsed !== false) {
                return $parsed;
            }
        }

        // 3. Regex matching in heading or element text
        $textToSearch = $title . ' ' . substr(strip_tags($el->plaintext), 0, 500);

        // ISO format YYYY-MM-DD
        if (preg_match('/\b(20\d\d[-/.][01]\d[-/.][0-3]\d)\b/', $textToSearch, $m)) {
            $parsed = strtotime($m[1]);
            if ($parsed !== false) {
                return $parsed;
            }
        }

        // Month Day, Year (e.g. September 6, 2026 or Sep 6, 2026)
        if (preg_match('/\b(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},?\s+20\d\d\b/i', $textToSearch, $m)) {
            $parsed = strtotime($m[0]);
            if ($parsed !== false) {
                return $parsed;
            }
        }

        // Day Month Year (e.g. 6 September 2026)
        if (preg_match('/\b\d{1,2}\s+(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+20\d\d\b/i', $textToSearch, $m)) {
            $parsed = strtotime($m[0]);
            if ($parsed !== false) {
                return $parsed;
            }
        }

        return null;
    }

    private function extractUri($el, $headingEl, string $baseUrl, string $title): string
    {
        // Check for anchor inside heading
        if ($headingEl) {
            $anchor = $headingEl->find('a', 0);
            if ($anchor && $anchor->href) {
                return $anchor->href;
            }
            if (!empty($headingEl->id)) {
                return $baseUrl . '#' . $headingEl->id;
            }
        }

        // Check for anchor or ID in container
        if (!empty($el->id)) {
            return $baseUrl . '#' . $el->id;
        }

        $hashAnchor = $el->find('a[href*="#"]', 0);
        if ($hashAnchor && $hashAnchor->href) {
            return $hashAnchor->href;
        }

        $firstAnchor = $el->find('a', 0);
        if ($firstAnchor && $firstAnchor->href) {
            return $firstAnchor->href;
        }

        // Fallback: anchor with slugified title
        $slug = preg_replace('/[^a-z0-9]+/i', '-', strtolower($title));
        $slug = trim($slug, '-');
        return $baseUrl . ($slug ? '#' . $slug : '');
    }

    public function detectParameters($url)
    {
        $parsed = parse_url($url);
        $path = strtolower($parsed['path'] ?? '');
        $query = strtolower($parsed['query'] ?? '');

        // Match paths or query params indicating changelogs or releases
        if (preg_match('/(changelog|release|updates|whats-new|what-is-new|versions|history|announcements)/i', $path . '?' . $query)) {
            return ['url' => $url];
        }

        return null;
    }
}
