<?php

declare(strict_types=1);

class GenericChangelogBridge extends BridgeAbstract
{
    const NAME = 'Generic Changelog & Release Bridge';
    const URI = 'https://github.com/sheepdestroyer/SheepVibes';
    const DESCRIPTION = 'Automatically extracts changelog, release, and blog entries from arbitrary web pages';
    const MAINTAINER = 'SheepVibes';
    const CACHE_TIMEOUT = 1800;

    const PARAMETERS = [[
        'url' => [
            'name' => 'Page URL',
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

        // Mitigate SSRF: Validate that target resolves only to public, non-reserved IP addresses
        $parsed = parse_url($url);
        if (!$parsed || !isset($parsed['host'])) {
            throwClientException('Invalid target URL');
        }
        $host = $parsed['host'];
        $ips = gethostbynamel($host);
        if ($ips !== false) {
            foreach ($ips as $ip) {
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                    throwClientException('Target resolves to a private or reserved IP address');
                }
            }
        }

        $html = getSimpleHTMLDOM($url);
        if (!$html) {
            throwServerException('Could not load content from ' . $url);
        }

        // 1. Try structured JSON-LD schema (common in blogs and semantic documentation)
        $this->extractFromJsonLd($html, $url);
        if (!empty($this->items)) {
            return;
        }

        // 2. Try container-based entry extraction
        $this->extractFromContainers($html, $url);
        if (!empty($this->items)) {
            return;
        }

        // 3. Fallback to heading-delimited extraction
        $this->extractFromHeadings($html, $url);
    }

    private function extractFromJsonLd($html, string $baseUrl): void
    {
        foreach ($html->find('script[type="application/ld+json"]') as $script) {
            $raw = trim($script->innertext);
            $json = json_decode($raw, true);
            if (!$json || !is_array($json)) {
                continue;
            }

            // Normalize top-level arrays of JSON-LD objects
            $nodes = (isset($json[0]) && is_array($json[0])) ? $json : [$json];
            foreach ($nodes as $node) {
                if (!is_array($node)) {
                    continue;
                }

                // Case A: blogPost array (e.g. Lucebox and standard schema.org Blog)
                if (isset($node['blogPost']) && is_array($node['blogPost'])) {
                    foreach ($node['blogPost'] as $post) {
                        $item = $this->parseJsonLdItem($post, $baseUrl);
                        if ($item) {
                            $this->items[] = $item;
                        }
                    }
                }

                // Case B: ItemList with itemListElement array
                if (isset($node['itemListElement']) && is_array($node['itemListElement'])) {
                    foreach ($node['itemListElement'] as $element) {
                        $itemData = $element['item'] ?? $element;
                        if (is_array($itemData)) {
                            $item = $this->parseJsonLdItem($itemData, $baseUrl);
                            if ($item) {
                                $this->items[] = $item;
                            }
                        }
                    }
                }

                // Case C: Array in @graph
                if (isset($node['@graph']) && is_array($node['@graph'])) {
                    foreach ($node['@graph'] as $graphNode) {
                        $type = $graphNode['@type'] ?? '';
                        if (in_array($type, ['BlogPosting', 'Article', 'NewsArticle', 'TechArticle'])) {
                            $item = $this->parseJsonLdItem($graphNode, $baseUrl);
                            if ($item) {
                                $this->items[] = $item;
                            }
                        }
                    }
                }

                // Case D: Single BlogPosting / Article object
                $type = $node['@type'] ?? '';
                if (in_array($type, ['BlogPosting', 'Article', 'NewsArticle', 'TechArticle'])) {
                    $item = $this->parseJsonLdItem($node, $baseUrl);
                    if ($item) {
                        $this->items[] = $item;
                    }
                }
            }

            if (!empty($this->items)) {
                return;
            }
        }
    }

    private function parseJsonLdItem(array $data, string $baseUrl): ?array
    {
        $title = trim((string)($data['headline'] ?? $data['name'] ?? ''));
        if (empty($title)) {
            return null;
        }

        $uri = (string)($data['url'] ?? $baseUrl);
        $dateStr = $data['datePublished'] ?? $data['dateCreated'] ?? $data['dateModified'] ?? null;
        $timestamp = $dateStr ? strtotime((string)$dateStr) : time();
        $content = (string)($data['description'] ?? $data['articleBody'] ?? $title);

        $item = [
            'title' => $title,
            'uri' => defaultLinkTo($uri, $baseUrl),
            'timestamp' => $timestamp ?: time(),
            'content' => defaultLinkTo($content, $baseUrl),
            'uid' => defaultLinkTo($uri, $baseUrl),
        ];

        if (isset($data['image'])) {
            $img = is_array($data['image']) ? ($data['image']['url'] ?? '') : (string)$data['image'];
            if ($img) {
                $imgUrl = defaultLinkTo($img, $baseUrl);
                $item['enclosures'] = [$imgUrl];
                $item['content'] = '<p><img src="' . $imgUrl . '" /></p>' . $item['content'];
            }
        }

        return $item;
    }

    private function extractFromContainers($html, string $baseUrl): void
    {
        $candidateSelectors = [
            'article.changelog-entry',
            'div[data-section-row]',
            'div.section-row-wrapper',
            'a.post-card',
            'article.post-card',
            'div.post-card',
            'article[class*="changelog"]',
            'div[class*="changelog-entry"]',
            'div[class*="changelog-item"]',
            'div[class*="changelog__item"]',
            'div[class*="release-entry"]',
            'div[class*="release-item"]',
            'div[class*="release-card"]',
            '[class*="post-card"]',
            '[class*="article-card"]',
            '[class*="blog-card"]',
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
        // Find title heading or post-title class
        $headingEl = $el->find('h1, h2, h3, h4, h5, [class*="title"], [class*="heading"], [class*="version"], .post-title', 0);
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
        $excerptEl = $el->find('.post-excerpt, [class*="excerpt"], [class*="summary"], [class*="description"]', 0);
        $content = $excerptEl ? trim($excerptEl->plaintext) : trim($el->innertext);
        if (empty($content)) {
            $content = htmlspecialchars($title);
        }

        $item = [
            'title' => $title,
            'uri' => defaultLinkTo($uri, $baseUrl),
            'timestamp' => $timestamp ?: time(),
            'content' => defaultLinkTo($content, $baseUrl),
            'uid' => defaultLinkTo($uri, $baseUrl),
        ];

        // Check for card images
        $img = $el->find('img.post-card-img, img[class*="card"], img', 0);
        if ($img && $img->src) {
            $imgSrc = defaultLinkTo($img->src, $baseUrl);
            $item['enclosures'] = [$imgSrc];
            if (strpos($item['content'], $imgSrc) === false) {
                $item['content'] = '<p><img src="' . $imgSrc . '" /></p>' . $item['content'];
            }
        }

        return $item;
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
                if (preg_match('/(v?\d+\.\d+|\b(20\d\d[-\/.][01]\d[-\/.][0-3]\d)\b|release|changelog|update)/i', $text)) {
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
        if (preg_match('/\b(20\d\d[-\/.][01]\d[-\/.][0-3]\d)\b/', $textToSearch, $m)) {
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
        // Check if element itself is an anchor link (e.g. a.post-card)
        if ($el->tag === 'a' && $el->href) {
            return $el->href;
        }

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
        $host = strtolower($parsed['host'] ?? '');
        $path = strtolower($parsed['path'] ?? '');
        $query = strtolower($parsed['query'] ?? '');

        // Defer to official specialized bridges for major platforms
        if (in_array($host, ['github.com', 'www.github.com', 'gitlab.com', 'www.gitlab.com', 'youtube.com', 'www.youtube.com', 'reddit.com', 'www.reddit.com'])) {
            return null;
        }

        // Match paths or query params indicating changelogs, releases, blogs, or articles
        if (preg_match('/(changelog|release|updates|whats-new|what-is-new|versions|history|announcements|blog|news|articles|posts)/i', $path . '?' . $query)) {
            return ['url' => $url];
        }

        return null;
    }
}
