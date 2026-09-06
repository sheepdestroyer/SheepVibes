<?php

declare(strict_types=1);

class AntigravityChangelogBridge extends BridgeAbstract
{
    const NAME = 'Antigravity Changelog';
    const URI = 'https://antigravity.google/changelog';
    const DESCRIPTION = 'Returns recent changelog updates from Antigravity';
    const MAINTAINER = 'SheepVibes';
    const CACHE_TIMEOUT = 1800;

    const PARAMETERS = [[
        'url' => [
            'name' => 'Changelog URL',
            'type' => 'text',
            'required' => false,
            'defaultValue' => 'https://antigravity.google/changelog',
        ],
    ]];

    public function collectData()
    {
        $url = $this->getInput('url') ?: self::URI;
        $html = getSimpleHTMLDOM($url);
        if (!$html) {
            throwServerException('Could not load content from ' . $url);
        }

        // Find each changelog section row
        foreach ($html->find('div[data-section-row], div.section-row-wrapper') as $row) {
            $titleEl = $row->find('h3[data-h3-pin], h3.heading-7', 0);
            if (!$titleEl) {
                continue;
            }
            $title = trim($titleEl->plaintext);

            // Version and date
            $versionEl = $row->find('a.version-link', 0);
            $version = $versionEl ? trim($versionEl->plaintext) : '';
            $versionHref = $versionEl ? $versionEl->href : '';

            $date = null;
            $versionDiv = $row->find('div.version', 0);
            if ($versionDiv) {
                $versionText = $versionDiv->plaintext;
                if (preg_match('/([A-Za-z]+\s+\d{1,2},\s+\d{4})/', $versionText, $m)) {
                    $date = strtotime($m[1]);
                }
            }

            // Description / content
            $content = '';
            $descDiv = $row->find('div.description', 0);
            if ($descDiv) {
                $changesDiv = $descDiv->find('div.changes', 0);
                if ($changesDiv) {
                    $content .= $changesDiv->innertext;
                }
                $expandable = $descDiv->find('div.expandable-items', 0);
                if ($expandable) {
                    $content .= $expandable->innertext;
                }
            }
            if (empty($content)) {
                $content = $title;
            }

            $item = [];
            $item['title'] = $version ? "[$version] $title" : $title;
            $item['uri'] = $versionHref ? defaultLinkTo($versionHref, self::URI) : self::URI . '#' . urlencode($title);
            $item['timestamp'] = $date ?: time();
            $item['content'] = defaultLinkTo($content, self::URI);
            $item['uid'] = $item['uri'];
            $this->items[] = $item;
        }
    }

    public function detectParameters($url)
    {
        $parsed = parse_url($url);
        $host = strtolower($parsed['host'] ?? '');
        if ($host !== 'antigravity.google') {
            return null;
        }
        $path = $parsed['path'] ?? '';
        if (strpos($path, '/changelog') === 0 || strpos($path, '/releases') === 0 || $path === '' || $path === '/') {
            return ['url' => 'https://antigravity.google/changelog'];
        }
        return null;
    }
}
