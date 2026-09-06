<?php

declare(strict_types=1);

class JulesChangelogBridge extends BridgeAbstract
{
    const NAME = 'Jules Changelog';
    const URI = 'https://jules.google/docs/changelog/';
    const DESCRIPTION = 'Returns recent changelog updates from Google Jules';
    const MAINTAINER = 'SheepVibes';
    const CACHE_TIMEOUT = 1800;

    const PARAMETERS = [[
        'url' => [
            'name' => 'Changelog URL',
            'type' => 'text',
            'required' => false,
            'defaultValue' => 'https://jules.google/docs/changelog/',
        ],
    ]];

    public function collectData()
    {
        $url = $this->getInput('url') ?: self::URI;
        $html = getSimpleHTMLDOM($url);
        if (!$html) {
            throwServerException('Could not load content from ' . $url);
        }

        foreach ($html->find('article.changelog-entry') as $article) {
            $titleEl = $article->find('h2.title', 0);
            if (!$titleEl) {
                continue;
            }
            $title = trim($titleEl->plaintext);
            $titleId = $titleEl->id ?? '';

            $dateEl = $article->find('span.date', 0);
            $date = $dateEl ? strtotime(trim($dateEl->plaintext)) : time();

            // Link can use anchor id
            $uri = $titleId ? self::URI . '#' . $titleId : self::URI;

            // Content is article innertext without the header
            $header = $article->find('header', 0);
            $content = $article->innertext;
            if ($header) {
                $content = str_replace($header->outertext, '', $content);
            }
            $content = trim($content);
            if (empty($content)) {
                $content = $title;
            }

            $item = [];
            $item['title'] = $title;
            $item['uri'] = $uri;
            $item['timestamp'] = $date;
            $item['content'] = defaultLinkTo($content, self::URI);
            $item['uid'] = $uri;
            $this->items[] = $item;
        }
    }

    public function detectParameters($url)
    {
        $parsed = parse_url($url);
        $host = strtolower($parsed['host'] ?? '');
        if ($host !== 'jules.google') {
            return null;
        }
        $path = $parsed['path'] ?? '';
        if (strpos($path, '/docs/changelog') === 0 || $path === '' || $path === '/') {
            return ['url' => 'https://jules.google/docs/changelog/'];
        }
        return null;
    }
}
