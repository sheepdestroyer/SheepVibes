<?php

declare(strict_types=1);

class LuceboxBridge extends BridgeAbstract
{
    const NAME = 'Lucebox Blog';
    const URI = 'https://www.lucebox.com/blog';
    const DESCRIPTION = 'Returns recent blog posts from lucebox.com/blog';
    const MAINTAINER = 'SheepVibes';
    const CACHE_TIMEOUT = 1800;

    const PARAMETERS = [[
        'url' => [
            'name' => 'Blog URL',
            'type' => 'text',
            'required' => false,
            'defaultValue' => 'https://www.lucebox.com/blog',
        ],
    ]];

    public function collectData()
    {
        $url = $this->getInput('url') ?: self::URI;
        $html = getSimpleHTMLDOM($url);
        if (!$html) {
            throwServerException('Could not load content from ' . $url);
        }

        // Try extracting from JSON-LD schema first
        foreach ($html->find('script[type="application/ld+json"]') as $script) {
            $json = json_decode($script->innertext, true);
            if (isset($json['blogPost']) && is_array($json['blogPost'])) {
                foreach ($json['blogPost'] as $post) {
                    $item = [];
                    $item['title'] = $post['headline'] ?? 'Untitled';
                    $item['uri'] = $post['url'] ?? $url;
                    $item['timestamp'] = isset($post['datePublished']) ? strtotime($post['datePublished']) : time();
                    $item['content'] = $post['description'] ?? $item['title'];
                    $item['uid'] = $item['uri'];
                    $this->items[] = $item;
                }
                return;
            }
        }

        // Fallback to HTML post-card elements
        foreach ($html->find('a.post-card') as $card) {
            $item = [];
            $titleEl = $card->find('.post-title', 0);
            $item['title'] = $titleEl ? trim($titleEl->plaintext) : 'Untitled';
            $item['uri'] = defaultLinkTo($card->href, $url);
            $excerptEl = $card->find('.post-excerpt', 0);
            $item['content'] = $excerptEl ? trim($excerptEl->plaintext) : '';
            $imgEl = $card->find('img.post-card-img', 0);
            if ($imgEl && $imgEl->src) {
                $imgSrc = defaultLinkTo($imgEl->src, $url);
                $item['enclosures'] = [$imgSrc];
                $item['content'] = '<p><img src="' . $imgSrc . '" /></p>' . $item['content'];
            }
            $item['uid'] = $item['uri'];
            $this->items[] = $item;
        }
    }

    public function detectParameters($url)
    {
        $parsed = parse_url($url);
        $host = strtolower($parsed['host'] ?? '');
        if ($host !== 'lucebox.com' && $host !== 'www.lucebox.com') {
            return null;
        }
        $path = $parsed['path'] ?? '';
        if (strpos($path, '/blog') === 0 || $path === '' || $path === '/') {
            return ['url' => 'https://www.lucebox.com/blog'];
        }
        return null;
    }
}
