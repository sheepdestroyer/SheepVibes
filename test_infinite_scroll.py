
import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()

        # Capture console logs
        page.on("console", lambda msg: print(f"CONSOLE: {msg.text()}"))

        # Capture network requests
        async def log_request(route, request):
            if "/api/feeds/" in request.url and "/items" in request.url:
                print(f"NETWORK: {request.method} {request.url}")
            await route.continue_()

        await page.route("**/*", log_request)

        await page.goto("http://localhost:5000")

        # Add a new tab
        await page.click("#add-tab-button")
        await page.keyboard.press("Enter")

        # Add the RSS feed
        await page.fill("#feed-url-input", "http://feeds.feedburner.com/blogspot/RLXA")
        await page.click("#add-feed-button")

        # Wait for the feed to load
        await page.wait_for_selector(".feed-widget")

        # Scroll to the bottom of the feed
        await page.evaluate("document.querySelector('.feed-widget ul').scrollTop = document.querySelector('.feed-widget ul').scrollHeight")

        # Wait for a moment to see if more items are loaded
        await asyncio.sleep(2)

        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
