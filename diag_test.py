
import asyncio
from playwright.async_api import async_playwright

async def main():
    print("Starting Playwright diagnostic test...")
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        print("Navigating to localhost...")
        await page.goto("http://localhost:5000")
        title = await page.title()
        print(f"Page title: {title}")
        await browser.close()
    print("Playwright diagnostic test finished successfully.")

if __name__ == "__main__":
    asyncio.run(main())
