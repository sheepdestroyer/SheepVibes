
import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()

        # Retry logic for connecting to localhost in case it takes a moment to start
        connected = False
        for i in range(5):
            try:
                await page.goto("http://localhost:5000")
                connected = True
                break
            except Exception as e:
                print(f"Connection attempt {i+1} failed: {e}")
                await asyncio.sleep(1)
        
        if not connected:
            print("Failed to connect to localhost:5000")
            await browser.close()
            exit(1)

        # Add a new tab
        await page.click("#add-tab-button")
        await page.keyboard.press("Enter")

        # Open the settings menu to access "Add Feed"
        await page.click("#settings-button")

        # Add the RSS feed
        # Using Google AI Blog as it usually has enough items
        # Wait for the input to be visible (it is inside the settings menu)
        await page.wait_for_selector("#feed-url-input", state="visible")
        await page.fill("#feed-url-input", "http://feeds.feedburner.com/blogspot/RLXA")
        await page.click("#add-feed-button")

        # Wait for the feed to load
        try:
            await page.wait_for_selector(".feed-widget", timeout=10000)
            await page.wait_for_selector(".feed-widget ul li", timeout=10000)
        except Exception as e:
            print(f"Timed out waiting for feed to load: {e}")
            await browser.close()
            exit(1)
        
        # Count initial items
        initial_items = await page.evaluate("document.querySelectorAll('.feed-widget ul li').length")
        print(f"Initial item count: {initial_items}")

        # Scroll window to the bottom to trigger infinite scroll
        print("Scrolling to bottom...")
        await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")

        # Wait for more items to load
        # We wait for the item count to increase
        try:
            await page.wait_for_function(
                f"document.querySelectorAll('.feed-widget ul li').length > {initial_items}",
                timeout=20000
            )
            print("New items loaded successfully!")
        except Exception as e:
            print(f"Timed out waiting for new items: {e}")
            
        # Verify
        final_items = await page.evaluate("document.querySelectorAll('.feed-widget ul li').length")
        print(f"Final item count: {final_items}")

        await browser.close()

        if final_items > initial_items:
            print("TEST PASSED: Item count increased.")
        else:
            print("TEST FAILED: Item count did not increase.")
            exit(1)

if __name__ == "__main__":
    asyncio.run(main())
