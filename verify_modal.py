
import asyncio
from playwright.async_api import async_playwright, expect

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        try:
            await page.goto("http://localhost:8000", timeout=10000)

            # Wait for the modal element to be in the DOM
            modal = page.locator("#edit-feed-modal")
            await modal.wait_for(state="attached", timeout=5000)

            # The core of the bug fix: ensure the modal is hidden by default.
            print("Checking if modal is visible...")
            is_visible = await modal.is_visible()
            if is_visible:
                raise AssertionError("Test Failed: Edit feed modal is visible by default.")
            else:
                print("Test Passed: Edit feed modal is hidden by default.")

        except Exception as e:
            print(f"An error occurred: {e}")
            await page.screenshot(path="verify_error.png", full_page=True)
            print("Screenshot saved to verify_error.png")
            raise  # Re-raise the exception to fail the script
        finally:
            await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
