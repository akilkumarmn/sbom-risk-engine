"""Screenshot the dashboard (sample data, Formula + ML mode, first finding
expanded) for the deck: docs/figures/dashboard.png. Needs playwright + chromium.

    python -m scripts.screenshot_dashboard
"""
import asyncio
import subprocess
import sys
import time

from engine import config


async def shoot(url: str, out: str):
    from playwright.async_api import async_playwright
    async with async_playwright() as p:
        b = await p.chromium.launch()
        pg = await b.new_page(viewport={"width": 1280, "height": 900}, device_scale_factor=1.5)
        await pg.goto(url)
        await pg.wait_for_timeout(800)
        await pg.click("#btnSample")
        await pg.wait_for_selector("#findings .card")
        await pg.wait_for_timeout(600)
        await pg.click("#findings .card >> nth=0")
        await pg.wait_for_timeout(500)
        box = await pg.evaluate("""() => { const r = document.getElementById('results').getBoundingClientRect();
                                           return {x: r.left + scrollX, y: r.top + scrollY, w: r.width, h: r.height}; }""")
        await pg.screenshot(path=out, full_page=True,
                            clip={"x": box["x"] - 10, "y": box["y"] - 10, "width": box["w"] + 20, "height": min(box["h"], 820)})
        await b.close()


def main():
    port = 8799
    srv = subprocess.Popen([sys.executable, "-m", "http.server", str(port), "-d", str(config.SITE_DIR)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.0)
        out = config.FIGURES_DIR / "dashboard.png"
        asyncio.run(shoot(f"http://localhost:{port}/dashboard.html", str(out)))
        print("wrote", out)
    finally:
        srv.terminate()


if __name__ == "__main__":
    main()
