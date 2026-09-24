"""Screenshot the deployed dashboard for the deck and the report. Needs
playwright + chromium (pip install playwright && playwright install chromium).

    python -m scripts.screenshot_dashboard

Writes three figures to docs/figures/:
  dashboard_upload.png  the three upload boxes and the five signal cards
  dashboard.png         the ranked output with a finding expanded (Formula + ML)
  dashboard_detail.png  the per-finding breakdown on its own
"""
import asyncio
import subprocess
import sys
import time

from engine import config


async def _clip(pg, selector, out, max_h=820):
    box = await pg.evaluate("""(sel) => { const r = document.querySelector(sel).getBoundingClientRect();
                                          return {x: r.left + scrollX, y: r.top + scrollY, w: r.width, h: r.height}; }""",
                            selector)
    await pg.screenshot(path=out, full_page=True,
                        clip={"x": box["x"] - 10, "y": box["y"] - 10, "width": box["w"] + 20,
                              "height": min(box["h"], max_h) + 20})


async def shoot(url: str, out: str):
    from playwright.async_api import async_playwright
    async with async_playwright() as p:
        b = await p.chromium.launch()
        pg = await b.new_page(viewport={"width": 1280, "height": 900}, device_scale_factor=1.5)
        await pg.goto(url)
        await pg.wait_for_timeout(800)
        await _clip(pg, ".dropzones", str(config.FIGURES_DIR / "dashboard_upload.png"), 900)
        await pg.click("#btnSample")
        await pg.wait_for_selector("#findings .card")
        await pg.wait_for_timeout(600)
        await pg.click("#findings .card >> nth=0")
        await pg.wait_for_timeout(500)
        await _clip(pg, "#results", out, 780)
        await _clip(pg, "#findings .card.open .detail", str(config.FIGURES_DIR / "dashboard_detail.png"), 620)
        await b.close()


def main():
    port = 8799
    srv = subprocess.Popen([sys.executable, "-m", "http.server", str(port), "-d", str(config.SITE_DIR)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.0)
        out = config.FIGURES_DIR / "dashboard.png"
        asyncio.run(shoot(f"http://localhost:{port}/dashboard.html", str(out)))
        for f in ("dashboard_upload.png", "dashboard.png", "dashboard_detail.png"):
            print("wrote", config.FIGURES_DIR / f)
    finally:
        srv.terminate()


if __name__ == "__main__":
    main()
