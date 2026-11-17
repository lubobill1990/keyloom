import argparse
import math
from pathlib import Path

from PIL import Image, ImageOps


ROOT = Path(__file__).resolve().parent.parent
BRAND = ROOT / "assets" / "brand"
ICO_SIZES = [(size, size) for size in (16, 24, 32, 48, 64, 128, 256)]


def build() -> None:
    with Image.open(BRAND / "icon-source.png") as original:
        source = original.convert("RGB")
    mask = ImageOps.grayscale(source).point(lambda value: 255 if value > 150 else 0)
    bounds = mask.getbbox()
    if not bounds:
        raise ValueError("The generated icon has no readable foreground.")
    left, top, right, bottom = bounds
    size = min(min(source.size), math.ceil(max(right - left, bottom - top) / 0.76))
    x = max(0, min(source.width - size, round((left + right - size) / 2)))
    y = max(0, min(source.height - size, round((top + bottom - size) / 2)))
    normalized = source.crop((x, y, x + size, y + size)).resize((1024, 1024), Image.Resampling.LANCZOS)
    normalized.resize((512, 512), Image.Resampling.LANCZOS).save(BRAND / "icon.png", optimize=True)
    normalized.save(BRAND / "icon.ico", sizes=ICO_SIZES)

    with Image.open(BRAND / "banner-source.png") as original:
        banner = original.convert("RGB")
    foreground = ImageOps.grayscale(banner).point(lambda value: 255 if value < 210 else 0)
    bounds = foreground.getbbox()
    if not bounds:
        raise ValueError("The generated banner has no readable content.")
    height = round(banner.width / 4.8)
    center = (bounds[1] + bounds[3]) / 2
    y = max(0, min(banner.height - height, round(center - height / 2)))
    if bounds[1] < y or bounds[3] > y + height:
        raise ValueError("Banner crop would cut meaningful content.")
    banner.crop((0, y, banner.width, y + height)).save(BRAND / "readme-banner.png", optimize=True)

    limit = round(banner.width * 0.61)
    active = [foreground.crop((0, row, limit, row + 1)).getbbox() is not None for row in range(banner.height)]
    start = next(index for index, value in enumerate(active) if value)
    end = start
    while end < len(active) and active[end]:
        end += 1
    if end - start < 40:
        raise ValueError("Cannot isolate the generated wordmark safely.")
    band = foreground.crop((0, start, limit, end))
    box = band.getbbox()
    if not box:
        raise ValueError("Wordmark crop is empty.")
    cropped = banner.crop((box[0], start, box[2], end))
    logo = Image.new("RGB", (cropped.width + 64, cropped.height + 64), "white")
    logo.paste(cropped, (32, 32))
    logo.save(BRAND / "logo.png", optimize=True)


def check() -> None:
    with Image.open(BRAND / "icon.png") as icon:
        if icon.size != (512, 512):
            raise ValueError("Unexpected application icon dimensions.")
    with Image.open(BRAND / "icon.ico") as icon:
        if not set(ICO_SIZES) <= icon.ico.sizes():
            raise ValueError("The Windows icon is missing required DPI sizes.")
    with Image.open(BRAND / "readme-banner.png") as banner:
        if banner.width / banner.height < 4:
            raise ValueError("README banner is not the expected shallow layout.")
    for filename in ("logo.png", "icon-source.png", "banner-source.png"):
        with Image.open(BRAND / filename) as image:
            image.verify()
    print("Brand assets verified: original sources, wordmark, 512px icon, multi-size ICO, shallow README banner.")


if __name__ == "__main__":
    arguments = argparse.ArgumentParser()
    arguments.add_argument("--check", action="store_true")
    options = arguments.parse_args()
    if not options.check:
        build()
    check()
