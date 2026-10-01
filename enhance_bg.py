# enhance_bg.py  — run once, outputs static/img/campus_bg.jpg
from PIL import Image, ImageEnhance, ImageFilter

SRC = "static/img/campus_original.jpg"
DST = "static/img/campus_bg.jpg"

img = Image.open(SRC).convert("RGB")

# 1. Upscale with high-quality resampling (works well for architectural photos)
target_w = 1920
ratio = target_w / img.width
img = img.resize((target_w, int(img.height * ratio)), Image.LANCZOS)

# 2. Mild pre-blur to kill JPEG artifacts from the low-res source
img = img.filter(ImageFilter.GaussianBlur(radius=1.0))

# 3. Enhance: color, contrast, sharpness, brightness
img = ImageEnhance.Color(img).enhance(1.35)        # richer sandstone
img = ImageEnhance.Contrast(img).enhance(1.15)     # define shadow/light
img = ImageEnhance.Brightness(img).enhance(1.05)   # lift the haze
img = ImageEnhance.Sharpness(img).enhance(1.4)     # crisp edges

# 4. Optional: warm the highlights slightly (heritage building feel)
r, g, b = img.split()
r = r.point(lambda v: min(255, int(v * 1.03)))
b = b.point(lambda v: int(v * 0.97))
img = Image.merge("RGB", (r, g, b))

# 5. Save optimized for web
img.save(DST, "JPEG", quality=82, optimize=True, progressive=True)
print(f"✓ Saved {DST} ({img.size[0]}x{img.size[1]})")