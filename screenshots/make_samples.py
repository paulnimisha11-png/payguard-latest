"""Generates the demo payment screenshots (generic receipt design, not a copy of any real app)."""
import io, os
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
GF = "/usr/share/fonts/truetype/google-fonts/"
LIB = "/usr/share/fonts/truetype/liberation/"
def F(name, size): return ImageFont.truetype(name, size)
W, H = 1080, 2340
UTR_OK = "626921345678"   # year digit 6, day 269 (= 26 Sep 2026), hour 21

def receipt(amount="2,450", small_amount="2,450", status="Payment successful", utr=UTR_OK,
            date="26 Sep 2026, 9:40 pm", edit_amount=None):
    im = Image.new("RGB", (W, H), (255, 255, 255))
    d = ImageDraw.Draw(im)
    # status bar
    d.text((60, 40), "9:41", font=F(GF + "Poppins-Medium.ttf", 36), fill=(30, 30, 30))
    d.text((W - 200, 40), "5G  82%", font=F(GF + "Poppins-Medium.ttf", 32), fill=(30, 30, 30))
    # check mark
    ok = "success" in status
    col = (26, 150, 90) if ok else (225, 140, 20)
    d.ellipse((440, 260, 640, 460), fill=col)
    if ok:
        d.line((490, 365, 530, 405, 595, 320), fill="white", width=18, joint="curve")
    else:
        d.text((520, 290), "!", font=F(GF + "Poppins-Bold.ttf", 120), fill="white")
    d.text((W // 2, 540), status, font=F(GF + "Poppins-Medium.ttf", 52), fill=(20, 20, 20), anchor="mm")
    d.text((W // 2, 700), f"₹{amount}", font=F(GF + "Poppins-Bold.ttf", 130), fill=(20, 20, 20), anchor="mm")
    d.text((W // 2, 850), "Paid to", font=F(GF + "Poppins-Regular.ttf", 40), fill=(110, 110, 110), anchor="mm")
    d.text((W // 2, 920), "Sharma Stationery", font=F(GF + "Poppins-Medium.ttf", 52), fill=(20, 20, 20), anchor="mm")
    d.text((W // 2, 985), "sharma.stationery@okaxis", font=F(GF + "Poppins-Regular.ttf", 38), fill=(110, 110, 110), anchor="mm")
    # details card
    d.rounded_rectangle((60, 1100, W - 60, 1900), radius=36, fill=(244, 246, 250))
    rows = [("Amount", f"₹{small_amount}"), ("Date & time", date), ("UPI transaction ID", utr),
            ("From", "Rahul K  (XXXX 4821)"), ("Payment app", "UPI")]
    y = 1160
    for k, v in rows:
        d.text((110, y), k, font=F(GF + "Poppins-Regular.ttf", 38), fill=(110, 110, 110))
        d.text((110, y + 56), v, font=F(GF + "Poppins-Medium.ttf", 44), fill=(20, 20, 20))
        y += 150
    d.text((W // 2, 2050), "Share receipt", font=F(GF + "Poppins-Medium.ttf", 44), fill=(40, 90, 200), anchor="mm")
    if edit_amount:
        # paint over the headline amount with a near-white patch and type a new number in another font
        d.rectangle((250, 620, 830, 785), fill=(250, 250, 248))
        d.text((W // 2, 700), f"₹{edit_amount}", font=F(LIB + "LiberationSans-Bold.ttf", 128), fill=(40, 40, 40), anchor="mm")
    return im

def save(im, name, **kw):
    im.save(os.path.join(HERE, name), **kw)

save(receipt(), "genuine_receipt.png")
save(receipt(edit_amount="24,500"), "fake_edited_amount.png")
save(receipt(status="Payment pending"), "fake_pending.png")
def redrawn(utr=UTR_OK):
    """Simulates an AI/editor re-render: same receipt, but every digit of the reference number is drawn separately
    with a random sub-pixel vertical offset (what regenerated text looks like under the glyph-consistency check)."""
    import random
    random.seed(7)
    big = receipt(utr="").resize((W * 4, H * 4), Image.LANCZOS)
    d = ImageDraw.Draw(big)
    f = F(GF + "Poppins-Medium.ttf", 44 * 4)
    x = 110 * 4
    for ch in utr:
        d.text((x, (1160 + 2 * 150 + 56) * 4 + random.choice([-2, -1, 1, 2])), ch, font=f, fill=(20, 20, 20))
        x += int(d.textlength(ch, font=f))
    return big.resize((W, H), Image.LANCZOS)
save(redrawn("626921346629"), "fake_redrawn_digits.png")
ex = Image.Exif(); ex[305] = "Adobe Photoshop 25.0 (Windows)"
save(receipt(), "fake_photoshop.jpg", quality=92, exif=ex.tobytes())
buf = io.BytesIO(); receipt().save(buf, "JPEG", quality=70)   # what WhatsApp does: recompress, strip metadata
save(Image.open(io.BytesIO(buf.getvalue())), "genuine_whatsapp_forwarded.jpg", quality=70)
print("ok")
