# Third-party components and credits

PayGuard's own code is under the MIT License (see `LICENSE`). It uses the components below, each under its own
license. Nothing here is copied into our source files except where marked "bundled".

## Python libraries (installed with `pip install -r requirements.txt`, not bundled)
| Library | License | Used for |
|---|---|---|
| [FastAPI](https://github.com/fastapi/fastapi) | MIT | Web server / API |
| [Uvicorn](https://github.com/encode/uvicorn) | BSD-3-Clause | ASGI server |
| [python-multipart](https://github.com/Kludex/python-multipart) | Apache-2.0 | File uploads |
| [HTTPX](https://github.com/encode/httpx) | BSD-3-Clause | HTTP client (VirusTotal, Claude API, Web Push) |
| [Androguard](https://github.com/androguard/androguard) | Apache-2.0 | Reading APK manifests and certificates |
| [OpenCV (opencv-python-headless)](https://github.com/opencv/opencv-python) | Apache-2.0 | QR decoding, image processing |
| [NumPy](https://numpy.org) | BSD-3-Clause (and others, see package) | Image arrays |
| [Pillow](https://python-pillow.org) | MIT-CMU (HPND) | Image handling |
| [RapidOCR (rapidocr_onnxruntime)](https://github.com/RapidAI/RapidOCR) | Apache-2.0 | Text reading in payment screenshots; ships PaddleOCR PP-OCRv3 models ([PaddleOCR](https://github.com/PaddlePaddle/PaddleOCR), Apache-2.0) |
| [ONNX Runtime](https://github.com/microsoft/onnxruntime) | MIT | Runs the OCR models |
| [pytesseract](https://github.com/madmaze/pytesseract) | Apache-2.0 | Fallback OCR wrapper |
| [ReportLab](https://www.reportlab.com/opensource/) | BSD | Evidence PDF for complaints |
| [qrcode](https://github.com/lincolnloop/python-qrcode) | BSD | Payment / join QR images |
| [scikit-learn](https://scikit-learn.org) | BSD-3-Clause | Training the UPI scam model only (`requirements-ml.txt`); not used on the server |
| [cryptography](https://github.com/pyca/cryptography) | Apache-2.0 OR BSD-3-Clause | Web Push encryption and signing |
| [psycopg 3 (psycopg[binary])](https://github.com/psycopg/psycopg) | LGPL-3.0-only | Postgres driver for accounts (used as an unmodified library) |
| [clerk-backend-api](https://github.com/clerk/clerk-sdk-python) (with [PyJWT](https://github.com/jpadilla/pyjwt)) | MIT | Verifying Clerk session tokens, Clerk Backend API |
| [ClerkJS (`@clerk/clerk-js`, `@clerk/ui`)](https://github.com/clerk/javascript) | MIT | Sign-in / sign-up form; loaded from Clerk's CDN at run time, not bundled |

## Web fonts (loaded from Google Fonts, not bundled)
| Font | License | Used for |
|---|---|---|
| [Orbitron](https://fonts.google.com/specimen/Orbitron) | SIL Open Font License 1.1 | Headings on the landing, sign-in and app pages |
| [Inter](https://fonts.google.com/specimen/Inter), [JetBrains Mono](https://fonts.google.com/specimen/JetBrains+Mono), Noto Sans (Devanagari, Kannada, Tamil, Telugu, Bengali) | SIL Open Font License 1.1 | Body text, code-style text, Indian scripts |

## Services (optional, configured by environment variables)
| Service | Used for |
|---|---|
| [Supabase](https://supabase.com) (hosted Postgres) or any Postgres | Storing accounts |
| [Clerk](https://clerk.com) | Sign-in (Google, email), email verification, password recovery |
| [Brevo](https://www.brevo.com) or [Resend](https://resend.com) email API | Welcome, sign-in alert and password emails |
| [Google Gemini API](https://ai.google.dev) | Optional AI explanation of APK scan results (only extracted metadata is sent) |

## Artwork
The hooded figure, shield logo, warp-speed light rays, matrix rain and all other visuals are original SVG/canvas drawings
made for this project (no stock or third-party images; a stock photo was looked at only as a pose/mood reference and nothing from it is included). UI effects (3D tilt cards, spotlight, decrypting text, magnetic buttons)
are our own vanilla JS/CSS implementations inspired by common web-design patterns; no code was copied from UI kits.

## System programs (installed in the Docker image with apt, not bundled)
| Program | License | Used for |
|---|---|---|
| [Tesseract OCR](https://github.com/tesseract-ocr/tesseract) | Apache-2.0 | Fallback OCR engine |
| [eSpeak NG](https://github.com/espeak-ng/espeak-ng) | GPL-3.0-or-later | Server "read aloud" voice for languages the phone has no voice for. Run as a separate program; PayGuard does not link to it. |

## Bundled in this repository
| File(s) | Source | License |
|---|---|---|
| `static/vendor/jsQR.js` | [jsQR](https://github.com/cozmo/jsQR) by Cosmo Wolfe | Apache-2.0 (`static/vendor/jsQR.LICENSE`) |
| `static/vendor/lenis.min.js` | [Lenis](https://github.com/darkroom-engineering/lenis) smooth scroll by darkroom.engineering | MIT (`static/vendor/lenis.LICENSE`) |
| `tests/fonts/Poppins-*.ttf` | [Poppins](https://github.com/itfoundry/Poppins), The Poppins Project Authors | SIL Open Font License 1.1 (`tests/fonts/OFL.txt`); used only to draw synthetic test receipts |
| `samples/a2dp.Vol_137.apk` | [A2DP Volume](https://github.com/jroal/a2dpvolume) by Jim Roal, via [F-Droid](https://f-droid.org/en/packages/a2dp.Vol/) | GPL-3.0-only; unmodified binary used as a known-benign test input |
| `samples/com.politedroid_4.apk` | [Polite Droid](https://github.com/miguelvps/PoliteDroid), from the [F-Droid server test repo](https://github.com/f-droid/fdroidserver/tree/master/tests/repo) | GPL-3.0-only; unmodified binary used as a known-benign test input |
| `samples/com.teleca.jamendo_35.apk` | [Jamendo for Android](https://github.com/telecapoland/jamendo-android) by Teleca Poland | Apache-2.0; unmodified binary used as a known-benign test input |
| `samples/Courier_Delivery_Update.apk`, `samples/qr/*`, `samples/screenshots/*` | Made by the PayGuard team (inert fixtures; no real malware, no real person's data) | MIT, like the rest of the project |

The GPL-3.0 sample apps are redistributed unmodified; their source code is available at the links above.

## Loaded by the website at run time (not bundled)
| Resource | License |
|---|---|
| [Inter](https://github.com/rsms/inter), [Noto Sans Devanagari / Kannada](https://github.com/notofonts), [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono) via Google Fonts | SIL Open Font License 1.1 |

## Android app
| Component | License / terms |
|---|---|
| [Google code scanner (`play-services-code-scanner`)](https://developers.google.com/ml-kit/vision/barcode-scanning/code-scanner) | [Google APIs Terms of Service](https://developers.google.com/terms) and the [ML Kit terms](https://developers.google.com/ml-kit/terms) (not open source; used as a dependency, not bundled in this repo) |
| Android SDK / Gradle Android plugin | Android Software Development Kit License / Apache-2.0 |

## Optional online services (off unless you set an API key)
| Service | Terms |
|---|---|
| Anthropic Claude API (`ANTHROPIC_API_KEY`) for the family WhatsApp message | [Anthropic commercial terms](https://www.anthropic.com/legal/commercial-terms) |
| VirusTotal (`VT_API_KEY`) hash lookup | [Google Cloud / VirusTotal terms](https://cloud.google.com/terms) |
| Web Push delivery (browser vendors' push services) | Standard Web Push protocol (RFC 8030 / 8291 / 8292) |

## Development tools
Parts of this project were written with the help of an AI coding assistant (Anthropic's Claude). The team
reviewed, tested, deployed and changed the code, and is responsible for it.
