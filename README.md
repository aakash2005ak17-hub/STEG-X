# STEG-X — Multi-Media Steganography Lab

Educational research prototype for embedding, extracting and examining data in supported carrier formats.

## Features in this starter
- Image: PNG RGB LSB encode/decode.
- Audio: uncompressed PCM WAV 16-bit LSB encode/decode.
- Video: frame LSB with AVI/MJPEG output (OpenCV/FFmpeg required).
- Text: invisible Unicode-character payload.
- Documents: append/recover payload in PDF files.
- Network: append/recover payload in a UDP packet inside a PCAP capture (Scapy).
- Forensic triage: SHA-256, file signature, sampled byte entropy, printable ASCII ratio and marker check.

## Important limitations
This is a learning prototype, not a production security product. Basic LSB is fragile and detectable; do not use it for real secrets. JPEG/MP3/MP4 lossy recompression can destroy payloads. Audio supports PCM WAV only. Video encoding outputs AVI/MJPEG to preserve the modified frame bits. Document support is PDF only. Network support is a controlled PCAP lab demonstration, not a covert-network tool. The forensic analyzer is heuristic and cannot prove that steganography is present or absent. There is no user authentication, upload persistence, malware scanning, rate limiting or production hardening.

## Run locally (Windows / macOS / Linux)
1. Install Python 3.10 or newer.
2. Install FFmpeg if you plan to use video.
3. Create and activate a virtual environment:
   - Windows: `py -m venv .venv` then `.venv\Scripts\activate`
   - macOS/Linux: `python3 -m venv .venv` then `source .venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Start: `python app.py`
6. Open `http://127.0.0.1:5000`

For Scapy PCAP support, install Npcap on Windows if needed. No live packet capture is performed; upload a PCAP file you are authorized to inspect.

## Deploy online
This Flask app can be deployed to a Python host such as Render:
1. Push this folder to a GitHub repository.
2. In Render, create a new Web Service and connect the repository.
3. Render can detect `render.yaml`; use build command `pip install -r requirements.txt` and start command `gunicorn wsgi:app`.
4. Set a 100 MB upload limit or lower it to suit your host.
5. Test with non-sensitive sample files.

Online hosting is a shared server environment. Do not upload confidential evidence or real secrets. Use HTTPS, authentication, malware scanning, strict size limits, request timeouts, isolated processing, logging controls and a security review before any public launch. For safer use, keep sensitive work local.

## Suggested test files
- PNG image, PCM 16-bit WAV, short MP4 video, UTF-8 text file, sample PDF, and a PCAP containing at least one UDP packet.
- Start with short messages and keep an untouched copy of every original carrier.

## Project structure
```
stegx/
  __init__.py
  core.py
  routes.py
  templates/index.html
  static/style.css
  static/app.js
app.py
wsgi.py
requirements.txt
render.yaml
```
