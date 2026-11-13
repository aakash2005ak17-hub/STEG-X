import io, os, re, json, math, struct, hashlib, zipfile, tempfile, subprocess
from pathlib import Path
from PIL import Image
import numpy as np

MARK = b"\nSTEGX_PAYLOAD_V1:"
TEXT_MARK = "\u2063\u2064"
def pack(data: bytes) -> bytes:
    return MARK + str(len(data)).encode() + b":" + data
def unpack(blob: bytes) -> bytes:
    i = blob.rfind(MARK)
    if i < 0: raise ValueError("No STEG-X payload marker found.")
    tail = blob[i+len(MARK):]
    n, sep, payload = tail.partition(b":")
    if not sep or not n.isdigit(): raise ValueError("Invalid payload marker.")
    size = int(n)
    if len(payload) < size: raise ValueError("Payload is truncated.")
    return payload[:size]
def bits(data):
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))
def unbits(arr):
    arr = np.asarray(arr, dtype=np.uint8)
    arr = arr[:len(arr)//8*8]
    return np.packbits(arr).tobytes()

def image_encode(raw, message):
    im = Image.open(io.BytesIO(raw)).convert("RGB")
    a = np.array(im, dtype=np.uint8)
    payload = pack(message.encode("utf-8"))
    b = bits(payload)
    flat = a.reshape(-1)
    if len(b) > flat.size: raise ValueError("Message too large for this image.")
    flat[:len(b)] = (flat[:len(b)] & 254) | b
    out = io.BytesIO()
    Image.fromarray(a).save(out, format="PNG")
    return out.getvalue()
def image_decode(raw):
    a = np.array(Image.open(io.BytesIO(raw)).convert("RGB"), dtype=np.uint8).reshape(-1)
    # Header is variable; scan LSB stream in bounded chunks for marker.
    stream = unbits(a & 1)
    return unpack(stream).decode("utf-8")

def wav_encode(raw, message):
    import soundfile as sf
    audio, rate = sf.read(io.BytesIO(raw), dtype="int16", always_2d=True)
    payload = pack(message.encode("utf-8"))
    b = bits(payload)
    flat = audio.reshape(-1)
    if len(b) > flat.size: raise ValueError("Message too large for this WAV file.")
    flat[:len(b)] = (flat[:len(b)] & np.int16(0xFFFE)) | b.astype(np.int16)
    out = io.BytesIO()
    sf.write(out, audio, rate, format="WAV", subtype="PCM_16")
    return out.getvalue()
def wav_decode(raw):
    import soundfile as sf
    audio, _ = sf.read(io.BytesIO(raw), dtype="int16", always_2d=True)
    return unpack(unbits(audio.reshape(-1) & 1)).decode("utf-8")

def text_encode(raw, message):
    text = raw.decode("utf-8")
    payload = pack(message.encode("utf-8"))
    encoded = "".join(f"{x:08b}" for x in payload)
    # Each bit represented by one of two invisible Unicode format characters.
    hidden = "".join(TEXT_MARK[0] if x == "0" else TEXT_MARK[1] for x in encoded)
    return (text + hidden).encode("utf-8")
def text_decode(raw):
    text = raw.decode("utf-8")
    hidden = re.findall(f"[{TEXT_MARK[0]}{TEXT_MARK[1]}]", text)
    if not hidden: raise ValueError("No STEG-X invisible-character payload found.")
    stream = bytes(0 for _ in [])  # marker reconstruction below
    bitstr = "".join("0" if c == TEXT_MARK[0] else "1" for c in hidden)
    data = bytes(int(bitstr[i:i+8], 2) for i in range(0, len(bitstr)-7, 8))
    return unpack(data).decode("utf-8")

def pdf_encode(raw, message):
    if not raw.startswith(b"%PDF-"): raise ValueError("Document carrier must be a PDF.")
    return raw + pack(message.encode("utf-8"))
def pdf_decode(raw):
    return unpack(raw).decode("utf-8")

def video_encode(raw, message):
    # Requires OpenCV/FFmpeg support. Output is AVI/FFV1 (lossless) to preserve embedded bits.
    import cv2
    src = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False); src.write(raw); src.close()
    cap = cv2.VideoCapture(src.name)
    if not cap.isOpened():
        os.unlink(src.name); raise ValueError("Could not read video. Try a standard MP4.")
    fps = cap.get(cv2.CAP_PROP_FPS) or 24
    w, h = int(cap.get(3)), int(cap.get(4))
    frames = []
    while True:
        ok, frame = cap.read()
        if not ok: break
        frames.append(frame)
    cap.release(); os.unlink(src.name)
    if not frames: raise ValueError("Video contains no readable frames.")
    payload = pack(message.encode("utf-8")); b = bits(payload)
    capacity = frames[0].shape[0] * frames[0].shape[1] * 3 * len(frames)
    if len(b) > capacity: raise ValueError("Message too large for this video's frame capacity.")
    # Spread data across the concatenated frame pixel stream.
    pos = 0
    for frame in frames:
        flat = frame.reshape(-1)
        take = min(len(b)-pos, flat.size)
        if take > 0:
            flat[:take] = (flat[:take] & 254) | b[pos:pos+take]
            pos += take
        if pos >= len(b): break
    outpath = tempfile.NamedTemporaryFile(suffix=".avi", delete=False).name
    writer = cv2.VideoWriter(outpath, cv2.VideoWriter_fourcc(*"FFV1"), fps, (w,h))
    for f in frames: writer.write(f)
    writer.release()
    data = Path(outpath).read_bytes(); os.unlink(outpath)
    return data
def video_decode(raw):
    import cv2
    src = tempfile.NamedTemporaryFile(suffix=".avi", delete=False); src.write(raw); src.close()
    cap = cv2.VideoCapture(src.name); chunks=[]
    while True:
        ok, frame=cap.read()
        if not ok: break
        chunks.append(frame.reshape(-1) & 1)
    cap.release(); os.unlink(src.name)
    if not chunks: raise ValueError("Could not decode video frames.")
    return unpack(unbits(np.concatenate(chunks))).decode("utf-8")

def pcap_encode(raw, message):
    from scapy.all import rdpcap, wrpcap, UDP, Raw
    packets = rdpcap(io.BytesIO(raw))
    payload = pack(message.encode("utf-8"))
    for p in packets:
        if UDP in p:
            old = bytes(p[UDP].payload)
            p[UDP].remove_payload()
            p[UDP].add_payload(Raw(old + payload))
            break
    else: raise ValueError("No UDP packet found in capture.")
    out=io.BytesIO(); wrpcap(out, packets); return out.getvalue()
def pcap_decode(raw):
    from scapy.all import rdpcap, Raw, UDP
    packets=rdpcap(io.BytesIO(raw))
    for p in packets:
        if UDP in p and Raw in p:
            try: return unpack(bytes(p[Raw])).decode("utf-8")
            except Exception: pass
    raise ValueError("No STEG-X payload found in UDP packet data.")

def analyze(raw, filename):
    sample=raw[:min(len(raw), 2_000_000)]
    counts=np.bincount(np.frombuffer(sample,dtype=np.uint8), minlength=256)
    probs=counts[counts>0]/max(1,counts.sum())
    entropy=float(-(probs*np.log2(probs)).sum())
    printable=sum(32 <= b < 127 or b in (9,10,13) for b in sample)
    return {
      "filename": filename, "size_bytes": len(raw),
      "sha256": hashlib.sha256(raw).hexdigest(),
      "entropy_bits_per_byte": round(entropy,4),
      "printable_ascii_ratio": round(printable/max(1,len(sample)),4),
      "known_stegx_marker": MARK.decode("ascii", errors="ignore") in raw.decode("latin1"),
      "file_signature": raw[:16].hex(" "),
      "warning": "Heuristic triage only. High entropy or unusual structure does not prove steganography."
    }
