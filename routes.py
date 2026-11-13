from flask import Blueprint, render_template, request, send_file, jsonify
from werkzeug.utils import secure_filename
from . import core
import io
bp=Blueprint("main", __name__)

@bp.get("/")
def home(): return render_template("index.html")

@bp.post("/api/hide")
def hide():
    f=request.files.get("file"); message=request.form.get("message","")
    kind=request.form.get("kind","image")
    if not f or not message: return jsonify(error="Choose a carrier file and enter a message."),400
    raw=f.read()
    try:
        fn=secure_filename(f.filename or "carrier")
        funcs={"image":core.image_encode,"audio":core.wav_encode,"video":core.video_encode,
               "text":core.text_encode,"document":core.pdf_encode,"network":core.pcap_encode}
        if kind not in funcs: raise ValueError("Unsupported module.")
        result=funcs[kind](raw,message)
        ext={"image":"png","audio":"wav","video":"avi","text":"txt","document":"pdf","network":"pcap"}[kind]
        return send_file(io.BytesIO(result), as_attachment=True, download_name=f"stegx_encoded.{ext}", mimetype="application/octet-stream")
    except Exception as e: return jsonify(error=str(e)),400

@bp.post("/api/extract")
def extract():
    f=request.files.get("file"); kind=request.form.get("kind","image")
    if not f: return jsonify(error="Choose an encoded carrier file."),400
    funcs={"image":core.image_decode,"audio":core.wav_decode,"video":core.video_decode,
           "text":core.text_decode,"document":core.pdf_decode,"network":core.pcap_decode}
    try:
        if kind not in funcs: raise ValueError("Unsupported module.")
        return jsonify(message=funcs[kind](f.read()))
    except Exception as e: return jsonify(error=str(e)),400

@bp.post("/api/analyze")
def analyze():
    f=request.files.get("file")
    if not f: return jsonify(error="Choose a file to analyze."),400
    try: return jsonify(core.analyze(f.read(), f.filename or "uploaded-file"))
    except Exception as e: return jsonify(error=str(e)),400
