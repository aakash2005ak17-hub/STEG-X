"use strict";

const $ = id => document.getElementById(id);

const modules = {
  image: {
    title: "PNG Image Lab",
    kicker: "IMAGE STEGANOGRAPHY",
    desc: "Hide and extract messages using RGB LSB encoding in PNG images.",
    accept: "image/png"
  },
  audio: {
    title: "WAV Audio Lab",
    kicker: "AUDIO STEGANOGRAPHY",
    desc: "Hide and extract messages in uncompressed 16-bit PCM WAV audio.",
    accept: ".wav,audio/wav"
  },
  video: {
    title: "Video Payload Lab",
    kicker: "VIDEO EXPERIMENTAL",
    desc: "Experimental trailing-payload demonstration. This does not modify individual video frames.",
    accept: "video/*,.mp4,.webm,.avi,.mov,.mkv"
  },
  document: {
    title: "PDF Document Lab",
    kicker: "DOCUMENT PAYLOAD",
    desc: "Add and extract an identifiable payload after PDF file bytes.",
    accept: ".pdf,application/pdf"
  },
  text: {
    title: "Unicode Text Lab",
    kicker: "TEXT STEGANOGRAPHY",
    desc: "Hide messages using invisible Unicode characters.",
    accept: ""
  },
  network: {
    title: "Network File Lab",
    kicker: "PCAP EXPERIMENTAL",
    desc: "Experimental payload addition to an existing PCAP file. No live packet capture.",
    accept: ".pcap,.pcapng,application/octet-stream"
  },
  forensics: {
    title: "Forensic Inspection",
    kicker: "BASIC FORENSIC TRIAGE",
    desc: "Inspect file metadata, SHA-256 hash, entropy and STEG-X markers.",
    accept: "*/*"
  }
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const MAGIC = encoder.encode("STEGX1:");

let current = "image";
let mode = "encode";
let selectedFile = null;
let outputURL = null;

function wrapPayload(payload) {
  const result = new Uint8Array(MAGIC.length + 4 + payload.length);
  result.set(MAGIC);
  new DataView(result.buffer).setUint32(MAGIC.length, payload.length);
  result.set(payload, MAGIC.length + 4);
  return result;
}

function findPayload(bytes) {
  outer:
  for (let i = 0; i <= bytes.length - MAGIC.length - 4; i++) {
    for (let j = 0; j < MAGIC.length; j++) {
      if (bytes[i + j] !== MAGIC[j]) continue outer;
    }

    const length = new DataView(
      bytes.buffer,
      bytes.byteOffset + i + MAGIC.length,
      4
    ).getUint32(0);

    if (length <= bytes.length - i - MAGIC.length - 4) {
      return bytes.slice(
        i + MAGIC.length + 4,
        i + MAGIC.length + 4 + length
      );
    }
  }

  return null;
}

async function readFile(file) {
  return new Uint8Array(await file.arrayBuffer());
}

function showResult(title, description, preview, blob, filename) {
  $("result").classList.remove("hidden");
  $("result-title").textContent = title;
  $("result-desc").textContent = description;
  $("preview-area").replaceChildren();
  $("download-link").classList.add("hidden");

  if (preview) $("preview-area").append(preview);

  if (outputURL) {
    URL.revokeObjectURL(outputURL);
    outputURL = null;
  }

  if (blob) {
    outputURL = URL.createObjectURL(blob);
    const link = $("download-link");
    link.href = outputURL;
    link.download = filename;
    link.classList.remove("hidden");
  }
}

function showError(error) {
  showResult(
    "Operation failed",
    error.message || String(error),
    null,
    null,
    ""
  );
}

/* IMAGE STEGANOGRAPHY */

async function encodeImage(file, message) {
  if (file.type !== "image/png") {
    throw new Error("Please select a PNG image.");
  }

  const bitmap = await createImageBitmap(file);
  const canvas = document.createElement("canvas");

  canvas.width = bitmap.width;
  canvas.height = bitmap.height;

  const context = canvas.getContext("2d", {
    willReadFrequently: true
  });

  context.drawImage(bitmap, 0, 0);

  const imageData = context.getImageData(
    0, 0, canvas.width, canvas.height
  );

  const pixels = imageData.data;
  const payload = wrapPayload(encoder.encode(message));
  const requiredBits = payload.length * 8;
  const capacity = Math.floor((pixels.length / 4) * 3);

  if (requiredBits > capacity) {
    throw new Error("Message is too large for this image.");
  }

  let bit = 0;

  for (let i = 0; i < pixels.length && bit < requiredBits; i++) {
    if (i % 4 === 3) continue;

    pixels[i] =
      (pixels[i] & 254) |
      ((payload[bit >> 3] >> (7 - (bit % 8))) & 1);

    bit++;
  }

  context.putImageData(imageData, 0, 0);

  return await new Promise(resolve => {
    canvas.toBlob(resolve, "image/png");
  });
}

async function decodeImage(file) {
  const bitmap = await createImageBitmap(file);
  const canvas = document.createElement("canvas");

  canvas.width = bitmap.width;
  canvas.height = bitmap.height;

  const context = canvas.getContext("2d", {
    willReadFrequently: true
  });

  context.drawImage(bitmap, 0, 0);

  const pixels = context.getImageData(
    0, 0, canvas.width, canvas.height
  ).data;

  const bytes = new Uint8Array(
    Math.floor((pixels.length / 4 * 3) / 8)
  );

  let bit = 0;

  for (let i = 0; i < pixels.length; i++) {
    if (i % 4 === 3) continue;
    if (bit >= bytes.length * 8) break;

    bytes[bit >> 3] =
      (bytes[bit >> 3] << 1) |
      (pixels[i] & 1);

    bit++;
  }

  const payload = findPayload(bytes);

  if (!payload) {
    throw new Error("No compatible STEG-X message found.");
  }

  return decoder.decode(payload);
}

/* WAV AUDIO STEGANOGRAPHY */

function getWavData(bytes) {
  if (
    decoder.decode(bytes.slice(0, 4)) !== "RIFF" ||
    decoder.decode(bytes.slice(8, 12)) !== "WAVE"
  ) {
    throw new Error("Invalid WAV file.");
  }

  const view = new DataView(
    bytes.buffer,
    bytes.byteOffset,
    bytes.byteLength
  );

  let offset = 12;
  let format = null;
  let audioData = null;

  while (offset + 8 <= bytes.length) {
    const chunk = decoder.decode(
      bytes.slice(offset, offset + 4)
    );

    const size = view.getUint32(offset + 4, true);
    const start = offset + 8;

    if (start + size > bytes.length) break;

    if (chunk === "fmt ") {
      format = {
        type: view.getUint16(start, true),
        bits: view.getUint16(start + 14, true)
      };
    }

    if (chunk === "data") {
      audioData = { start, size };
      break;
    }

    offset = start + size + (size % 2);
  }

  if (
    !format ||
    !audioData ||
    format.type !== 1 ||
    format.bits !== 16
  ) {
    throw new Error(
      "Only 16-bit PCM WAV files are supported."
    );
  }

  return audioData;
}

async function encodeAudio(file, message) {
  const bytes = await readFile(file);
  const data = getWavData(bytes);
  const payload = wrapPayload(encoder.encode(message));
  const requiredBits = payload.length * 8;

  if (requiredBits > data.size / 2) {
    throw new Error("Message is too large for this WAV file.");
  }

  let bit = 0;

  for (
    let i = data.start;
    i < data.start + data.size && bit < requiredBits;
    i += 2
  ) {
    bytes[i] =
      (bytes[i] & 254) |
      ((payload[bit >> 3] >> (7 - (bit % 8))) & 1);

    bit++;
  }

  return new Blob([bytes], { type: "audio/wav" });
}

async function decodeAudio(file) {
  const bytes = await readFile(file);
  const data = getWavData(bytes);

  const output = new Uint8Array(
    Math.floor(data.size / 16)
  );

  let bit = 0;

  for (
    let i = data.start;
    i < data.start + data.size &&
    bit < output.length * 8;
    i += 2
  ) {
    output[bit >> 3] =
      (output[bit >> 3] << 1) |
      (bytes[i] & 1);

    bit++;
  }

  const payload = findPayload(output);

  if (!payload) {
    throw new Error("No compatible STEG-X payload found.");
  }

  return decoder.decode(payload);
}

/* EXPERIMENTAL FILE PAYLOAD */

async function encodeAppend(file, message) {
  const original = await readFile(file);
  const payload = wrapPayload(encoder.encode(message));

  return new Blob(
    [original, payload],
    { type: file.type || "application/octet-stream" }
  );
}

async function decodeAppend(file) {
  const bytes = await readFile(file);
  const payload = findPayload(bytes);

  if (!payload) {
    throw new Error("No STEG-X payload found.");
  }

  return decoder.decode(payload);
}

/* TEXT STEGANOGRAPHY */

function encodeText(message, coverText) {
  const hidden = Array.from(
    encoder.encode(message)
  ).map(byte =>
    Array.from({ length: 8 }, (_, i) =>
      (byte >> (7 - i)) & 1
        ? "\u200C"
        : "\u200B"
    ).join("")
  ).join("");

  return coverText + "\u2063" + hidden + "\u2063";
}

function decodeText(text) {
  const parts = text.split("\u2063");

  if (parts.length < 3) {
    throw new Error("No hidden Unicode message found.");
  }

  const hidden = parts[parts.length - 2];
  const bits = Array.from(hidden).map(char => {
    if (char === "\u200B") return 0;
    if (char === "\u200C") return 1;
    return null;
  }).filter(bit => bit !== null);

  if (bits.length % 8 !== 0) {
    throw new Error("Hidden message is incomplete.");
  }

  const bytes = new Uint8Array(bits.length / 8);

  for (let i = 0; i < bits.length; i++) {
    bytes[i >> 3] =
      (bytes[i >> 3] << 1) | bits[i];
  }

  return decoder.decode(bytes);
}

/* BASIC FORENSIC ANALYSIS */

function calculateEntropy(bytes) {
  const counts = new Array(256).fill(0);

  for (const byte of bytes) counts[byte]++;

  let entropy = 0;

  for (const count of counts) {
    if (!count) continue;

    const probability = count / bytes.length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

async function forensicAnalysis(file) {
  const bytes = await readFile(file);

  const hashBuffer = await crypto.subtle.digest(
    "SHA-256",
    bytes
  );

  const hash = Array.from(
    new Uint8Array(hashBuffer)
  ).map(byte => byte.toString(16).padStart(2, "0")).join("");

  const entropy = calculateEntropy(bytes);
  const marker = findPayload(bytes);

  const report = [
    "STEG-X FORENSIC REPORT",
    "----------------------",
    `File name: ${file.name}`,
    `File size: ${file.size} bytes`,
    `File type: ${file.type || "Unknown"}`,
    `Last modified: ${new Date(file.lastModified).toLocaleString()}`,
    `SHA-256: ${hash}`,
    `Entropy: ${entropy.toFixed(4)} bits/byte`,
    `STEG-X marker: ${marker ? "Detected" : "Not detected"}`,
    "",
    "Note: This is basic triage, not proof of steganography."
  ].join("\n");

  return report;
}

/* USER INTERFACE */

function updateMode(nextMode) {
  mode = nextMode;

  $("encode-btn").classList.toggle(
    "active",
    mode === "encode"
  );

  $("decode-btn").classList.toggle(
    "active",
    mode === "decode"
  );

  $("message-field").classList.toggle(
    "hidden",
    mode === "decode" || current === "forensics"
  );

  $("cover-field").classList.toggle(
    "hidden",
    current !== "text" || mode === "decode"
  );

  $("message-label").textContent =
    current === "text" ? "Hidden message" : "Message to hide";

  $("action-btn").textContent =
    mode === "encode" ? "Embed Message" : "Extract Message";
}

function selectModule(name) {
  if (!modules[name]) return;

  current = name;
  selectedFile = null;

  document.querySelectorAll("[data-module]").forEach(button => {
    button.classList.toggle(
      "active",
      button.dataset.module === name
    );
  });

  $("module-title").textContent = modules[name].title;
  $("module-kicker").textContent = modules[name].kicker;
  $("module-desc").textContent = modules[name].desc;

  $("file-input").accept = modules[name].accept;

  $("file-input").value = "";
  $("file-name").textContent = "No file selected";

  $("text-input").value = "";
  $("cover-text").value = "";

  $("result").classList.add("hidden");

  updateMode("encode");
}

async function runOperation() {
  try {
    if (current === "text") {
      if (mode === "encode") {
        const message = $("text-input").value;
        const cover = $("cover-text").value;

        if (!message.trim()) {
          throw new Error("Enter a message first.");
        }

        const result = encodeText(message, cover);

        const blob = new Blob(
          [result],
          { type: "text/plain;charset=utf-8" }
        );

        showResult(
          "Message embedded",
          "Copy or download the generated text.",
          document.createTextNode(result),
          blob,
          "stegx-hidden-text.txt"
        );
      } else {
        const result = decodeText($("text-input").value);

        showResult(
          "Message extracted",
          result,
          document.createTextNode(result),
          null,
          ""
        );
      }

      return;
    }

    if (!selectedFile) {
      throw new Error("Please select a file first.");
    }

    if (current === "forensics") {
      const report = await forensicAnalysis(selectedFile);

      showResult(
        "Forensic analysis complete",
        report,
        document.createElement("pre"),
        new Blob([report], { type: "text/plain" }),
        "stegx-forensic-report.txt"
      );

      $("preview-area").firstChild.textContent = report;
      return;
    }

    if (mode === "encode") {
      const message = $("text-input").value;

      if (!message.trim()) {
        throw new Error("Enter a message first.");
      }

      let blob;
      let filename;

      if (current === "image") {
        blob = await encodeImage(selectedFile, message);
        filename = "stegx-encoded.png";
      } else if (current === "audio") {
        blob = await encodeAudio(selectedFile, message);
        filename = "stegx-encoded.wav";
      } else {
        blob = await encodeAppend(selectedFile, message);
        filename = "stegx-encoded-" + selectedFile.name;
      }

      const preview = document.createElement("p");
      preview.textContent = "Encoded file is ready.";

      showResult(
        "Message embedded successfully",
        "Download your encoded file below.",
        preview,
        blob,
        filename
      );
    } else {
      let result;

      if (current === "image") {
        result = await decodeImage(selectedFile);
      } else if (current === "audio") {
        result = await decodeAudio(selectedFile);
      } else {
        result = await decodeAppend(selectedFile);
      }

      showResult(
        "Message extracted successfully",
        result,
        document.createTextNode(result),
        null,
        ""
      );
    }
  } catch (error) {
    showError(error);
  }
}

/* EVENT LISTENERS */

document.querySelectorAll("[data-module]").forEach(button => {
  button.addEventListener("click", () => {
    selectModule(button.dataset.module);
  });
});

$("encode-btn").addEventListener("click", () => {
  updateMode("encode");
});

$("decode-btn").addEventListener("click", () => {
  updateMode("decode");
});

$("file-input").addEventListener("change", event => {
  selectedFile = event.target.files[0] || null;

  $("file-name").textContent =
    selectedFile ? selectedFile.name : "No file selected";
});

$("action-btn").addEventListener("click", runOperation);

selectModule("image");
