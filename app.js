// app.js - browser-only PNG LSB steganography

const ID = {
  file: "carrierFile",
  msg: "secretMessage",
  encodeBtn: "encodeBtn",
  status: "status",
};

const $ = (id) => document.getElementById(id);
const MAGIC = [0x53, 0x58]; // "SX"

function setStatus(text) {
  const el = $(ID.status);
  if (el) el.textContent = text;
}

function loadImage(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => { URL.revokeObjectURL(url); resolve(img); };
    img.onerror = () => reject(new Error("Image load aagala. PNG file use pannu."));
    img.src = url;
  });
}

function toBits(bytes) {
  const bits = [];
  for (const b of bytes) {
    for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
  }
  return bits;
}

async function encode() {
  try {
    const file = $(ID.file).files[0];
    const message = $(ID.msg).value;
    if (!file) return setStatus("Error: Carrier file select pannu.");
    if (!message) return setStatus("Error: Secret message type pannu.");

    const img = await loadImage(file);
    const canvas = document.createElement("canvas");
    canvas.width = img.naturalWidth;
    canvas.height = img.naturalHeight;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    ctx.drawImage(img, 0, 0);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const px = imageData.data;

    // payload = magic(2) + length(4) + message bytes
    const msgBytes = new TextEncoder().encode(message);
    const len = msgBytes.length;
    const header = [
      ...MAGIC,
      (len >>> 24) & 255, (len >>> 16) & 255, (len >>> 8) & 255, len & 255,
    ];
    const bits = toBits([...header, ...msgBytes]);

    const capacity = canvas.width * canvas.height * 3;
    if (bits.length > capacity) {
      return setStatus(
        `Error: Message romba perusu. Max ${Math.floor(capacity / 8) - 6} bytes.`
      );
    }

    // write bits into LSB of R, G, B (skip alpha)
    let bi = 0;
    for (let i = 0; i < px.length && bi < bits.length; i++) {
      if (i % 4 === 3) continue;
      px[i] = (px[i] & 0xfe) | bits[bi++];
    }

    ctx.putImageData(imageData, 0, 0);
    canvas.toBlob((blob) => {
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "stego.png";
      document.body.appendChild(a);
      a.click();
      a.remove();
      setStatus(`Done! ${len} bytes embed aagiduchu. stego.png download aachu.`);
    }, "image/png");
  } catch (e) {
    setStatus("Error: " + e.message);
  }
}

// Optional: decode (call decodeFile(file) from a decode button)
async function decodeFile(file) {
  const img = await loadImage(file);
  const canvas = document.createElement("canvas");
  canvas.width = img.naturalWidth;
  canvas.height = img.naturalHeight;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(img, 0, 0);
  const px = ctx.getImageData(0, 0, canvas.width, canvas.height).data;

  let idx = 0;
  const readByte = () => {
    let v = 0;
    for (let k = 0; k < 8; k++) {
      while (idx % 4 === 3) idx++;
      v = (v << 1) | (px[idx++] & 1);
    }
    return v;
  };

  if (readByte() !== MAGIC[0] || readByte() !== MAGIC[1]) {
    throw new Error("Indha image-la hidden message illa.");
  }
  const len =
    ((readByte() << 24) | (readByte() << 16) | (readByte() << 8) | readByte()) >>> 0;
  if (len > (px.length / 4) * 3 / 8) throw new Error("Data corrupt aagirukku.");

  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = readByte();
  return new TextDecoder().decode(out);
}

document.addEventListener("DOMContentLoaded", () => {
  const btn = $(ID.encodeBtn);
  if (btn) btn.addEventListener("click", encode);
});
