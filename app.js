// app.js - STEG-X browser-only
// Supports: Image (PNG), Audio (PCM WAV), Video (uncompressed AVI)

const MAGIC = [0x53, 0x58]; // "SX"
const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------- Tabs ----------
document.querySelectorAll(".tabs button").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tabs button").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.add("hidden"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.tab).classList.remove("hidden");
  });
});

// ---------- Common helpers ----------
function show(el, text, isError) {
  el.textContent = text;
  el.style.display = "block";
  el.style.color = isError ? "#ffcc33" : "";
}

function download(blob, name) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 10000);
}

async function readBytes(file) {
  return new Uint8Array(await file.arrayBuffer());
}

function str(buf, off, n) {
  let s = "";
  for (let i = 0; i < n; i++) s += String.fromCharCode(buf[off + i]);
  return s;
}

function buildPayload(message) {
