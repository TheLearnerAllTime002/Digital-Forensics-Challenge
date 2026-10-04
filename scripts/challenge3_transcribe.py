import os, wave, numpy as np, whisper, json
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"

ROOT = os.path.dirname(__file__)
ORIG = os.environ.get("CHALLENGE3_AUDIO", os.path.join(ROOT, "..", "data", "challenge3", "war-intercept.wav"))
OUT  = os.environ.get("CHALLENGE3_OUTPUT", os.path.join(ROOT, "..", "data", "generated", "challenge3"))
DEN  = os.path.join(OUT, "war-intercept-denoised.wav")

def load_wav(path):
    with wave.open(path) as wf:
        sr = wf.getframerate()
        raw = wf.readframes(wf.getnframes())
    audio = np.frombuffer(raw, dtype=np.int16).astype(np.float32) / 32768.0
    return audio, sr

orig_audio, sr = load_wav(ORIG)
den_audio,  _  = load_wav(DEN)

print(f"Original  : shape={orig_audio.shape}  max={np.max(np.abs(orig_audio)):.4f}  rms={np.sqrt(np.mean(orig_audio**2)):.4f}")
print(f"Denoised  : shape={den_audio.shape}   max={np.max(np.abs(den_audio)):.4f}  rms={np.sqrt(np.mean(den_audio**2)):.4f}")

model = whisper.load_model("small")
print("Model loaded.")

# Try both original and denoised with relaxed settings
for label, audio in [("ORIGINAL", orig_audio), ("DENOISED", den_audio)]:
    print(f"\n--- Transcribing {label} ---")
    result = model.transcribe(
        audio,
        language="en",
        verbose=True,
        temperature=(0.0, 0.2, 0.4, 0.6, 0.8, 1.0),
        fp16=False,
        no_speech_threshold=0.2,
        logprob_threshold=-2.0,
        compression_ratio_threshold=3.0,
        condition_on_previous_text=False,
        word_timestamps=True,
    )
    txt = result["text"].strip()
    segs = result.get("segments", [])
    print(f"  Segments: {len(segs)}")
    print(f"  Text: {txt[:500]}")

    out_path = os.path.join(OUT, f"transcript_{label.lower()}.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"WAR INTERCEPT TRANSCRIPT ({label})\n")
        f.write("=" * 60 + "\n\n")
        f.write("FULL TEXT:\n")
        f.write(txt + "\n\n")
        f.write("=" * 60 + "\n")
        f.write("TIMESTAMPED SEGMENTS:\n\n")
        for seg in segs:
            s, e, t = seg["start"], seg["end"], seg["text"].strip()
            ms, ss = divmod(int(s), 60)
            me, se2 = divmod(int(e), 60)
            f.write(f"[{ms:02d}:{ss:02d} --> {me:02d}:{se2:02d}]  {t}\n")
    print(f"  Saved: {out_path}")
