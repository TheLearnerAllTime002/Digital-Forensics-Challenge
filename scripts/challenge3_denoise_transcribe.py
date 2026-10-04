"""
Challenge 3 — Denoise and Transcribe war-intercept.wav
Pipeline:
  1. Load WAV
  2. Spectral subtraction denoising (noise profile from first 0.5s)
  3. Save denoised WAV
  4. Transcribe with OpenAI Whisper (medium model)
  5. Save transcript + screenshots
"""

import os, wave, struct, math, time
import numpy as np
from scipy.signal import butter, sosfilt
from PIL import Image, ImageDraw, ImageFont

os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"

IN_WAV   = os.environ.get(
    "CHALLENGE3_AUDIO",
    os.path.join(os.path.dirname(__file__), "..", "data", "challenge3", "war-intercept.wav"),
)
OUT_DIR  = os.environ.get(
    "CHALLENGE3_OUTPUT",
    os.path.join(os.path.dirname(__file__), "..", "data", "generated", "challenge3"),
)
SHOT_DIR = os.environ.get(
    "CHALLENGE3_SCREENSHOTS",
    os.path.join(os.path.dirname(__file__), "..", "data", "generated", "challenge3"),
)
os.makedirs(OUT_DIR,  exist_ok=True)
os.makedirs(SHOT_DIR, exist_ok=True)

DENOISED_WAV  = os.path.join(OUT_DIR, "war-intercept-denoised.wav")
TRANSCRIPT_TXT = os.path.join(OUT_DIR, "transcript.txt")

# ── Step 1: Load WAV ──────────────────────────────────────────────────────────
print("[1/5] Loading WAV ...")
with wave.open(IN_WAV) as wf:
    n_channels  = wf.getnchannels()
    samp_width  = wf.getsampwidth()
    frame_rate  = wf.getframerate()
    n_frames    = wf.getnframes()
    raw_bytes   = wf.readframes(n_frames)

duration = n_frames / frame_rate
print(f"      {n_channels}ch  {samp_width*8}-bit  {frame_rate}Hz  {duration:.1f}s")

# Convert to float32 [-1, 1]
samples = np.frombuffer(raw_bytes, dtype=np.int16).astype(np.float32) / 32768.0
if n_channels > 1:
    samples = samples.reshape(-1, n_channels).mean(axis=1)  # mix to mono

# ── Step 2: Denoising ─────────────────────────────────────────────────────────
print("[2/5] Denoising (spectral subtraction + bandpass) ...")

SR = frame_rate

# 2a. High-pass filter to remove DC / very low rumble (below 80 Hz)
sos_hp = butter(4, 80 / (SR/2), btype='high', output='sos')
samples = sosfilt(sos_hp, samples)

# 2b. Low-pass filter to remove hiss above 8 kHz (speech is 80–8000 Hz)
sos_lp = butter(4, min(8000 / (SR/2), 0.99), btype='low', output='sos')
samples = sosfilt(sos_lp, samples)

# 2c. Spectral subtraction
FRAME_LEN  = int(SR * 0.025)   # 25 ms frames
HOP_LEN    = int(SR * 0.010)   # 10 ms hop
NOISE_SECS = 0.5               # use first 0.5s as noise profile
ALPHA      = 2.0               # over-subtraction factor
BETA       = 0.002             # spectral floor

noise_frames = int(NOISE_SECS * SR / HOP_LEN)
noise_profile = None

def stft_frame(sig, start, flen):
    chunk = sig[start:start+flen]
    if len(chunk) < flen:
        chunk = np.pad(chunk, (0, flen - len(chunk)))
    window = np.hanning(flen)
    return np.fft.rfft(chunk * window)

# Estimate noise power spectrum from first 0.5s
noise_specs = []
for i in range(noise_frames):
    spec = stft_frame(samples, i * HOP_LEN, FRAME_LEN)
    noise_specs.append(np.abs(spec)**2)
noise_profile = np.mean(noise_specs, axis=0)

# Apply spectral subtraction frame by frame
n_frames_total = (len(samples) - FRAME_LEN) // HOP_LEN + 1
output = np.zeros(len(samples))
window_sum = np.zeros(len(samples))
win = np.hanning(FRAME_LEN)

for i in range(n_frames_total):
    start = i * HOP_LEN
    spec  = stft_frame(samples, start, FRAME_LEN)
    mag   = np.abs(spec)
    phase = np.angle(spec)
    mag2  = mag**2
    # Subtract noise
    clean_mag2 = np.maximum(mag2 - ALPHA * noise_profile, BETA * mag2)
    clean_mag  = np.sqrt(clean_mag2)
    clean_spec = clean_mag * np.exp(1j * phase)
    frame_out  = np.fft.irfft(clean_spec)[:FRAME_LEN]
    output[start:start+FRAME_LEN] += frame_out * win
    window_sum[start:start+FRAME_LEN] += win**2

# Overlap-add normalisation
mask = window_sum > 1e-8
output[mask] /= window_sum[mask]

# Normalise amplitude
peak = np.max(np.abs(output))
if peak > 0:
    output = output / peak * 0.95

print(f"      Denoising complete. Output peak: {peak:.4f}")

# ── Step 3: Save denoised WAV ─────────────────────────────────────────────────
print(f"[3/5] Saving denoised WAV -> {DENOISED_WAV}")
out_int16 = (output * 32767).astype(np.int16)
with wave.open(DENOISED_WAV, 'w') as wf:
    wf.setnchannels(1)
    wf.setsampwidth(2)
    wf.setframerate(SR)
    wf.writeframes(out_int16.tobytes())
print(f"      Saved: {os.path.getsize(DENOISED_WAV):,} bytes")

# ── Step 4: Transcribe with Whisper ──────────────────────────────────────────
print("[4/5] Transcribing with Whisper (medium model) ...")
import whisper

model = whisper.load_model("medium")
print("      Model loaded. Running transcription ...")

t0 = time.time()
result = model.transcribe(
    DENOISED_WAV,
    language="en",
    verbose=False,
    word_timestamps=True,
    condition_on_previous_text=True,
    temperature=0.0,
)
elapsed = time.time() - t0
print(f"      Transcription done in {elapsed:.1f}s")

# ── Step 5: Save transcript ───────────────────────────────────────────────────
print(f"[5/5] Saving transcript -> {TRANSCRIPT_TXT}")

full_text = result["text"].strip()
segments  = result.get("segments", [])

with open(TRANSCRIPT_TXT, "w", encoding="utf-8") as f:
    f.write("WAR INTERCEPT — TRANSCRIPT\n")
    f.write("=" * 60 + "\n\n")
    f.write("FULL TEXT:\n")
    f.write(full_text + "\n\n")
    f.write("=" * 60 + "\n")
    f.write("TIMESTAMPED SEGMENTS:\n\n")
    for seg in segments:
        start = seg["start"]
        end   = seg["end"]
        text  = seg["text"].strip()
        m_s, s_s = divmod(int(start), 60)
        m_e, s_e = divmod(int(end),   60)
        f.write(f"[{m_s:02d}:{s_s:02d} --> {m_e:02d}:{s_e:02d}]  {text}\n")

print("\n" + "="*60)
print("FULL TRANSCRIPT:")
print("="*60)
print(full_text)
print("\nTIMESTAMPED SEGMENTS:")
for seg in segments:
    start = seg["start"]; end = seg["end"]; text = seg["text"].strip()
    m_s, s_s = divmod(int(start), 60); m_e, s_e = divmod(int(end), 60)
    print(f"  [{m_s:02d}:{s_s:02d}-->{m_e:02d}:{s_e:02d}] {text}")

# ── Save Screenshots ──────────────────────────────────────────────────────────
def save_screenshot(title, lines, filename):
    font_size = 13
    try:    font = ImageFont.truetype("cour.ttf", font_size)
    except: font = ImageFont.load_default()
    padding = 18
    line_h  = font_size + 5
    width   = 1000
    height  = padding*2 + len(lines)*line_h + 44
    img  = Image.new("RGB", (width, height), (12, 12, 22))
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, width, 36], fill=(40, 60, 100))
    draw.text((10, 9), f"Challenge 3 — Audio Denoising & Transcription  |  {title}", font=font, fill=(180,220,255))
    y = 46
    for line in lines:
        color = (255,255,255)
        if line.startswith("===") or line.startswith("WAR") or line.startswith("FULL") or line.startswith("TIME"):
            color = (100,200,255)
        elif line.startswith("[") and "-->" in line:
            color = (180,255,180)
        elif "denoised" in line.lower() or "spectral" in line.lower():
            color = (255,200,80)
        draw.text((padding, y), line[:118], font=font, fill=color)
        y += line_h
    out_path = os.path.join(SHOT_DIR, filename)
    img.save(out_path)
    print(f"[SAVED] {out_path}")

# Screenshot 1 – pipeline info
pipeline_lines = [
    "PIPELINE SUMMARY", "="*60, "",
    f"Input file    : war-intercept.wav",
    f"Duration      : {duration:.1f}s ({duration/60:.2f} min)",
    f"Sample rate   : {SR} Hz",
    f"Channels      : {n_channels} (mono)",
    f"Bit depth     : {samp_width*8}-bit",
    "",
    "DENOISING STEPS:",
    "  1. High-pass filter  (Butterworth 4th order, cutoff 80 Hz)",
    "     -> removes DC offset and low-frequency rumble",
    "  2. Low-pass filter   (Butterworth 4th order, cutoff 8000 Hz)",
    "     -> removes high-frequency hiss above speech range",
    "  3. Spectral subtraction (alpha=2.0, beta=0.002)",
    "     -> noise profile estimated from first 0.5s of recording",
    "     -> per-frame magnitude spectrum cleaned, phase preserved",
    "     -> overlap-add reconstruction (25ms frames, 10ms hop)",
    "",
    "TRANSCRIPTION:",
    "  Model  : OpenAI Whisper (medium)",
    "  Lang   : English (forced)",
    f"  Time   : {elapsed:.1f}s",
    f"  Output : {TRANSCRIPT_TXT}",
]
save_screenshot("Pipeline Summary", pipeline_lines, "01_pipeline_summary.png")

# Screenshot 2 – full transcript
transcript_lines = ["FULL TRANSCRIPT", "="*60, ""] + \
    [l for l in full_text.split(". ") if l] + \
    ["", "="*60, "TIMESTAMPED SEGMENTS", ""]
for seg in segments:
    start = seg["start"]; end = seg["end"]; text = seg["text"].strip()
    m_s, s_s = divmod(int(start), 60); m_e, s_e = divmod(int(end), 60)
    transcript_lines.append(f"[{m_s:02d}:{s_s:02d} --> {m_e:02d}:{s_e:02d}]  {text}")
save_screenshot("Full Transcript", transcript_lines, "02_transcript.png")

print(f"\nAll outputs saved to:")
print(f"  {OUT_DIR}")
print(f"  {SHOT_DIR}")
