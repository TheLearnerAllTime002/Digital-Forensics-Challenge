"""Challenge 3 — Save annotated screenshots"""
import os
from PIL import Image, ImageDraw, ImageFont

SHOT_DIR = os.environ.get(
    "CHALLENGE3_SCREENSHOTS",
    os.path.join(os.path.dirname(__file__), "..", "data", "generated", "challenge3"),
)
os.makedirs(SHOT_DIR, exist_ok=True)

def save_screenshot(title, lines, filename):
    font_size = 13
    try:    font = ImageFont.truetype("cour.ttf", font_size)
    except: font = ImageFont.load_default()
    padding = 18
    line_h  = font_size + 5
    width   = 1000
    height  = padding*2 + len(lines)*line_h + 44
    img  = Image.new("RGB", (width, height), (10, 10, 20))
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, width, 36], fill=(50, 30, 90))
    draw.text((10, 9), f"Challenge 3 — Audio Denoising & Transcription  |  {title}", font=font, fill=(200,180,255))
    y = 46
    for line in lines:
        color = (255,255,255)
        if line.startswith("===") or line.startswith("WAR") or line.startswith("PIPELINE") or line.startswith("FULL") or line.startswith("TIME"):
            color = (150,200,255)
        elif line.startswith("[") and "-->" in line:
            color = (180,255,180)
        elif "denoised" in line.lower() or "spectral" in line.lower() or "filter" in line.lower():
            color = (255,200,80)
        elif "rms" in line.lower() or "entropy" in line.lower() or "noise" in line.lower():
            color = (255,160,60)
        elif line.strip().startswith("*") or "WARNING" in line:
            color = (255,100,100)
        draw.text((padding, y), line[:118], font=font, fill=color)
        y += line_h
    out_path = os.path.join(SHOT_DIR, filename)
    img.save(out_path)
    print(f"[SAVED] {out_path}")

# Screenshot 1 – Audio metadata + pipeline
pipeline_lines = [
    "PIPELINE SUMMARY", "="*62, "",
    "INPUT FILE    : war-intercept.wav",
    "Duration      : 279.0s (4.65 minutes)",
    "Sample rate   : 16000 Hz",
    "Channels      : 1 (mono)",
    "Bit depth     : 16-bit PCM",
    "File size     : 8,928,078 bytes",
    "",
    "AUDIO CHARACTERISTICS:",
    "  Original RMS amplitude : 0.1377  (moderate level, noisy)",
    "  Denoised RMS amplitude : 0.0020  (over-filtered — too aggressive)",
    "  Peak amplitude         : 0.7201 (original) / 0.9500 (denoised, normalised)",
    "",
    "DENOISING STEPS APPLIED:",
    "  Step 1: High-pass Butterworth filter (4th order, cutoff 80 Hz)",
    "          -> removes DC offset and sub-speech rumble",
    "  Step 2: Low-pass Butterworth filter (4th order, cutoff 8000 Hz)",
    "          -> removes hiss above speech frequency range",
    "  Step 3: Spectral subtraction (alpha=2.0 over-subtraction, beta=0.002 floor)",
    "          -> noise profile estimated from first 0.5s of recording",
    "          -> per-frame STFT magnitude cleaned, phase preserved",
    "          -> overlap-add reconstruction (25ms frames, 10ms hop, Hanning window)",
    "",
    "NOTE: Spectral subtraction was too aggressive for this recording.",
    "      The original WAV was used for final transcription.",
    "",
    "TRANSCRIPTION ENGINE:",
    "  Model  : OpenAI Whisper (small, 461 MB)",
    "  Input  : Original WAV (numpy float32 array, bypassing ffmpeg)",
    "  Lang   : English (forced)",
    "  Params : temperature fallback (0.0->1.0), no_speech_threshold=0.2",
    "  Output : 73 segments detected",
]
save_screenshot("Pipeline & Audio Metadata", pipeline_lines, "01_pipeline_metadata.png")

# Screenshot 2 – Full transcript
transcript_lines = [
    "FULL TRANSCRIPT (ORIGINAL WAV, WHISPER SMALL)", "="*62, "",
    "I have to start with Christmas Eve.",
    "Because then I opened my warriors Christmas party.",
    "Some of us fell out in the war rats.",
    "Standing around helping, I grabbed a few people down here.",
    "I lay out few people, I found out I was a little bit too young.",
    "That is a my cookie, Alex.",
    "Hey, Charlie, your mother's a slow crow.",
    "Tell them this one, Charlie. A small but the kid.",
    "No way. No way. No way.",
    "So, look at that. This is sort of a new age.",
    "Oh, that's a terrible question.",
    "Isn't this where my father's a man?",
    "No, I don't care what I get new raise up life and die.",
    "You better hang out with that father. I'll be swiping.",
    "You can have anything but my flesh, Charlie. I'm gonna hang on it.",
    "I'm gonna have dinner with the queen.",
    "I've been out in the sun for a while. That's what the notes say.",
    "We'll spend a sad drive on each other.",
    "And I have been chosen as the two American officers that have been in the US.",
    "That's true, what they know is it's clean there. Wow.",
    "They know what they know. They know what they know.",
    "It's less than triple money then. We really were in business.",
    "You know, my bill will probably cost me a million dollars on a single bill, $40.",
    "But thanks to your special presentation,",
    "I was able to put together a small package for the bill.",
    "I got a message that said, Thank you. I got it.",
    "The other hand, I put all my strength.",
    "In order to chase the spirit out, I put all my strength.",
    "You're not going to watch this anymore, right?",
    "I'm going to watch this.",
    "You're not going to watch this anymore, right?",
]
save_screenshot("Full Transcript", transcript_lines, "02_full_transcript.png")

# Screenshot 3 – Timestamped segments (key ones)
seg_lines = [
    "TIMESTAMPED SEGMENTS (KEY EXTRACTS)", "="*62, "",
    "[00:15 --> 00:20]  I have to start with Christmas Eve.",
    "[00:21 --> 00:23]  Because then I opened my warriors Christmas party.",
    "[00:24 --> 00:25]  Some of us fell out in the war rats.",
    "[00:26 --> 00:28]  Standing around helping, I grabbed a few people down here.",
    "[00:29 --> 00:31]  That is a my cookie, Alex.",
    "[00:32 --> 00:34]  Hey, Charlie, your mother's a slow crow.",
    "[00:34 --> 00:35]  Tell them this one, Charlie.",
    "[00:36 --> 00:37]  A small but the kid.",
    "[00:41 --> 00:42]  So, look at that.",
    "[00:42 --> 00:43]  This is sort of a new age.",
    "[00:45 --> 00:46]  Oh, that's a terrible question.",
    "[00:47 --> 00:48]  Isn't this where my father's a man?",
    "[00:49 --> 00:51]  No, I don't care what I get new raise up life and die.",
    "[00:52 --> 00:53]  You better hang out with that father.",
    "[00:54 --> 00:56]  You can have anything but my flesh, Charlie.",
    "[01:15 --> 01:17]  I'm gonna have dinner with the queen.",
    "[01:17 --> 01:19]  I've been out in the sun for a while.",
    "[01:19 --> 01:21]  That's what the notes say.",
    "[01:21 --> 01:23]  We'll spend a sad drive on each other.",
    "[01:24 --> 01:27]  And I have been chosen as the two American officers",
    "[01:27 --> 01:27]  that have been in the US.",
    "[01:27 --> 01:30]  That's true, what they know is it's clean there.",
    "[01:36 --> 01:38]  It's less than triple money then.",
    "[01:38 --> 01:39]  We really were in business.",
    "[01:40 --> 01:43]  You know, my bill will probably cost me a million dollars",
    "[01:43 --> 01:45]  on a single bill, $40.",
    "[01:46 --> 01:48]  But thanks to your special presentation,",
    "[01:48 --> 01:50]  I was able to put together a small package for the bill.",
    "[01:51 --> 01:53]  I got a message that said,",
    "[03:23 --> 03:23]  Thank you.",
    "[03:52 --> 03:53]  I got it.",
    "[04:02 --> 04:13]  The other hand, I put all my strength.",
    "[04:13 --> 04:15]  In order to chase the spirit out, I put all my strength.",
    "[04:21 --> 04:23]  You're not going to watch this anymore, right?",
    "[04:24 --> 04:26]  I'm going to watch this.",
    "[04:26 --> 04:34]  You're not going to watch this anymore, right?",
    "[04:35 --> 04:37]  You're not going to watch this anymore, right?",
    "",
    "* Large silence gap: 00:58 to 01:15 (17 seconds)",
    "* Large silence gap: 01:53 to 03:23 (90 seconds)",
    "* Large silence gap: 03:53 to 04:02 (9 seconds)",
    "* Audio ends at 04:37 with repeated phrase",
]
save_screenshot("Timestamped Segments", seg_lines, "03_timestamped_segments.png")

print(f"\nAll screenshots saved to: {SHOT_DIR}")
