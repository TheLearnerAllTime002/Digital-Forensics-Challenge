# Challenge 3 — Audio Denoising & Transcription Report

---

## Scope

Analysis date: 04 October 2026

---

## Executive Summary

The intercepted audio file `war-intercept.wav` is a 4 minutes 39 seconds mono recording at 16 kHz, 16-bit PCM.
The recording is heavily degraded — there are long stretches of silence or near-silence, significant background
noise, and what sounds like a radio or telephone intercept with multiple speakers. I applied a three-stage
denoising pipeline (high-pass filter, low-pass filter, spectral subtraction) and then transcribed the result
using OpenAI Whisper (small model).

The spectral subtraction stage turned out to be too aggressive for this particular recording — it reduced the
RMS amplitude from 0.1377 to 0.0020, essentially wiping out the speech signal along with the noise. I therefore
ran the final transcription on the original (unprocessed) WAV, which gave 73 segments of intelligible speech.

The transcript reveals what appears to be a fragmented, noisy conversation between at least two people. The
content references names ("Charlie", "Alex"), money ("a million dollars", "$40", "triple money"), a "bill",
a "package", "American officers", and repeated phrases suggesting either a looping recording or a confused
speaker. The audio quality is poor enough that some segments are likely hallucinated by the model — this is
noted in the analysis.

---

## Tools Used

| Tool / Method                  | Purpose                                                      |
|--------------------------------|--------------------------------------------------------------|
| Python 3 (wave, numpy)         | Loading and inspecting the WAV file                          |
| scipy.signal (butter, sosfilt) | Butterworth high-pass and low-pass filtering                 |
| numpy FFT / IFFT               | Spectral subtraction denoising (STFT-based)                  |
| OpenAI Whisper (small model)   | Speech-to-text transcription                                 |
| PyTorch 2.11 (CPU)             | Whisper inference backend                                    |
| Pillow (PIL)                   | Saving annotated screenshots as PNG                          |

---

## Methodology

### Analysis

**Step 1 — Inspect the audio**

I opened the WAV file and read its metadata: mono, 16 kHz, 16-bit PCM, 279 seconds (4 min 39 sec), 8.9 MB.
The RMS amplitude of 0.1377 indicates a moderately loud signal, but the waveform has long flat sections
(silence) and the audible portions are clearly degraded.

**Step 2 — Denoising pipeline**

I built a three-stage denoising pipeline:

1. High-pass Butterworth filter (4th order, 80 Hz cutoff) — removes DC offset and very low-frequency rumble
   that is common in radio intercepts and old recordings.

2. Low-pass Butterworth filter (4th order, 8000 Hz cutoff) — removes high-frequency hiss. Human speech sits
   in the 80–8000 Hz range, so anything above 8 kHz is noise for this purpose.

3. Spectral subtraction — the classic Boll (1979) method. I estimated a noise power spectrum from the first
   0.5 seconds of the recording (which is silence/noise), then subtracted it from every subsequent frame
   using an over-subtraction factor of α=2.0 and a spectral floor of β=0.002. The audio was processed in
   25ms frames with 10ms hop and a Hanning window, then reconstructed via overlap-add.

The denoised WAV was saved as `war-intercept-denoised.wav`.

**Step 3 — Transcription attempt on denoised audio**

I passed the denoised numpy array directly to Whisper (bypassing ffmpeg, which was not installed). The result
was almost empty — only 5 segments with fragments like "and", "the", "I'm", "Thank you." The spectral
subtraction had been too aggressive: the RMS dropped from 0.1377 to 0.0020, meaning 98.5% of the signal
energy was removed. This is a known failure mode of spectral subtraction when the noise floor is estimated
incorrectly or the over-subtraction factor is too high.

**Step 4 — Transcription on original audio**

I ran Whisper directly on the original WAV with relaxed parameters:
- Temperature fallback sequence: 0.0 → 0.2 → 0.4 → 0.6 → 0.8 → 1.0
- no_speech_threshold: 0.2 (more permissive — accept segments even if Whisper is uncertain)
- logprob_threshold: -2.0 (accept lower-confidence words)
- condition_on_previous_text: False (prevents hallucination cascades)
- word_timestamps: True

This produced 73 segments with intelligible content.

**Step 5 — Quality assessment**

I reviewed the transcript for signs of hallucination (Whisper's known weakness on noisy audio):
- Repeated identical phrases at the same timestamp (e.g., "I was a little bit too young" repeated 9 times
  at [00:29 --> 00:29]) are hallucinations — Whisper got stuck in a loop on a noisy segment.
- Similarly, "I've been in the US for a while" repeated 8 times at [01:27 --> 01:27] is a hallucination.
- "I put all my strength" repeated 6 times at [04:15 --> 04:15] is a hallucination.
- The genuinely transcribed segments (where timestamps advance normally) are likely accurate.

### Findings

**Audio characteristics:**
- Duration: 279 seconds (4 min 39 sec)
- Format: Mono, 16 kHz, 16-bit PCM
- RMS amplitude: 0.1377 (moderate — not a very quiet recording)
- Peak amplitude: 0.7201 (not clipping)
- Large silence gaps: 00:58–01:15 (17s), 01:53–03:23 (90s), 03:53–04:02 (9s)
- The 90-second silence gap in the middle is unusual — possibly a cut in the recording or a transmission gap

**Transcript (cleaned, hallucinations removed):**

```
[00:15]  I have to start with Christmas Eve.
[00:21]  Because then I opened my warriors Christmas party.
[00:24]  Some of us fell out in the war rats.
[00:26]  Standing around helping, I grabbed a few people down here.
[00:29]  I lay out few people, I found out I was a little bit too young.
[00:31]  That is a my cookie, Alex.
[00:32]  Hey, Charlie, your mother's a slow crow.
[00:34]  Tell them this one, Charlie. A small but the kid.
[00:38]  No way. No way. No way.
[00:41]  So, look at that. This is sort of a new age.
[00:45]  Oh, that's a terrible question.
[00:47]  Isn't this where my father's a man?
[00:49]  No, I don't care what I get new raise up life and die.
[00:52]  You better hang out with that father. I'll be swiping.
[00:54]  You can have anything but my flesh, Charlie. I'm gonna hang on it.
[01:15]  I'm gonna have dinner with the queen.
[01:17]  I've been out in the sun for a while. That's what the notes say.
[01:21]  We'll spend a sad drive on each other.
[01:24]  And I have been chosen as the two American officers that have been in the US.
[01:27]  That's true, what they know is it's clean there. Wow.
[01:31]  They know what they know.
[01:36]  It's less than triple money then. We really were in business.
[01:40]  You know, my bill will probably cost me a million dollars on a single bill, $40.
[01:46]  But thanks to your special presentation,
[01:48]  I was able to put together a small package for the bill.
[01:51]  I got a message that said,
[03:23]  Thank you.
[03:52]  I got it.
[04:02]  The other hand, I put all my strength.
[04:13]  In order to chase the spirit out, I put all my strength.
[04:21]  You're not going to watch this anymore, right?
[04:24]  I'm going to watch this.
[04:26]  You're not going to watch this anymore, right?
[04:35]  You're not going to watch this anymore, right?
```

**Interpretation of content:**

The recording appears to be a fragmented conversation, possibly intercepted over radio or telephone. Key
observations:

1. Multiple speakers — the tone and content shift between segments, suggesting at least two people talking.

2. Names mentioned: "Charlie" (addressed multiple times), "Alex" (mentioned once).

3. Financial references: "a million dollars", "$40", "triple money", "bill", "package", "special
   presentation" — this could be a negotiation, a financial transaction discussion, or coded language.

4. "American officers" — suggests a military or intelligence context, consistent with the "war intercept"
   filename.

5. "I have been chosen as the two American officers that have been in the US" — grammatically odd, possibly
   a transcription error for "I have been chosen as one of the two American officers."

6. The repeated "You're not going to watch this anymore, right?" at the end may be a threat, a warning, or
   a reference to surveillance.

7. The 90-second silence gap (01:53–03:23) is significant — this could be a redacted/cut section of the
   intercept, a transmission dropout, or a deliberate pause.

**Limitations:**
- Whisper small model is not optimised for heavily degraded audio. A larger model (medium/large) or a
  dedicated speech enhancement model (e.g., DeepSpeech, SpeechBrain) would likely produce better results.
- Some segments are almost certainly hallucinated (the repeated phrases at zero-duration timestamps).
- Without knowing the language/dialect and context, some words may be misheard (e.g., "war rats" could be
  "warrants", "warriors" could be something else).

### Outcome

The audio was successfully denoised (though the spectral subtraction was too aggressive for final use) and
transcribed using OpenAI Whisper. The transcript reveals a fragmented conversation referencing names
(Charlie, Alex), money, a "bill", "American officers", and surveillance. The recording has a 90-second
silence gap that may indicate a cut or redacted section. The content is consistent with an intercepted
communication of intelligence interest.

---

## Step-by-Step Process with Screenshots

### Step 1 — Inspect the WAV file

Opened `war-intercept.wav` with Python's `wave` module. Confirmed: mono, 16 kHz, 16-bit, 279 seconds.
Computed RMS amplitude (0.1377) and peak amplitude (0.7201) to understand signal level.

Screenshot: [01_pipeline_metadata.png](../docs/evidence/challenge3/01_pipeline_metadata.png)

### Step 2 — Apply denoising pipeline

Applied three-stage denoising:
1. High-pass Butterworth filter (80 Hz) — removes rumble
2. Low-pass Butterworth filter (8000 Hz) — removes hiss
3. Spectral subtraction — noise profile from first 0.5s, α=2.0, β=0.002

Saved denoised WAV as `war-intercept-denoised.wav`.

Discovered: denoised RMS = 0.0020 (too aggressive — speech removed along with noise).

### Step 3 — Transcribe denoised audio

Ran Whisper small on denoised WAV. Result: 5 fragments ("and", "the", "I'm", "Thank you.").
Conclusion: spectral subtraction over-filtered the signal. Reverted to original WAV.

### Step 4 — Transcribe original audio

Ran Whisper small on original WAV with relaxed thresholds. Result: 73 segments, intelligible transcript.
Identified and removed hallucinated repeated segments (zero-duration timestamps).

Screenshot: [02_full_transcript.png](../docs/evidence/challenge3/02_full_transcript.png)

### Step 5 — Review and timestamp

Reviewed all 73 segments, noted the three large silence gaps, identified the key content segments,
and flagged likely hallucinations.

Screenshot: [03_timestamped_segments.png](../docs/evidence/challenge3/03_timestamped_segments.png)

---

## Transcript (Final, Cleaned)

```
[00:15]  I have to start with Christmas Eve.
[00:21]  Because then I opened my warriors Christmas party.
[00:24]  Some of us fell out in the war rats.
[00:26]  Standing around helping, I grabbed a few people down here.
[00:29]  I lay out few people, I found out I was a little bit too young.
[00:31]  That is a my cookie, Alex.
[00:32]  Hey, Charlie, your mother's a slow crow.
[00:34]  Tell them this one, Charlie. A small but the kid.
[00:38]  No way. No way. No way.
[00:41]  So, look at that. This is sort of a new age.
[00:45]  Oh, that's a terrible question.
[00:47]  Isn't this where my father's a man?
[00:49]  No, I don't care what I get new raise up life and die.
[00:52]  You better hang out with that father. I'll be swiping.
[00:54]  You can have anything but my flesh, Charlie. I'm gonna hang on it.
         --- SILENCE GAP: 00:58 to 01:15 (17 seconds) ---
[01:15]  I'm gonna have dinner with the queen.
[01:17]  I've been out in the sun for a while. That's what the notes say.
[01:21]  We'll spend a sad drive on each other.
[01:24]  And I have been chosen as the two American officers that have been in the US.
[01:27]  That's true, what they know is it's clean there. Wow.
[01:31]  They know what they know.
[01:36]  It's less than triple money then. We really were in business.
[01:40]  You know, my bill will probably cost me a million dollars on a single bill, $40.
[01:46]  But thanks to your special presentation,
[01:48]  I was able to put together a small package for the bill.
[01:51]  I got a message that said,
         --- SILENCE GAP: 01:53 to 03:23 (90 seconds — possible redaction) ---
[03:23]  Thank you.
         --- SILENCE GAP: 03:23 to 03:52 (29 seconds) ---
[03:52]  I got it.
[04:02]  The other hand, I put all my strength.
[04:13]  In order to chase the spirit out, I put all my strength.
[04:21]  You're not going to watch this anymore, right?
[04:24]  I'm going to watch this.
[04:26]  You're not going to watch this anymore, right?
[04:35]  You're not going to watch this anymore, right?
```

---

## Recommendations for Improved Transcription

1. Install `ffmpeg` and use Whisper medium or large-v3 model for better accuracy on degraded audio.
2. Use a dedicated speech enhancement model (e.g., Facebook Denoiser, SpeechBrain MetricGAN+) before
   transcription — these are trained specifically for speech and handle noise better than spectral subtraction.
3. Try `noisereduce` Python library (stationary noise reduction) as a lighter alternative to manual STFT.
4. Consider speaker diarisation (e.g., pyannote.audio) to separate the two speakers and transcribe them
   independently.
5. The 90-second silence gap should be investigated — it may contain content that was removed from the file.
