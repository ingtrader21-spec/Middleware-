#!/usr/bin/env python3
"""Generate the bounded, non-copyrighted fixture-6198 media source."""
import math
import struct
import wave
from pathlib import Path


OUTPUT = Path("/run/codestra-fixture-6198/test-tone-8k-mono-s16.wav")
SAMPLE_RATE = 8000
DURATION_SECONDS = 10
FREQUENCY_HZ = 1000
AMPLITUDE = 8000

OUTPUT.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
with wave.open(str(OUTPUT), "wb") as output:
    output.setnchannels(1)
    output.setsampwidth(2)
    output.setframerate(SAMPLE_RATE)
    for index in range(SAMPLE_RATE * DURATION_SECONDS):
        sample = int(
            AMPLITUDE * math.sin(2 * math.pi * FREQUENCY_HZ * index / SAMPLE_RATE)
        )
        output.writeframesraw(struct.pack("<h", sample))
OUTPUT.chmod(0o600)
