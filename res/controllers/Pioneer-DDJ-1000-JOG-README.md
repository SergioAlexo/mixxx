# Pioneer DDJ-1000 jog displays in Mixxx — MIDI→HID reimplementation

This adds the DDJ-1000's **jog-wheel screens** to Mixxx, driven entirely by open
code. It builds on the live, no-rekordbox unlock proven in
`DDJ1000_JOG_WAVEFORM_SOLVED.md`: the jog screens live on the unit's **HID**
performance mode, which is gated by a **MIDI SysEx cert handshake** (FNV-1a, no
per-unit secret). The earlier community mapping and the `sergioalexo` jog-display
notes concluded the handshake needed an unknowable secret and gave up on the
screens — that blocker is gone.

## Architecture: two mappings, one unit

The DDJ-1000 exposes a USB-MIDI interface **and** an HID interface at the same
time. Mixxx enumerates them as two devices, so this is two mappings — load both:

| File | Protocol | Job |
|---|---|---|
| `Pioneer-DDJ-1000.midi.xml` + `-scripts.js` | MIDI | All controls (unchanged) **plus** the cert handshake: arm poll `50 01`, challenge/response `0x12/0x14`, and the keepalive. |
| `Pioneer-DDJ-1000.hid.xml` + `-hid-scripts.js` | HID | The jog screens: streams `0x21` status (deck view + keepalive), and on load pushes `0x2F` beat grid and the `0x2C` overview waveform. |
| `Pioneer-DDJ-1000-jog-lib.js` | — | Shared, pure library: handshake crypto + all packet builders. Loaded by both. Node-testable. |

They are separate Mixxx controllers and share no JS state — they don't need to.
The MIDI side runs the handshake; the HID side streams unconditionally and
watches its own HID input head (`00 20` = performance mode) to learn when the
unit has been unlocked, re-pushing the beat grid + waveform at that moment.

Why the handshake lives in the MIDI mapping (not HID): the handshake is MIDI
SysEx, and a Mixxx HID mapping cannot send MIDI. Why the screens live in the HID
mapping: the waveform/status reports are HID, and a MIDI mapping cannot send HID.

## Install / try it

Copy the five `Pioneer-DDJ-1000*` files into your Mixxx controller mappings
folder (or run this Mixxx build), then in **Preferences → Controllers** enable
**both** the "Pioneer DDJ-1000" (MIDI) and "Pioneer DDJ-1000 (Jog Displays)"
(HID) mappings for the unit. Load a track; the deck view with a beat grid and a
(placeholder) waveform should appear on the jog screen.

The handshake can be disabled (leaving the unit in plain MIDI mode) by setting
`PioneerDDJ1000.jog.enabled = false`.

## What is real vs. placeholder

Real engine data: deck view, beat grid (from `bpm` + `duration`), track-loaded
and playing state, track length, **and the overview waveform** (see below). The
handshake, arm, keepalive, and all packet framing are the proven protocol.

**Waveform data:** this branch adds a small core hook,
`engine.getWaveformSummary(group, columns)`, which returns a track's analysed
overview resampled to N columns of `[all, low, mid, high]` band amplitudes
(0..255). The HID driver uses it (`wavePointsFromSummary`) and falls back to a
synthesized pattern (`PioneerDDJ1000HID.config.wavePattern`) only when the hook
is absent (stock Mixxx) or the overview is not analysed yet — it retries while
analysis runs. Stock Mixxx exposes no waveform data to controller scripts; the
hook lives in `src/controllers/scripting/legacy/controllerscriptinterfacelegacy.*`.

## Remaining work

1. **Live playhead.** `0x21` status bytes 12–14 (position) are not yet decoded,
   so the status stream currently holds a static position (the beat grid still
   gives the time axis). Decode and feed live `playposition`.
2. **Artwork (`0x2B`).** Needs the cover-art JPEG bytes, not yet exposed to JS —
   a second small core hook, like the waveform one.
3. **Windows:** confirm Mixxx can open the HID output interface alongside the
   MIDI mapping while the ASIO driver owns the audio device.

## Testing

The library and both state machines have Node self-tests (no hardware needed):

```bash
node res/controllers/Pioneer-DDJ-1000-jog-lib.js   # crypto + packet builders vs. the Python reference
```

The handshake JS is verified byte-for-byte against `stage4/ddj_cert.py`, and the
packet builders against `stage3/tools/ddj_jog.py`.
