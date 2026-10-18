// Pioneer DDJ-1000 jog-display HID driver for Mixxx.
//
// This is the HID half of the DDJ-1000 mapping. The MIDI half
// (Pioneer-DDJ-1000.midi.xml) handles all controls AND runs the SysEx cert
// handshake that unlocks the unit's HID "performance mode". This half owns the
// jog screens: it streams the 0x21 status frames that keep the deck view alive
// and, when a track is loaded, pushes the 0x2F beat grid and the 0x2C overview
// waveform for that deck.
//
// The two mappings are separate Mixxx controllers for one physical unit and do
// not share JS state. They don't need to: this driver streams unconditionally
// and watches its own HID input head (0x00 0x20 = performance mode) to learn
// when the MIDI side has unlocked the unit, re-pushing the render context then.
//
// Packet builders and the (shared) handshake crypto are in
// Pioneer-DDJ-1000-jog-lib.js (DDJ1000Jog).
//
// WAVEFORM DATA: stock Mixxx exposes no track overview waveform to controller
// scripts. This branch adds a small core hook, engine.getWaveformSummary(group,
// columns), returning the analysed overview as N columns of [all, low, mid,
// high] amplitudes. This driver uses it and only falls back to a synthesized
// placeholder pattern when the hook is absent (stock Mixxx) or the overview is
// not analysed yet (it retries while analysis runs). Everything else here --
// beat grid, status, playing state, duration -- is real engine data too.

// eslint-disable-next-line no-var
var PioneerDDJ1000HID = {};

PioneerDDJ1000HID.config = {
    // Paced sender tick. rekordbox streams 0x21 at ~120 Hz per deck; 8 ms
    // matches that. Needs this branch's 5 ms timer floor -- stock Mixxx clamps
    // timers to 20 ms (50 Hz), which still works, just less smoothly.
    tickMs: 8,
    burstChunk: 3,          // burst packets per tick (~375/s, as before)
    idleDeckEvery: 125,     // empty decks only need a slow keepalive (~1 s, in ticks)
    slewGain: 0.15,         // fraction of the position error corrected per tick
    snapMs: 150,            // larger errors (seek, hot cue, scratch) jump at once
    maxLagMs: 12,           // never trail/lead the engine by more than ~1 audio buffer
    wavePattern: "sine",    // placeholder: "sine" | "square" | "ramp" | "flat"
    renderDelayMs: 120,     // wait after a load before pushing context (let analysis settle)
    waveRetries: 20,        // re-check for the analysed waveform this many times...
    waveRetryMs: 500,       // ...every this many ms (covers slow analysis)
};

// HID deck N maps to Mixxx [ChannelN]. The left jog shows deck 1 or 3, the
// right jog deck 2 or 4; the unit routes a deck's data to the right screen.
PioneerDDJ1000HID.decks = [1, 2, 3, 4];

PioneerDDJ1000HID.group = function(deck) {
    return "[Channel" + deck + "]";
};

// Everything goes through Mixxx's non-skipping HID output FIFO (all our reports
// share reportID 0, so the skipping/coalescing path can't carry a multi-packet
// transfer). That FIFO holds only 32 reports and the IO thread drains one per
// loop, so we must NOT dump a 73-packet waveform in one go -- it overflows and
// packets are dropped. Instead a single paced tick flushes a bounded chunk of
// the burst queue (beat grid / waveform, which take priority) or, when the queue
// is empty, streams the current status frame for each loaded deck. That keeps
// the FIFO well under 32 while still giving a continuous status keepalive.
PioneerDDJ1000HID.sendReport = function(report) {
    controller.send(report, report.length, 0, true);
};

// Queue burst packets; the paced tick drains them a chunk at a time.
PioneerDDJ1000HID.pending = [];
PioneerDDJ1000HID.sendBurst = function(packets) {
    for (let i = 0; i < packets.length; i++) {
        PioneerDDJ1000HID.pending.push(packets[i]);
    }
};

PioneerDDJ1000HID.tickCount = 0;
PioneerDDJ1000HID.tick = function() {
    const cfg = PioneerDDJ1000HID.config;
    const pending = PioneerDDJ1000HID.pending;
    const idleTick = (PioneerDDJ1000HID.tickCount++ % cfg.idleDeckEvery) === 0;
    // Status first, every tick, so a burst (track load, cue edit) never stalls
    // the platter; then a bounded chunk of the burst queue. An empty deck gets
    // the "no track" status (trackLoaded:false) as a slow keepalive, so the jog
    // shows rekordbox's not-loaded view instead of its loading spinner -- but
    // only while the other deck on the same jog (1/3 left, 2/4 right) is empty
    // too. rekordbox never sends status for an empty deck once a track is up;
    // our "no track" frames for deck 3 landed on the left jog in the middle of
    // deck 1's stream and made its platter stutter.
    PioneerDDJ1000HID.decks.forEach((deck) => {
        const st = PioneerDDJ1000HID.state[deck];
        if (!st) {
            return;
        }
        if (!st.loaded) {
            const partner = PioneerDDJ1000HID.state[deck > 2 ? deck - 2 : deck + 2];
            if (!idleTick || (partner && partner.loaded)) {
                return;
            }
        }
        if (!st.loaded) {
            PioneerDDJ1000HID.sendReport(DDJ1000Jog.statusPacket({
                deck: deck,
                playing: false,
                trackLoaded: false,
            }));
            return;
        }
        // Read duration live (it may not have been set when the track first
        // loaded).
        const group = PioneerDDJ1000HID.group(deck);
        const durationMs = Math.round(engine.getValue(group, "duration") * 1000) || st.durationMs;
        const elapsedMs = PioneerDDJ1000HID.smoothElapsedMs(deck, group,
            PioneerDDJ1000HID.estimateElapsedMs(deck, group, durationMs), durationMs);
        const ratio = engine.getValue(group, "rate_ratio") || 1;
        const bpm = engine.getValue(group, "bpm");
        const cue = engine.getValue(group, "cue_point");
        PioneerDDJ1000HID.sendReport(DDJ1000Jog.statusPacket({
            deck: deck,
            playing: st.playing,
            // Dim the platter only while it is really at rest: a brake keeps
            // play on until the deck has stopped, and a paused deck being
            // scratched is moving.
            paused: !st.playing && !PioneerDDJ1000HID.scratching(group),
            trackLoaded: true,
            durationMs: durationMs,
            elapsedMs: elapsedMs,
            cueMs: cue >= 0 ? PioneerDDJ1000HID.samplesToMs(group, cue) : -1,
            bpm: bpm,
            ratePct: (ratio - 1) * 100,
        }));
    });
    const n = Math.min(cfg.burstChunk, pending.length);
    for (let i = 0; i < n; i++) {
        PioneerDDJ1000HID.sendReport(pending.shift());
    }
};

// engine.isScratching() only sees scratches started by THIS script; the scratch
// is started by the MIDI mapping (a separate controller), so read the engine's
// shared scratch2_enable control instead.
PioneerDDJ1000HID.scratching = function(group) {
    return engine.getValue(group, "scratch2_enable") > 0;
};

// The estimate above re-anchors on every 15 Hz playposition update, and the
// anchor's timestamp is when the callback reached the script, not when the
// engine produced it -- so each re-anchor nudges the position a few ms forward
// or back, which reads as judder at ~120 Hz. Instead run our own clock at the
// playing speed and steer it toward the estimate a little each tick, never
// faster than 1.5x or slower than 0.5x real speed so it can't run backwards.
// Large errors (seek, hot cue, scratch, pause) snap immediately.
PioneerDDJ1000HID.smoothElapsedMs = function(deck, group, target, durationMs) {
    const cfg = PioneerDDJ1000HID.config;
    const st = PioneerDDJ1000HID.state[deck];
    const now = Date.now();
    const moving = engine.getValue(group, "play") > 0 && !PioneerDDJ1000HID.scratching(group);
    const clock = st.clock;
    let ms = target;
    if (moving && clock) {
        const speed = (engine.getValue(group, "rate_ratio") || 1) *
            (engine.getValue(group, "reverse") ? -1 : 1);
        const step = (now - clock.at) * speed;
        const predicted = clock.ms + step;
        const err = target - predicted;
        if (Math.abs(err) <= cfg.snapMs) {
            const limit = Math.abs(step) * 0.5;
            ms = predicted + Math.max(-limit, Math.min(limit, err * cfg.slewGain));
            // Hard bound: a nudge or bend changes the speed without a scratch,
            // and the slew alone would let the platter trail the hand.
            ms = Math.max(target - cfg.maxLagMs, Math.min(target + cfg.maxLagMs, ms));
        }
    }
    ms = Math.min(Math.max(ms, 0), durationMs);
    st.clock = {ms: ms, at: now};
    return ms;
};

// Mixxx cue/hotcue positions are in (stereo) samples.
PioneerDDJ1000HID.samplesToMs = function(group, samples) {
    return samples * 1000 / ((engine.getValue(group, "track_samplerate") || 44100) * 2);
};

// Hot cues 1..16 as the unit's 0x30 list (all shown in rekordbox's default
// colour; the unit's colour numbering is the pad palette, not RGB).
PioneerDDJ1000HID.hotCuePackets = function(deck) {
    const group = PioneerDDJ1000HID.group(deck);
    const cues = [];
    for (let n = 1; n <= 16; n++) {
        const pos = engine.getValue(group, `hotcue_${n}_position`);
        if (engine.getValue(group, `hotcue_${n}_status`) > 0 && pos >= 0) {
            cues.push({slot: n - 1, ms: PioneerDDJ1000HID.samplesToMs(group, pos)});
        }
    }
    return DDJ1000Jog.hotCuePackets(deck, PioneerDDJ1000HID.state[deck].durationMs, cues);
};

// Mixxx updates playposition only 15 times a second, and the unit draws the
// spinning platter straight from the position we stream, so sending the raw
// value makes the platter step at 15 Hz. Between updates, advance it by the
// time passed at the current playing speed (as the MIDI mapping's
// estimateElapsed does for the standard-mode platter).
PioneerDDJ1000HID.estimateElapsedMs = function(deck, group, durationMs) {
    // Preferred: this branch's engine hook, the position as of the latest audio
    // buffer (what the waveforms render from). It also moves while scratching
    // or nudging a paused deck. Stock Mixxx lacks it; the estimate below is the
    // fallback.
    if (typeof engine.getEnginePlayPosition === "function") {
        const enginePos = engine.getEnginePlayPosition(group);
        if (enginePos >= 0) {
            return Math.min(enginePos, 1) * durationMs;
        }
    }
    const sample = PioneerDDJ1000HID.state[deck].position;
    let pos = engine.getValue(group, "playposition");
    if (!(pos >= 0)) {
        pos = 0;
    }
    const reported = Math.min(pos, 1) * durationMs;
    if (!sample || !engine.getValue(group, "play") || PioneerDDJ1000HID.scratching(group) || durationMs <= 0) {
        return reported;
    }
    const speed = (engine.getValue(group, "rate_ratio") || 1) * (engine.getValue(group, "reverse") ? -1 : 1);
    const ms = Math.min(100, Date.now() - sample.at);
    const estimate = Math.min(Math.max(sample.value, 0), 1) * durationMs + ms * speed;
    return Math.min(Math.max(estimate, 0), durationMs);
};

// ---------------------------------------------------------------------------
// Per-deck state and engine wiring
// ---------------------------------------------------------------------------
PioneerDDJ1000HID.state = {};
PioneerDDJ1000HID.connections = [];
PioneerDDJ1000HID.unlocked = false;
PioneerDDJ1000HID.statusTimer = 0;

PioneerDDJ1000HID.newState = function() {
    return {loaded: false, playing: false, durationMs: 0, bpm: 0, loadTimer: 0,
        waveTries: 0, gotRealWave: false, position: null, clock: null, cueTimer: 0};
};

PioneerDDJ1000HID.init = function() {
    if (typeof DDJ1000Jog === "undefined") {
        engine.log("DDJ-1000 HID: jog-lib not loaded; jog screens disabled");
        return;
    }
    PioneerDDJ1000HID.decks.forEach((deck) => {
        const group = PioneerDDJ1000HID.group(deck);
        PioneerDDJ1000HID.state[deck] = PioneerDDJ1000HID.newState();
        PioneerDDJ1000HID.connect(group, "track_loaded", (v) => PioneerDDJ1000HID.onLoad(deck, v));
        PioneerDDJ1000HID.connect(group, "play", (v) => {
            PioneerDDJ1000HID.state[deck].playing = v > 0.5;
        });
        PioneerDDJ1000HID.connect(group, "playposition", (v) => {
            PioneerDDJ1000HID.state[deck].position = {value: v, at: Date.now()};
        });
        // Re-send the hot-cue list when one changes, as rekordbox does. Batched
        // through a short one-shot so clearing/setting several is one transfer.
        for (let n = 1; n <= 16; n++) {
            ["status", "position"].forEach((key) => {
                PioneerDDJ1000HID.connect(group, `hotcue_${n}_${key}`, () => PioneerDDJ1000HID.cuesChanged(deck));
            });
        }
        // Pick up a track already loaded when the mapping starts.
        if (engine.getValue(group, "track_loaded") > 0.5) {
            PioneerDDJ1000HID.onLoad(deck, 1);
        }
    });
    PioneerDDJ1000HID.statusTimer = engine.beginTimer(
        PioneerDDJ1000HID.config.tickMs, PioneerDDJ1000HID.tick);
};

PioneerDDJ1000HID.shutdown = function() {
    if (PioneerDDJ1000HID.statusTimer) {
        engine.stopTimer(PioneerDDJ1000HID.statusTimer);
        PioneerDDJ1000HID.statusTimer = 0;
    }
    PioneerDDJ1000HID.decks.forEach((deck) => {
        const st = PioneerDDJ1000HID.state[deck];
        if (st && st.loadTimer) {
            engine.stopTimer(st.loadTimer);
        }
        if (st && st.cueTimer) {
            engine.stopTimer(st.cueTimer);
        }
    });
    // Drop any queued burst and let the stream stop; performance mode reverts on
    // its own within ~1 s, returning the jog to the standard view. (We can't
    // reliably pace a clear burst while shutting down.)
    PioneerDDJ1000HID.pending = [];
    PioneerDDJ1000HID.connections.forEach((c) => c.disconnect());
    PioneerDDJ1000HID.connections = [];
};

PioneerDDJ1000HID.connect = function(group, key, cb) {
    const c = engine.makeConnection(group, key, cb);
    if (c) {
        PioneerDDJ1000HID.connections.push(c);
    }
    return c;
};

// ---------------------------------------------------------------------------
// Track load -> render context (beat grid + waveform)
// ---------------------------------------------------------------------------
PioneerDDJ1000HID.onLoad = function(deck, loaded) {
    const st = PioneerDDJ1000HID.state[deck];
    st.loaded = loaded > 0.5;
    if (st.loadTimer) {
        engine.stopTimer(st.loadTimer);
        st.loadTimer = 0;
    }
    if (!st.loaded) {
        return;
    }
    st.waveTries = 0;
    st.gotRealWave = false;
    st.gridSent = false;
    st.placeholderSent = false;
    st.artSent = false;
    st.cuesSent = false;
    // Defer: at the instant track_loaded fires, duration/bpm may not be set yet.
    st.loadTimer = engine.beginTimer(PioneerDDJ1000HID.config.renderDelayMs, () => {
        st.loadTimer = 0;
        PioneerDDJ1000HID.renderContext(deck);
    }, true);
};

PioneerDDJ1000HID.cuesChanged = function(deck) {
    const st = PioneerDDJ1000HID.state[deck];
    if (!st || !st.loaded || !st.cuesSent || st.cueTimer) {
        return;
    }
    st.cueTimer = engine.beginTimer(50, () => {
        st.cueTimer = 0;
        if (st.loaded) {
            PioneerDDJ1000HID.sendBurst(PioneerDDJ1000HID.hotCuePackets(deck));
            PioneerDDJ1000HID.sendBurst(DDJ1000Jog.cueInfoPackets(deck, st.durationMs));
        }
    }, true);
};

// Send the static render context ONCE per load: beat grid, then the waveform.
// The overview waveform must be sent as few times as possible -- re-sending it
// forces a full redraw on the unit (visible blink) and floods the single HID IO
// thread, which makes the whole jog display lag. So the waveform goes out at
// most twice: a placeholder immediately, then the real analysed data once it is
// ready. Retries only re-check for data; they never re-send the placeholder.
PioneerDDJ1000HID.renderContext = function(deck) {
    const group = PioneerDDJ1000HID.group(deck);
    const st = PioneerDDJ1000HID.state[deck];
    const durationS = engine.getValue(group, "duration");
    let bpm = engine.getValue(group, "bpm");
    if (!(bpm > 0)) {
        bpm = engine.getValue(group, "file_bpm");
    }
    st.durationMs = Math.round((durationS || 0) * 1000);
    st.bpm = bpm || 0;

    // Beat grid once (constant-BPM across the track).
    if (!st.gridSent && st.bpm > 0 && st.durationMs > 0) {
        PioneerDDJ1000HID.sendBurst(DDJ1000Jog.beatgridPackets(
            deck, DDJ1000Jog.makeBeats(st.bpm, st.durationMs, 0)));
        st.gridSent = true;
    }

    // Cue lists once, right after the grid (rekordbox order: 0x2F, 0x30, 0x2D).
    if (!st.cuesSent && st.durationMs > 0) {
        PioneerDDJ1000HID.sendBurst(PioneerDDJ1000HID.hotCuePackets(deck));
        PioneerDDJ1000HID.sendBurst(DDJ1000Jog.cueInfoPackets(deck, st.durationMs));
        st.cuesSent = true;
    }

    // Cover art once (rekordbox sends it after the grid, before the waveform).
    // Like the waveform it needs an engine hook; getCoverArt returns an empty
    // array until the track's cover is available, so a failed attempt just
    // retries on the next pass.
    if (!st.artSent && typeof engine.getCoverArt === "function") {
        const art = engine.getCoverArt(group, 80, DDJ1000Jog.ART_MAX);
        if (art && art.length > 0) {
            PioneerDDJ1000HID.sendBurst(DDJ1000Jog.artPackets(deck, art));
            st.artSent = true;
        }
    }

    // Real analysed overview if the engine hook has it yet.
    let realPoints = null;
    if (typeof engine.getWaveformSummary === "function") {
        const summary = engine.getWaveformSummary(group, DDJ1000Jog.WAVE_POINTS);
        if (summary && summary.length > 0) {
            realPoints = DDJ1000Jog.wavePointsFromSummary(summary);
        }
    }
    if (realPoints) {
        PioneerDDJ1000HID.sendBurst(DDJ1000Jog.wavePackets(deck, realPoints, false, true));
        st.gotRealWave = true;
        return; // done -- no more waveform sends for this track
    }
    // No real data yet: show the placeholder once, then only re-check (no resend).
    if (!st.placeholderSent) {
        PioneerDDJ1000HID.sendBurst(DDJ1000Jog.wavePackets(
            deck, DDJ1000Jog.patternPoints(PioneerDDJ1000HID.config.wavePattern), false, true));
        st.placeholderSent = true;
    }
    if (st.waveTries < PioneerDDJ1000HID.config.waveRetries && !st.loadTimer) {
        st.waveTries++;
        st.loadTimer = engine.beginTimer(PioneerDDJ1000HID.config.waveRetryMs, () => {
            st.loadTimer = 0;
            if (st.loaded && !st.gotRealWave) {
                PioneerDDJ1000HID.renderContext(deck);
            }
        }, true);
    }
};

// ---------------------------------------------------------------------------
// Input: detect performance-mode unlock from the HID input head (00 20).
// When the MIDI side completes the handshake the unit flips its input head to
// 0x00 0x20; that's our cue to (re-)push each loaded deck's render context, in
// case we pushed it while the unit was still in standard mode and ignored it.
// ---------------------------------------------------------------------------
PioneerDDJ1000HID.incomingData = function(data) {
    const bytes = (data instanceof ArrayBuffer) ? new Uint8Array(data) : data;
    if (!bytes || bytes.length < 2) {
        return;
    }
    const performance = bytes[0] === 0x00 && (bytes[1] & 0x20) !== 0;
    if (performance && !PioneerDDJ1000HID.unlocked) {
        PioneerDDJ1000HID.unlocked = true;
        engine.log("DDJ-1000 HID: unit in performance mode; pushing render context");
        PioneerDDJ1000HID.decks.forEach((deck) => {
            if (PioneerDDJ1000HID.state[deck] && PioneerDDJ1000HID.state[deck].loaded) {
                PioneerDDJ1000HID.renderContext(deck);
            }
        });
    } else if (!performance && PioneerDDJ1000HID.unlocked && bytes[0] === 0x00) {
        PioneerDDJ1000HID.unlocked = false;
    }
};
