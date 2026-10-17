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
    tickMs: 20,             // paced sender tick (~50 Hz)
    burstChunk: 8,          // packets flushed per tick from the burst queue
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

PioneerDDJ1000HID.tick = function() {
    const pending = PioneerDDJ1000HID.pending;
    if (pending.length > 0) {
        // Burst in progress: flush a chunk, skip status this tick.
        const n = Math.min(PioneerDDJ1000HID.config.burstChunk, pending.length);
        for (let i = 0; i < n; i++) {
            PioneerDDJ1000HID.sendReport(pending.shift());
        }
        return;
    }
    // Idle: stream status for each deck (keepalive + live position). An empty
    // deck still gets a frame -- the "no track" status (trackLoaded:false) --
    // so the jog shows rekordbox's not-loaded view instead of sitting on its
    // default loading spinner forever.
    PioneerDDJ1000HID.decks.forEach((deck) => {
        const st = PioneerDDJ1000HID.state[deck];
        if (!st) {
            return;
        }
        if (!st.loaded) {
            PioneerDDJ1000HID.sendReport(DDJ1000Jog.statusPacket({
                deck: deck,
                playing: false,
                trackLoaded: false,
            }));
            return;
        }
        // playposition is 0..1 over the track; scale to elapsed ms for the
        // jog's moving cursor (bytes 11-13 = elapsed * 256). Read duration live
        // (it may not have been set when the track first loaded).
        const group = PioneerDDJ1000HID.group(deck);
        let pos = engine.getValue(group, "playposition");
        if (!(pos >= 0)) {
            pos = 0;
        }
        const durationMs = Math.round(engine.getValue(group, "duration") * 1000) || st.durationMs;
        const elapsedMs = pos * durationMs;
        PioneerDDJ1000HID.sendReport(DDJ1000Jog.statusPacket({
            deck: deck,
            playing: st.playing,
            trackLoaded: true,
            durationMs: durationMs,
            elapsedMs: elapsedMs,
        }));
    });
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
        waveTries: 0, gotRealWave: false};
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
    // Defer: at the instant track_loaded fires, duration/bpm may not be set yet.
    st.loadTimer = engine.beginTimer(PioneerDDJ1000HID.config.renderDelayMs, () => {
        st.loadTimer = 0;
        PioneerDDJ1000HID.renderContext(deck);
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
