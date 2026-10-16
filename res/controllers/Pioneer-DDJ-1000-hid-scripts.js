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
    statusIntervalMs: 20,   // ~50 frames/s per loaded deck (keepalive + liveness)
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

// Send one 64-byte report (reportID 0). nonSkipping=true forces strict FIFO
// delivery with no de-duplication -- mandatory for the multi-packet beatgrid/
// waveform bursts (every packet shares reportID 0) and for the status stream
// (identical frames must still reach the unit to hold performance mode).
PioneerDDJ1000HID.sendReport = function(report, nonSkipping) {
    controller.send(report, report.length, 0, nonSkipping === true);
};

PioneerDDJ1000HID.sendBurst = function(packets) {
    for (let i = 0; i < packets.length; i++) {
        PioneerDDJ1000HID.sendReport(packets[i], true);
    }
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
        PioneerDDJ1000HID.config.statusIntervalMs, PioneerDDJ1000HID.statusTick);
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
        // Clear the deck's waveform (enable bit off) so the screen is tidy.
        if (st && st.loaded) {
            const empty = [];
            for (let i = 0; i < DDJ1000Jog.WAVE_POINTS; i++) {
                empty.push(DDJ1000Jog.wavePoint(0, 0, 0, 0));
            }
            PioneerDDJ1000HID.sendBurst(DDJ1000Jog.wavePackets(deck, empty, false, false));
        }
    });
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
    // Defer: at the instant track_loaded fires, duration/bpm may not be set yet.
    st.loadTimer = engine.beginTimer(PioneerDDJ1000HID.config.renderDelayMs, () => {
        st.loadTimer = 0;
        PioneerDDJ1000HID.renderContext(deck);
    }, true);
};

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

    // Beat grid (real): a constant-BPM grid across the track. A future refinement
    // can walk Mixxx's actual (possibly non-constant) beats via beat_next.
    if (st.bpm > 0 && st.durationMs > 0) {
        const beats = DDJ1000Jog.makeBeats(st.bpm, st.durationMs, 0);
        PioneerDDJ1000HID.sendBurst(DDJ1000Jog.beatgridPackets(deck, beats));
    }

    // Overview waveform. Prefer real analysed data from the engine hook
    // (engine.getWaveformSummary, added for controllers with their own
    // displays); fall back to a placeholder pattern if the build lacks the
    // hook or the overview is not analysed yet.
    let points = null;
    if (typeof engine.getWaveformSummary === "function") {
        const summary = engine.getWaveformSummary(group, DDJ1000Jog.WAVE_POINTS);
        if (summary && summary.length > 0) {
            points = DDJ1000Jog.wavePointsFromSummary(summary);
            st.gotRealWave = true;
        }
    }
    if (!points) {
        points = DDJ1000Jog.patternPoints(PioneerDDJ1000HID.config.wavePattern);
        // Analysis is asynchronous: the overview may not be ready right after
        // load. Retry a few times so the real waveform replaces the placeholder
        // once it is analysed.
        if (st.waveTries < PioneerDDJ1000HID.config.waveRetries && !st.loadTimer) {
            st.waveTries++;
            st.loadTimer = engine.beginTimer(PioneerDDJ1000HID.config.waveRetryMs, () => {
                st.loadTimer = 0;
                if (st.loaded && !st.gotRealWave) {
                    PioneerDDJ1000HID.renderContext(deck);
                }
            }, true);
        }
    }
    PioneerDDJ1000HID.sendBurst(DDJ1000Jog.wavePackets(deck, points, false, true));
};

// ---------------------------------------------------------------------------
// Status stream (keeps the deck view alive; carries playing/loaded/duration)
// ---------------------------------------------------------------------------
PioneerDDJ1000HID.statusTick = function() {
    PioneerDDJ1000HID.decks.forEach((deck) => {
        const st = PioneerDDJ1000HID.state[deck];
        if (!st || !st.loaded) {
            return;
        }
        const report = DDJ1000Jog.statusPacket({
            deck: deck,
            playing: st.playing,
            trackLoaded: true,
            durationMs: st.durationMs,
        });
        PioneerDDJ1000HID.sendReport(report, true);
    });
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
