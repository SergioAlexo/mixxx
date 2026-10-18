// Pioneer DDJ-1000 jog-display library for Mixxx.
//
// Pure, side-effect-free protocol code shared by the MIDI mapping (the SysEx
// unlock handshake) and the HID mapping (the jog-screen packet stream). No
// Mixxx API is touched here, so this file also runs under plain Node for the
// self-test at the bottom (`node Pioneer-DDJ-1000-jog-lib.js`).
//
// Provenance: reverse-engineered from the owner's own DDJ-1000 (firmware
// v1.12) and from Windows USBPcap captures of rekordbox 7.2.18. The handshake
// is FNV-1a + XOR with a universal constant -- no per-unit secret -- which is
// what lets open software pass the same cert rekordbox does and unlock the HID
// performance mode where the jog waveform lives. See DDJ1000_JOG_WAVEFORM_SOLVED.md.
//
// Transports (two separate Mixxx controllers for one physical unit):
//   * MIDI SysEx  -> arm poll `50 01`, handshake 0x12/0x13/0x14, keepalive.
//   * HID iface 3 -> 0x21 status, 0x2F beatgrid, 0x2B artwork, 0x2C waveform.

// eslint-disable-next-line no-var
var DDJ1000Jog = (function() {
    "use strict";

    // -----------------------------------------------------------------------
    // Handshake crypto (ported from stage4/ddj_cert.py)
    // -----------------------------------------------------------------------
    var FNV_OFF = 0x811c9dc5;
    var FNV_PRIME = 0x01000193;

    // Universal constant k = FNV1a(~"PioneerD"); identical on every DDJ-1000.
    var K = 0x680131fb;

    // Fixed tag-5 block rekordbox sends in 0x14, unchanged every session. The
    // firmware's checks on it compare against a fixed constant, so one valid
    // block is valid forever. 10 bytes.
    var TAG5 = [0x87, 0xa0, 0x8e, 0xea, 0xc0, 0x90, 0x34, 0x76, 0x0b, 0x90];

    // Pioneer SysEx envelope: F0 00 40 05 00 00 02 00 00 <type><len> <blocks> F7
    var HDR = [0xf0, 0x00, 0x40, 0x05, 0x00, 0x00, 0x02, 0x00, 0x00];

    // 32-bit FNV-1a. Math.imul keeps the multiply inside int32 without losing
    // the low bits to float rounding; `>>> 0` forces the unsigned result.
    function fnv1a(bytes) {
        var h = FNV_OFF;
        for (var i = 0; i < bytes.length; i++) {
            h = Math.imul(h ^ (bytes[i] & 0xff), FNV_PRIME) >>> 0;
        }
        return h >>> 0;
    }

    function be32(value) {
        value = value >>> 0;
        return [(value >>> 24) & 0xff, (value >>> 16) & 0xff,
            (value >>> 8) & 0xff, value & 0xff];
    }

    // big-endian value over nbytes -> one nibble per byte (low 4 bits), MSB first.
    function nibblesOf(bytesArray) {
        var out = [];
        for (var i = 0; i < bytesArray.length; i++) {
            out.push((bytesArray[i] >>> 4) & 0xf);
            out.push(bytesArray[i] & 0xf);
        }
        return out;
    }

    function valueFromNibbles(nb) {
        // Returned as unsigned 32-bit via >>> 0 at the end.
        var v = 0;
        for (var i = 0; i < nb.length; i++) {
            v = ((v << 4) | (nb[i] & 0xf)) >>> 0;
        }
        return v >>> 0;
    }

    function block(tag, data) {
        return [tag, data.length + 2].concat(data);
    }

    function wrap(msgType, blocks) {
        var payload = [msgType, 2 + blocks.length].concat(blocks);
        return HDR.concat(payload).concat([0xf7]);
    }

    // The arm poll that moves the unit from idle into "cert armed".
    function buildArm() {
        return HDR.concat([0x50, 0x01, 0xf7]);
    }

    // "Report all control positions": the unit answers within ~1 ms with a CC
    // dump of every fader/knob (tempo, trim, EQ, volume) on all four decks and
    // the mixer, as 14-bit MSB/LSB pairs. rekordbox sends this on connect to
    // sync the software to the hardware; the unit does not report positions on
    // its own. Captured from rekordbox: F0 00 40 05 00 00 02 00 00 03 01 F7.
    function buildRequestState() {
        return HDR.concat([0x03, 0x01, 0xf7]);
    }

    // Post-handshake display-config SysEx (types 0x0a/0x0b/0x0c), captured from
    // rekordbox's init burst. These move the jog from the idle logo into the
    // performance-mode deck view; without them the unit shows a loading spinner
    // after 0x15. Sent once on unlock. (The rest of rekordbox's init burst is
    // LED/pad state, which this mapping already drives from Mixxx.)
    var DECK_VIEW_HEX = [
        "f00040050000020000000a0028002600183d3a0564502a5440141a0469130000000000000000000000000000000000000000000000f7",
        "f00040050000020000000b310000000000f7",
        "f00040050000020000000c0000020e0e000000f7",
    ];

    function hexToBytes(h) {
        var out = [];
        for (var i = 0; i + 1 < h.length; i += 2) {
            out.push(parseInt(h.substr(i, 2), 16));
        }
        return out;
    }

    function deckViewSysex() {
        return DECK_VIEW_HEX.map(hexToBytes);
    }

    // Host challenge: 8 bytes (not all-00, not all-FF).
    function buildMsg12(hostChallenge) {
        var blocks = block(1, strBytes("PioneerDJ"))
            .concat(block(2, strBytes("rekordbox")))
            .concat(block(3, nibblesOf(hostChallenge)));
        return wrap(0x12, blocks);
    }

    // Our answer to the unit nonce r:  FNV1a( BE(r) ++ BE(k ^ r) ).
    function hostAnswer(r) {
        var kr = (K ^ r) >>> 0;
        return fnv1a(be32(r).concat(be32(kr)));
    }

    // What the unit must have placed in 0x13 tag-4 (self-check of the reply):
    //   FNV1a( HC(8 bytes) ++ BE(k ^ r) ).
    function predictUnitAnswer(hostChallenge, r) {
        var kr = (K ^ r) >>> 0;
        return fnv1a(hostChallenge.concat(be32(kr)));
    }

    function buildMsg14(r) {
        var ans = hostAnswer(r);
        var blocks = block(1, strBytes("PioneerDJ"))
            .concat(block(2, strBytes("rekordbox")))
            .concat(block(4, nibblesOf(be32(ans))))
            .concat(block(5, nibblesOf(TAG5)));
        return wrap(0x14, blocks);
    }

    // Validate envelope, return the [type][len][blocks] payload, or null.
    function strip(sysex) {
        var s = toBytes(sysex);
        if (s.length < 12 || s[0] !== 0xf0 || s[s.length - 1] !== 0xf7) {
            return null;
        }
        if (s[1] !== 0x00 || s[2] !== 0x40 || s[3] !== 0x05 ||
            s[4] !== 0x00 || s[5] !== 0x00 || s[6] !== 0x02 || s[7] !== 0x00) {
            return null;
        }
        return s.slice(9, s.length - 1);
    }

    function tlv(blocks) {
        var out = {};
        var i = 0;
        while (i + 1 < blocks.length) {
            var tag = blocks[i];
            var blen = blocks[i + 1];
            if (blen < 2) {
                break;
            }
            out[tag] = blocks.slice(i + 2, i + blen);
            i += blen;
        }
        return out;
    }

    function msgType(sysex) {
        var body = strip(sysex);
        return body === null ? null : body[0];
    }

    function isReady(sysex) {
        return msgType(sysex) === 0x11;
    }

    function isAccept(sysex) {
        return msgType(sysex) === 0x15;
    }

    // Parse the unit's 0x13 reply -> { r, unitAnswer }, or null.
    function parse13(sysex) {
        var body = strip(sysex);
        if (body === null || body[0] !== 0x13) {
            return null;
        }
        var fields = tlv(body.slice(2));
        return {
            r: fields[3] ? valueFromNibbles(fields[3]) : null,
            unitAnswer: fields[4] ? valueFromNibbles(fields[4]) : null,
        };
    }

    // -----------------------------------------------------------------------
    // HID jog-display packets (ported from stage3/tools/ddj_jog.py)
    // -----------------------------------------------------------------------
    var REPORT_LEN = 64;
    var MSG_STATUS = 0x21, MSG_ART = 0x2b, MSG_WAVE = 0x2c, MSG_BEATGRID = 0x2f;
    var WAVE_POINTS = 600, WAVE_POINT_LEN = 7, WAVE_MAX_H = 40;
    var WAVE_BYTES = WAVE_POINTS * WAVE_POINT_LEN; // 4200
    var ART_MAX = 0x2800; // 10240

    function rgb565(r, g, b) {
        return (((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)) & 0xffff;
    }

    function clamp(v, lo, hi) {
        v = Math.round(v);
        return v < lo ? lo : (v > hi ? hi : v);
    }

    // One 7-byte waveform column. Heights 0..40 px; inner bar drawn over the
    // outer and clamped to it. colOuter/colInner are RGB565; colOuter === 0
    // selects firmware preset colour `preset` (0..7). Little-endian u16s.
    function wavePoint(hOuter, hInner, colOuter, colInner, preset) {
        preset = preset || 0;
        var ho = clamp(hOuter, 0, WAVE_MAX_H);
        var hi = clamp(hInner, 0, ho);
        return [colOuter & 0xff, (colOuter >> 8) & 0xff,
            colInner & 0xff, (colInner >> 8) & 0xff,
            ho, hi, preset & 7];
    }

    function hdr(deck, msg, idx, total) {
        return [(deck << 4) & 0xf0, msg, idx & 0xff, (idx >> 8) & 0xff,
            total & 0xff, (total >> 8) & 0xff];
    }

    function padTo(arr, n) {
        var out = arr.slice(0);
        while (out.length < n) {
            out.push(0);
        }
        return out;
    }

    // Split 600 columns into the 0x2C packet stream (73 packets).
    //   packet 1 : hdr(6) + flags(1) + data[0:57]
    //   packet n : hdr(6) + data[57 + 58*(n-2) : +58]      (fw offset 58n-59)
    function wavePackets(deck, points, centered, enable) {
        var data = [];
        for (var p = 0; p < points.length; p++) {
            data = data.concat(points[p]);
        }
        if (data.length !== WAVE_BYTES) {
            throw new Error("need exactly " + WAVE_POINTS + " columns");
        }
        var first = 57, rest = 58;
        var total = 1 + Math.ceil((data.length - first) / rest);
        var flags = (enable === false ? 0 : 0x80) | (centered ? 0x40 : 0);
        var pkts = [padTo(hdr(deck, MSG_WAVE, 1, total)
            .concat([flags]).concat(data.slice(0, first)), REPORT_LEN)];
        for (var n = 2; n <= total; n++) {
            var off = rest * n - 59;
            pkts.push(padTo(hdr(deck, MSG_WAVE, n, total)
                .concat(data.slice(off, off + rest)), REPORT_LEN));
        }
        return pkts;
    }

    // 0x2B artwork (baseline JPEG, 80x80, <= 10240 bytes).
    //   packet 1 : hdr(6) + u16 size + data[0:56]
    //   packet n : hdr(6) + data[58n-60 : +58]
    function artPackets(deck, blob) {
        if (blob.length > ART_MAX) {
            throw new Error("artwork must be <= " + ART_MAX + " bytes");
        }
        var first = 56, rest = 58;
        var total = 1 + Math.max(0, Math.ceil((blob.length - first) / rest));
        var pkts = [padTo(hdr(deck, MSG_ART, 1, total)
            .concat([blob.length & 0xff, (blob.length >> 8) & 0xff])
            .concat(blob.slice(0, first)), REPORT_LEN)];
        for (var n = 2; n <= total; n++) {
            var off = rest * n - 60;
            pkts.push(padTo(hdr(deck, MSG_ART, n, total)
                .concat(blob.slice(off, off + rest)), REPORT_LEN));
        }
        return pkts;
    }

    // 0x2F beat grid: u16 LE count, then count x (beatInBar 1..4, posMs u24 LE),
    // chunked over the same header. beats = [{bar: 1..4, ms: <int>}, ...].
    function beatgridPackets(deck, beats) {
        var body = [beats.length & 0xff, (beats.length >> 8) & 0xff];
        for (var i = 0; i < beats.length; i++) {
            var ms = beats[i].ms | 0;
            body.push(beats[i].bar & 0xff, ms & 0xff, (ms >> 8) & 0xff, (ms >> 16) & 0xff);
        }
        var first = 52, rest = 58; // payload room after the 6-byte header
        var total = 1 + Math.max(0, Math.ceil((body.length - first) / rest));
        var pkts = [padTo(hdr(deck, MSG_BEATGRID, 1, total)
            .concat(body.slice(0, first)), REPORT_LEN)];
        for (var n = 2; n <= total; n++) {
            var off = first + rest * (n - 2);
            pkts.push(padTo(hdr(deck, MSG_BEATGRID, n, total)
                .concat(body.slice(off, off + rest)), REPORT_LEN));
        }
        return pkts;
    }

    // Build the regular beat list for a constant-BPM track: a beat every
    // 60000/bpm ms from firstBeatMs to durationMs, bar counter cycling 1..4.
    function makeBeats(bpm, durationMs, firstBeatMs) {
        if (!(bpm > 0) || !(durationMs > 0)) {
            return [];
        }
        var period = 60000.0 / bpm;
        var beats = [];
        var bar = 1;
        for (var t = firstBeatMs || 0; t < durationMs; t += period) {
            beats.push({bar: bar, ms: Math.round(t)});
            bar = bar >= 4 ? 1 : bar + 1;
        }
        return beats;
    }

    // -----------------------------------------------------------------------
    // 0x21 status. Byte layout is only partly decoded (see
    // ddj1000-mixxx-repo/JOG_DISPLAY_PROTOCOL.md), so we start from a captured
    // track-loaded/playing frame proven to render the deck view, and patch in
    // only the fields whose meaning is verified.
    // -----------------------------------------------------------------------
    var STATUS_TEMPLATE = [
        0x10, 0x21, 0x18, 0x0a, 0x11, 0x81, 0x00, 0x00, 0x00, 0xb4,
        0x00, 0x00, 0x00, 0x15, 0x00, 0x02, 0x01, 0x39, 0x03, 0x00,
        0x00, 0x86, 0x40, 0xd3, 0xff, 0x00, 0x00, 0x80, 0x00, 0x00,
        0x00, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0x40,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x01, 0x00,
        0x02, 0x0d, 0x00, 0x00];

    function putU24le(r, at, v) {
        r[at] = v & 0xff;
        r[at + 1] = (v >> 8) & 0xff;
        r[at + 2] = (v >> 16) & 0xff;
    }

    // A time as the unit encodes it: minutes, seconds, then milliseconds as a
    // u16 LE (4 bytes), e.g. 0:09.388 = 00 09 84 01.
    function timeBytes(ms) {
        ms = Math.max(0, Math.round(ms));
        var sec = Math.floor(ms / 1000);
        return [Math.min(255, Math.floor(sec / 60)), sec % 60,
            (ms % 1000) & 0xff, ((ms % 1000) >> 8) & 0xff];
    }

    // opts: { deck, playing (bool), trackLoaded (bool), durationMs, elapsedMs,
    //         cueMs, bpm, ratePct, paused, slip }.
    // Returns one 64-byte status report. Fields that are not yet decoded keep
    // the captured template value.
    //
    // Bytes 11-14 = elapsed time, bytes 15-18 = track length, both timeBytes()
    // (min, sec, ms u16 LE). Verified on rekordbox playback captures: elapsed
    // advances 1.0 s per second, ms runs 0..999. (An earlier reading as a
    // 1/256 s counter put frac*256 into the ms field, so the platter only ran
    // 0..255 ms of every second and then jumped.)
    //
    // From the rekordbox cue capture: bytes 31-33 = CUE point in ms (u24 LE),
    // bytes 55-57 = the active cue (same value unless a hot cue was called),
    // byte 58 = cue flags (0x01 cue set, 0x00 none). Bytes 21-22 = BPM as u16 LE
    // ((tenths << 12) | whole), bytes 23-24 = tempo in 0.01 % (s16 LE), bytes
    // 38-39 repeat the BPM.
    function statusPacket(opts) {
        var r = STATUS_TEMPLATE.slice(0);
        r[0] = (opts.deck << 4) & 0xf0;
        if (opts.trackLoaded === false) {
            r[9] = 0x10; // no track
        }
        // byte5 bit7 = playing.
        r[5] = (opts.playing ? 0x80 : 0x00) | (r[5] & 0x7f);
        // byte2 bit1 = deck paused: rekordbox sends 0x1a while the deck is at
        // rest (and while it brakes to a stop), 0x18 while it plays -- incl.
        // a CUE preview from a paused deck. The unit dims the platter on it.
        if (opts.paused) {
            r[2] |= 0x02;
        }
        // byte2 bit0 = SLIP on: rekordbox sends 0x19 (0x1b paused) for as long
        // as SLIP is on; the unit draws the jog screen red.
        if (opts.slip) {
            r[2] |= 0x01;
        }
        // byte3 bit1 = ON AIR: rekordbox sends 0x0a while the channel is
        // audible (fader up), 0x08 when not; the unit dims the jog screen.
        if (typeof opts.onAir === "boolean") {
            r[3] = opts.onAir ? (r[3] | 0x02) : (r[3] & ~0x02);
        }
        var i;
        if (typeof opts.elapsedMs === "number" && opts.elapsedMs >= 0) {
            var e = timeBytes(opts.elapsedMs);
            for (i = 0; i < 4; i++) {
                r[11 + i] = e[i];
            }
        }
        if (typeof opts.durationMs === "number" && opts.durationMs > 0) {
            var d = timeBytes(opts.durationMs);
            for (i = 0; i < 4; i++) {
                r[15 + i] = d[i];
            }
        }
        if (typeof opts.cueMs === "number") {
            if (opts.cueMs >= 0) {
                var c = Math.round(opts.cueMs);
                putU24le(r, 31, c);
                putU24le(r, 55, c);
                r[58] = 0x01;
            } else {
                putU24le(r, 31, 0);
                putU24le(r, 55, 0);
                r[58] = 0x00;
            }
        }
        if (typeof opts.bpm === "number" && opts.bpm > 0) {
            var t = Math.round(opts.bpm * 10);
            var v = (((t % 10) << 12) | (Math.floor(t / 10) & 0xfff)) & 0xffff;
            r[21] = r[38] = v & 0xff;
            r[22] = r[39] = (v >> 8) & 0xff;
        }
        if (typeof opts.ratePct === "number") {
            var p = clamp(opts.ratePct * 100, -32768, 32767) & 0xffff;
            r[23] = p & 0xff;
            r[24] = (p >> 8) & 0xff;
        }
        return r;
    }

    // Split a transfer body over 64-byte reports: hdr(6) + 58 payload bytes each.
    function chunked(deck, msg, body) {
        var room = REPORT_LEN - 6;
        var total = Math.max(1, Math.ceil(body.length / room));
        var pkts = [];
        for (var n = 1; n <= total; n++) {
            pkts.push(padTo(hdr(deck, msg, n, total)
                .concat(body.slice((n - 1) * room, n * room)), REPORT_LEN));
        }
        return pkts;
    }

    // 0x30 hot-cue list, sent by rekordbox after the beat grid on every load and
    // again whenever a hot cue changes: track length, then 16 slots of
    // [type 0x01][colour][timeBytes(ms)]; empty slots are zero. Colour is the
    // unit's pad-colour number (rekordbox's default green is 0x16).
    // cues = [{slot: 0..15, ms, color}, ...].
    var HOTCUE_SLOTS = 16;
    function hotCuePackets(deck, durationMs, cues) {
        var body = timeBytes(durationMs);
        var slots = [];
        var i;
        for (i = 0; i < HOTCUE_SLOTS; i++) {
            slots.push([0, 0, 0, 0, 0, 0]);
        }
        for (i = 0; i < (cues || []).length; i++) {
            var c = cues[i];
            if (c.slot >= 0 && c.slot < HOTCUE_SLOTS && c.ms >= 0) {
                slots[c.slot] = [0x01, (c.color === undefined ? 0x16 : c.color) & 0xff]
                    .concat(timeBytes(c.ms));
            }
        }
        for (i = 0; i < HOTCUE_SLOTS; i++) {
            body = body.concat(slots[i]);
        }
        return chunked(deck, 0x30, body);
    }

    // 0x2D, sent right after 0x30: track length, then a block that is identical
    // in every rekordbox capture (meaning not decoded; replayed verbatim).
    function cueInfoPackets(deck, durationMs) {
        var body = timeBytes(durationMs).concat([0x0a, 0x00]);
        for (var i = 0; i < 10; i++) {
            body = body.concat([0x9e, 0x2f, 0x27, 0x01, 0x00]);
        }
        return chunked(deck, 0x2d, body);
    }

    // Retarget a prebuilt report (byte0 high nibble) to another deck.
    function retarget(report, deck) {
        var out = report.slice(0);
        out[0] = ((deck << 4) & 0xf0) | (out[0] & 0x0f);
        return out;
    }

    // -----------------------------------------------------------------------
    // Placeholder waveform patterns, until Mixxx exposes real overview data.
    // -----------------------------------------------------------------------
    function patternPoints(name) {
        var pts = [];
        var i, x, h, inner, col;
        for (i = 0; i < WAVE_POINTS; i++) {
            x = i / WAVE_POINTS;
            if (name === "square") {
                var on = (Math.floor(i / 25) % 2) === 0;
                h = on ? WAVE_MAX_H : 3;
                inner = on ? h * 0.5 : 1;
                col = on ? rgb565(0, 255, 140) : rgb565(30, 30, 70);
                pts.push(wavePoint(h, inner, col, rgb565(255, 255, 255)));
            } else if (name === "sine") {
                h = 20 + 18 * Math.sin(2 * Math.PI * 4 * x);
                col = rgb565(Math.round(127 + 127 * Math.sin(2 * Math.PI * x)), 80,
                    Math.round(127 - 127 * Math.sin(2 * Math.PI * x)));
                pts.push(wavePoint(h, h * 0.5, col, rgb565(255, 255, 255)));
            } else if (name === "ramp") {
                pts.push(wavePoint(x * 40, x * 20, rgb565(0, 160, 255), rgb565(255, 255, 255)));
            } else { // flat/quiet
                pts.push(wavePoint(2, 1, rgb565(60, 60, 80), rgb565(200, 200, 200)));
            }
        }
        return pts;
    }

    // Map the engine's analysed overview (array of [all, low, mid, high], each
    // 0..255, from engine.getWaveformSummary) to 600 waveform columns. Outer
    // bar height = overall amplitude; inner bar = low-band (bass) amplitude.
    // Colour mixes the three bands: low->red, mid->green, high->blue, the
    // convention Mixxx's own RGB waveform uses. Each band is first normalized
    // to its own track peak (bass otherwise dominates and everything is red),
    // then the hue is drawn at full saturation the way rekordbox does: outer
    // bar brightest channel = 189, inner bar the same hue at 255.
    // WAVE_SATURATION pulls the common (grey) part out of the mix so similar
    // band levels still give a visible hue instead of a pastel/white column.
    var WAVE_OUTER_BRIGHT = 189, WAVE_INNER_BRIGHT = 255, WAVE_INNER_FRAC = 0.5;
    var WAVE_SATURATION = 0.6;

    function hueColour(r, g, b, bright) {
        var grey = Math.min(r, g, b) * WAVE_SATURATION;
        r -= grey;
        g -= grey;
        b -= grey;
        var m = Math.max(r, g, b);
        if (m <= 0) {
            return rgb565(bright, bright, bright);
        }
        return rgb565(r * bright / m, g * bright / m, b * bright / m);
    }

    function wavePointsFromSummary(summary) {
        var n = summary.length;
        if (!n) {
            return null;
        }
        // Normalize to the track's peak so the loudest part fills the full
        // column height, as rekordbox does -- Mixxx's raw overview samples
        // rarely approach 255, so a fixed /255 scale looks too short.
        var peak = [1, 1, 1, 1];
        for (var j = 0; j < n; j++) {
            for (var k = 0; k < 4; k++) {
                var a = summary[j] ? (summary[j][k] & 0xff) : 0;
                if (a > peak[k]) {
                    peak[k] = a;
                }
            }
        }
        var scale = WAVE_MAX_H / peak[0];
        var pts = [];
        for (var i = 0; i < WAVE_POINTS; i++) {
            var col = summary[Math.floor(i * n / WAVE_POINTS)] || [0, 0, 0, 0];
            var all = col[0] & 0xff;
            var r = (col[1] & 0xff) / peak[1];
            var g = (col[2] & 0xff) / peak[2];
            var b = (col[3] & 0xff) / peak[3];
            pts.push(wavePoint(all * scale, all * scale * WAVE_INNER_FRAC,
                hueColour(r, g, b, WAVE_OUTER_BRIGHT),
                hueColour(r, g, b, WAVE_INNER_BRIGHT)));
        }
        return pts;
    }

    // -----------------------------------------------------------------------
    // helpers that tolerate Array / ArrayBuffer / Uint8Array inputs
    // -----------------------------------------------------------------------
    function toBytes(x) {
        if (x instanceof Array) {
            return x;
        }
        if (typeof ArrayBuffer !== "undefined" && x instanceof ArrayBuffer) {
            x = new Uint8Array(x);
        }
        var out = [];
        for (var i = 0; i < x.length; i++) {
            out.push(x[i] & 0xff);
        }
        return out;
    }

    function strBytes(s) {
        var out = [];
        for (var i = 0; i < s.length; i++) {
            out.push(s.charCodeAt(i) & 0xff);
        }
        return out;
    }

    function kConst() { // recompute k, to show it is not a magic number
        var s = strBytes("PioneerDJ").slice(0, 8);
        for (var i = 0; i < s.length; i++) {
            s[i] = (~s[i]) & 0xff;
        }
        return fnv1a(s);
    }

    return {
        // handshake
        K: K, fnv1a: fnv1a, kConst: kConst,
        buildArm: buildArm, buildRequestState: buildRequestState,
        buildMsg12: buildMsg12, buildMsg14: buildMsg14,
        deckViewSysex: deckViewSysex,
        parse13: parse13, predictUnitAnswer: predictUnitAnswer, hostAnswer: hostAnswer,
        isReady: isReady, isAccept: isAccept, msgType: msgType,
        // HID packets
        REPORT_LEN: REPORT_LEN, WAVE_POINTS: WAVE_POINTS, WAVE_MAX_H: WAVE_MAX_H,
        ART_MAX: ART_MAX,
        rgb565: rgb565, wavePoint: wavePoint, wavePackets: wavePackets,
        artPackets: artPackets, beatgridPackets: beatgridPackets, makeBeats: makeBeats,
        statusPacket: statusPacket, retarget: retarget, patternPoints: patternPoints,
        timeBytes: timeBytes, hotCuePackets: hotCuePackets, cueInfoPackets: cueInfoPackets,
        wavePointsFromSummary: wavePointsFromSummary,
    };
})();

// Node/CommonJS export + self-test (no-op inside Mixxx's engine).
if (typeof module !== "undefined" && module.exports) {
    module.exports = DDJ1000Jog;
    if (require.main === module) {
        var J = DDJ1000Jog;
        var assert = function(c, m) {
            if (!c) {
                throw new Error("FAIL: " + m);
            }
        };
        assert(J.kConst() === J.K, "k recompute (" + J.kConst().toString(16) + ")");
        // Handshake values must match stage4/ddj_cert.py byte-for-byte.
        var hc = [1, 2, 3, 4, 5, 6, 7, 8];
        var r = 0x11223344;
        var hex = function(a) {
            return a.map(function(b) {
                return ("0" + (b & 0xff).toString(16)).slice(-2);
            }).join("");
        };
        assert((J.predictUnitAnswer(hc, r) >>> 0) === 0x065e44e6, "predict vs python");
        assert((J.hostAnswer(r) >>> 0) === 0xe6558896, "hostAnswer vs python");
        var m12 = J.buildMsg12(hc);
        assert(hex(m12) === "f00040050000020000122a010b50696f6e656572444a020b72656b6f7264626" +
            "f78031200010002000300040005000600070008f7", "0x12 vs python");
        var m14 = J.buildMsg14(r);
        assert(hex(m14) === "f000400500000200001438010b50696f6e656572444a020b72656b6f7264626" +
            "f78040a0e06050508080906051608070a00080e0e0a0c00090003040706000b0900f7", "0x14 vs python");
        // parse13 inverse of the encoding.
        var fake13 = [0xf0, 0x00, 0x40, 0x05, 0x00, 0x00, 0x02, 0x00, 0x00, 0x13, 0x02]
            .concat([3, 2 + 8].concat([1, 1, 2, 2, 3, 3, 4, 4]))
            .concat([4, 2 + 8].concat([0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 1]))
            .concat([0xf7]);
        var p = J.parse13(fake13);
        assert((p.r >>> 0) === 0x11223344, "parse13 r (" + (p.r >>> 0).toString(16) + ")");
        assert((p.unitAnswer >>> 0) === 0xabcdef01, "parse13 answer");
        // Waveform packetisation: 600 columns -> 73 x 64-byte packets.
        var pts = J.patternPoints("square");
        var wp = J.wavePackets(1, pts, false, true);
        assert(wp.length === 73, "wave 73 packets (got " + wp.length + ")");
        assert(wp[0][1] === 0x2c && wp[0][6] === 0x80, "wave header+flags");
        wp.forEach(function(pk, i) {
            assert(pk.length === 64, "wave packet " + i + " length");
        });
        // Beatgrid round trips its byte count.
        var beats = J.makeBeats(135.0, 10000, 0);
        var bg = J.beatgridPackets(1, beats);
        assert(bg[0][1] === 0x2f, "beatgrid type");
        var cnt = bg[0][6] | (bg[0][7] << 8);
        assert(cnt === beats.length, "beatgrid count (" + cnt + " vs " + beats.length + ")");
        // Status.
        var st = J.statusPacket({deck: 2, playing: true, trackLoaded: true, durationMs: 211201});
        assert(st.length === 64 && st[0] === 0x20 && st[1] === 0x21, "status header");
        assert((st[5] & 0x80) !== 0 && st[9] === 0xb4, "status playing+loaded");
        // 211201 ms = 3:31.201 -> 03 1f c9 00.
        assert(st[15] === 0x03 && st[16] === 0x1f && st[17] === 0xc9 && st[18] === 0x00, "status length");
        // Captured rekordbox frame: elapsed 0:09.388 = 00 09 84 01.
        var se = J.statusPacket({deck: 1, elapsedMs: 9388});
        assert(hex(se.slice(11, 15)) === "00098401", "status elapsed " + hex(se.slice(11, 15)));
        // Byte-exact against captured rekordbox 0x30 / 0x2D (decoded4, deck 1,
        // track 2:39.169, hot cues A/B at 3.063 s / 3.932 s).
        var hc2 = J.hotCuePackets(1, 159169, [{slot: 0, ms: 3063}, {slot: 1, ms: 3932}]);
        assert(hc2.length === 2 && hex(hc2[0]).indexOf("1030010002000227a900011600033f00011600" +
            "03a40300") === 0, "hotcue 0x30 " + hex(hc2[0]));
        assert(hex(hc2[1]) === "103002000200" + "00".repeat(58), "hotcue 0x30 pkt2");
        var ci = J.cueInfoPackets(1, 159169);
        assert(hex(ci[0]) === "102d010001000227a9000a00" + "9e2f270100".repeat(10) + "0000",
            "cue info 0x2d " + hex(ci[0]));
        // Cue/BPM/tempo encodings, checked against captured rekordbox frames.
        var sc = J.statusPacket({deck: 1, cueMs: 9149, bpm: 126.6, ratePct: -1.06});
        assert(sc[31] === 0xbd && sc[32] === 0x23 && sc[55] === 0xbd && sc[56] === 0x23 &&
            sc[58] === 0x01, "status cue");
        assert(sc[21] === 0x7e && sc[22] === 0x60 && sc[23] === 0x96 && sc[24] === 0xff, "status bpm/tempo");
        assert(sc[61] === 0x0d, "status tail aligned");
        assert(J.statusPacket({deck: 1, paused: true})[2] === 0x1a &&
            J.statusPacket({deck: 1, paused: false})[2] === 0x18, "status paused flag");
        // eslint-disable-next-line no-console
        console.log("self-test OK: k=" + J.K.toString(16) +
            ", wave=" + wp.length + " pkts, beatgrid=" + bg.length +
            " pkts (" + beats.length + " beats), status len=" + st.length);
    }
}
