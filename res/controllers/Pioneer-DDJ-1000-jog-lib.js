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
        0x00, 0x00, 0x15, 0x00, 0x00, 0x01, 0x00, 0x02, 0x0d, 0x00,
        0x00, 0x00, 0x00, 0x00];

    // opts: { deck, playing (bool), trackLoaded (bool), durationMs, elapsedMs }.
    // Returns one 64-byte status report. Fields that are not yet decoded keep
    // the captured template value.
    //
    // Playback position (the jog's moving cursor) is bytes 11-13, a 24-bit
    // big-endian count of 1/256-second units: field = elapsed_seconds * 256.
    // Decoded empirically from rekordbox captures (byte 12 ticks once per track-
    // second; the field advances at 256/s scaled by deck tempo).
    function statusPacket(opts) {
        var r = STATUS_TEMPLATE.slice(0);
        r[0] = (opts.deck << 4) & 0xf0;
        if (opts.trackLoaded === false) {
            r[9] = 0x10; // no track
        }
        // byte5 bit7 = playing.
        r[5] = (opts.playing ? 0x80 : 0x00) | (r[5] & 0x7f);
        if (typeof opts.elapsedMs === "number" && opts.elapsedMs >= 0) {
            var f = Math.round(opts.elapsedMs * 256 / 1000);
            if (f < 0) {
                f = 0;
            }
            r[10] = (f >> 24) & 0xff; // effectively 0 for any real track
            r[11] = (f >> 16) & 0xff;
            r[12] = (f >> 8) & 0xff;
            r[13] = f & 0xff;
        }
        if (typeof opts.durationMs === "number" && opts.durationMs > 0) {
            var d = opts.durationMs | 0;
            r[15] = 0x02;
            r[16] = d & 0xff;
            r[17] = (d >> 8) & 0xff;
            r[18] = (d >> 16) & 0xff;
        }
        return r;
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
    // convention Mixxx's own RGB waveform uses.
    function wavePointsFromSummary(summary) {
        var n = summary.length;
        if (!n) {
            return null;
        }
        // Normalize to the track's peak so the loudest part fills the full
        // column height, as rekordbox does -- Mixxx's raw overview samples
        // rarely approach 255, so a fixed /255 scale looks too short.
        var peak = 1;
        for (var j = 0; j < n; j++) {
            var a = summary[j] ? (summary[j][0] & 0xff) : 0;
            if (a > peak) {
                peak = a;
            }
        }
        var scale = WAVE_MAX_H / peak;
        var pts = [];
        for (var i = 0; i < WAVE_POINTS; i++) {
            var col = summary[Math.floor(i * n / WAVE_POINTS)] || [0, 0, 0, 0];
            var all = col[0] & 0xff, low = col[1] & 0xff, mid = col[2] & 0xff, high = col[3] & 0xff;
            var colOuter = rgb565(low, mid, high);
            pts.push(wavePoint(all * scale, low * scale, colOuter, rgb565(255, 255, 255)));
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
        assert(st[16] === 0x01 && st[17] === 0x39 && st[18] === 0x03, "status duration u24");
        // eslint-disable-next-line no-console
        console.log("self-test OK: k=" + J.K.toString(16) +
            ", wave=" + wp.length + " pkts, beatgrid=" + bg.length +
            " pkts (" + beats.length + " beats), status len=" + st.length);
    }
}
