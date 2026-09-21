from __future__ import annotations

from collections import defaultdict, deque
from statistics import mean, median, stdev
from typing import Any, Deque, Dict, List, Optional


ROLLING_WINDOW = 10

# Must match SV_STREAM_FEATURES in the training notebook and the names the
# joblib artefacts were fitted with. detectors.py builds the model input by
# NAME (via feature_names_in_), so these strings are the contract.
SV_STREAM_FEATURE_NAMES = (
    "smpcnt_delta",
    "smpcnt_delta_abs",
    "smpcnt_back",
    "smpcnt_delta_roll_std",
    "dt",
    "dt_roll_med",
    "dt_ratio",
    "noASDU",
)


class LiveMLFeatureBuilder:
    """Builds model-facing features incrementally from parsed packets."""

    def __init__(self) -> None:
        self.goose_history: Dict[str, Dict[str, Any]] = defaultdict(self._new_goose_history)
        self.sv_history: Dict[str, Dict[str, Any]] = defaultdict(self._new_sv_history)

    def reset(self) -> None:
        self.goose_history.clear()
        self.sv_history.clear()

    def enrich(self, feature: Dict[str, Any]) -> Dict[str, Any]:
        if feature.get("protocol") == "GOOSE":
            return self._enrich_goose(feature)
        if feature.get("protocol") == "SV":
            return self._enrich_sv(feature)
        return dict(feature)

    def _enrich_goose(self, feature: Dict[str, Any]) -> Dict[str, Any]:
        enriched = dict(feature)
        key = f"{feature.get('gocbRef') or 'unknown'}|{feature.get('src_mac') or 'unknown'}"
        history = self.goose_history[key]
        timestamp = self._to_float(feature.get("timestamp"))
        st_num = self._to_float(feature.get("stNum"))

        if timestamp is None or history["last_ts"] is None:
            time_interval = 0.0
        else:
            time_interval = max(0.0, timestamp - history["last_ts"])

        interval_window = list(history["intervals"]) + [time_interval]
        interval_mean = mean(interval_window) if interval_window else 0.0
        interval_std = stdev(interval_window) if len(interval_window) >= 2 else 0.0

        previous_st_nums = list(history["st_nums"])
        if st_num is None or not previous_st_nums:
            stnum_median = st_num or 0.0
            stnum_mean = st_num or 0.0
        else:
            stnum_median = median(previous_st_nums)
            stnum_mean = mean(previous_st_nums)

        enriched.update({
            "time_interval": time_interval,
            "timing_rolling_std": interval_std,
            "timing_cv": interval_std / (abs(interval_mean) + 1e-9),
            "stNum_cumulative_avg_diff": abs((st_num or 0.0) - stnum_mean),
            "stNum_deviation_from_median": (st_num or 0.0) - stnum_median,
            "Correlation_Mismatch": self._correlation_mismatch(feature),
        })

        if timestamp is not None:
            history["last_ts"] = timestamp
        history["intervals"].append(time_interval)
        if st_num is not None:
            history["st_nums"].append(st_num)

        return enriched

    def _correlation_mismatch(self, feature: Dict[str, Any]) -> int:
        return int(feature.get("Correlation_Mismatch") or 0)

    def _enrich_sv(self, feature: Dict[str, Any]) -> Dict[str, Any]:
        """Adds the value features plus the per-svID STREAM features.

        The stream features are what the SV detector runs on. They mirror
        compute_sv_features() in the training notebook:

            smpcnt_delta          = smpCnt - previous smpCnt for THIS svID
            smpcnt_delta_abs      = abs(smpcnt_delta)
            smpcnt_back           = 1 if the counter went backwards
            smpcnt_delta_roll_std = sample std of the last 10 deltas
            dt                    = timestamp - previous timestamp for THIS svID
            dt_roll_med           = median of the last 10 dt values
            dt_ratio              = dt / dt_roll_med
            noASDU                = ASDUs declared in the frame

        These detect a ROGUE PUBLISHER: a second publisher spoofing the real
        source MAC and svIDs while emitting physically plausible values on every
        bus. Its samples are indistinguishable from the legitimate stream, so
        value magnitudes cannot see it. What betrays it is that two independent
        publishers now share one svID, so the observed sample counter stops being
        monotonic and the observed inter-frame interval collapses.

        IMPORTANT: state is keyed on svID ALONE, never on (svID, src_mac). The
        entire signal is two publishers colliding under one svID. Keying by MAC
        would give each publisher its own clean monotonic counter and erase it.

        Rolling windows INCLUDE the current row, matching
        .rolling(10, min_periods=1) applied after groupby().diff() in the
        notebook. Undefined values (first frame of a stream, missing smpCnt) are
        emitted as 0.0, matching the notebook's .fillna(0) before predict.
        """
        enriched = dict(feature)

        voltages = [
            self._to_float(feature.get("phaseA_voltage")),
            self._to_float(feature.get("phaseB_voltage")),
            self._to_float(feature.get("phaseC_voltage")),
        ]
        currents = [
            self._to_float(feature.get("phaseA_current")),
            self._to_float(feature.get("phaseB_current")),
            self._to_float(feature.get("phaseC_current")),
        ]
        enriched["sv_v_max"] = self._max_abs(voltages)
        enriched["sv_i_max"] = self._max_abs(currents)

        key = str(feature.get("svID") or "unknown")
        history = self.sv_history[key]

        timestamp = self._to_float(feature.get("timestamp"))
        smp_cnt = self._to_float(feature.get("smpCnt"))

        smpcnt_delta = None  # type: Optional[float]
        if smp_cnt is not None and history["last_smpcnt"] is not None:
            smpcnt_delta = smp_cnt - history["last_smpcnt"]

        dt = None  # type: Optional[float]
        if timestamp is not None and history["last_ts"] is not None:
            dt = timestamp - history["last_ts"]

        # Append BEFORE aggregating: the pandas window includes the current row.
        # None placeholders preserve positional equivalence with pandas, which
        # keeps a slot for NaN but excludes it from the aggregation.
        history["deltas"].append(smpcnt_delta)
        history["dts"].append(dt)

        dt_roll_med = self._rolling_median(history["dts"])
        if dt is None or dt_roll_med == 0.0:
            dt_ratio = 0.0
        else:
            dt_ratio = dt / dt_roll_med

        enriched.update({
            "smpcnt_delta": self._or_zero(smpcnt_delta),
            "smpcnt_delta_abs": self._or_zero(
                abs(smpcnt_delta) if smpcnt_delta is not None else None
            ),
            "smpcnt_back": 1 if (smpcnt_delta is not None and smpcnt_delta < 0) else 0,
            "smpcnt_delta_roll_std": self._rolling_std(history["deltas"]),
            "dt": self._or_zero(dt),
            "dt_roll_med": dt_roll_med,
            "dt_ratio": dt_ratio,
            "noASDU": self._or_zero(self._to_float(feature.get("noASDU"))),
        })

        # Advance the per-svID cursor from EVERY frame, regardless of source MAC
        # or verdict. A rogue publisher writing into this sequence is precisely
        # what the model is meant to observe.
        if smp_cnt is not None:
            history["last_smpcnt"] = smp_cnt
        if timestamp is not None:
            history["last_ts"] = timestamp

        return enriched

    def _max_abs(self, values: List[Optional[float]]) -> float:
        present = [abs(value) for value in values if value is not None]
        return max(present, default=0.0)

    def _rolling_median(self, window: Deque[Optional[float]]) -> float:
        present = [value for value in window if value is not None]
        if not present:
            return 0.0
        return float(median(present))

    def _rolling_std(self, window: Deque[Optional[float]]) -> float:
        present = [value for value in window if value is not None]
        if len(present) < 2:
            return 0.0
        return float(stdev(present))

    def _or_zero(self, value: Optional[float]) -> float:
        return 0.0 if value is None else float(value)

    def _new_goose_history(self) -> Dict[str, Any]:
        return {
            "last_ts": None,
            "intervals": deque(maxlen=ROLLING_WINDOW),
            "st_nums": deque(maxlen=ROLLING_WINDOW),
        }

    def _new_sv_history(self) -> Dict[str, Any]:
        return {
            "last_ts": None,
            "last_smpcnt": None,
            "deltas": deque(maxlen=ROLLING_WINDOW),
            "dts": deque(maxlen=ROLLING_WINDOW),
        }

    def _to_float(self, value: Any) -> Optional[float]:
        try:
            if value is None:
                return None
            return float(value)
        except (TypeError, ValueError):
            return None
