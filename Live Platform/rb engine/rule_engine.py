def normalize_mac(mac):
    return mac.lower() if mac else None


def get_packet_bus(pkt, cfg):
    if pkt.get("protocol") == "GOOSE":
        gocbRef = pkt.get("gocbRef")
        if gocbRef:
            return cfg.get("gocbref_to_bus", {}).get(gocbRef)
    if pkt.get("protocol") == "SV":
        svID = pkt.get("svID")
        if svID:
            mapped = cfg.get("svid_to_bus", {}).get(svID)
            if mapped:
                return mapped
            import re
            match = re.search(r"bus(\d+)", str(svID))
            if match:
                return f"bus{match.group(1)}"

    src_mac = normalize_mac(pkt.get("src_mac"))
    for bus, mac in cfg.get("bus_to_mac", {}).items():
        if normalize_mac(mac) == src_mac:
            return bus
    return None


def check_common_identity_rules(pkt, cfg):
    reasons = []
    severity = "low"

    return reasons, severity


def check_goose_rules(pkt, state):
    reasons, severity = check_common_identity_rules(pkt, state.config)
    cfg = state.config

    gocbRef = pkt.get("gocbRef")
    stNum = pkt.get("stNum")
    sqNum = pkt.get("sqNum")
    ts = pkt.get("timestamp")
    src_mac = normalize_mac(pkt.get("src_mac"))
    bus_num = get_packet_bus(pkt, cfg)

    pkt["bus_num"] = bus_num
    excluded_buses = set(cfg.get("excluded_buses", []))
    if bus_num in excluded_buses:
        return {"rule_violation": False, "severity": "low", "reasons": ["excluded_bus"]}

    if gocbRef and gocbRef not in cfg.get("gocbref_to_bus", {}):
        reasons.append("unknown_gocbRef")
        severity = max(severity, "medium", key=lambda x: ["low","medium","high"].index(x))

    expected = normalize_mac(cfg.get("gocbref_to_mac", {}).get(gocbRef))
    if expected and src_mac and src_mac != expected:
        reasons.append("src_mac_mismatch")
        severity = "high"

    if bus_num and bus_num not in excluded_buses and cfg.get("bus_to_mac", {}).get(bus_num):
        expected_bus_mac = normalize_mac(cfg["bus_to_mac"].get(bus_num))
        if expected_bus_mac and src_mac and src_mac != expected_bus_mac:
            reasons.append("bus_mac_mismatch")
            severity = "high"

    prev = state.get_goose_prev(gocbRef) if gocbRef else None
    if prev and stNum is not None and prev.get("stNum") is not None:
        if stNum < prev["stNum"]:
            reasons.append("stNum_decreased")
            severity = "high"
        jump_thr = cfg.get("stnum_jump_threshold", 10000)
        if stNum - prev["stNum"] > jump_thr:
            reasons.append("stNum_jump")
            severity = "high"
        if prev.get("ts") and ts:
            interval = ts - prev.get("ts")
            normal = cfg.get("normal_goose_interval", 0.52)
            factor = cfg.get("abnormal_goose_interval_factor", 3)
            if interval > normal * factor:
                reasons.append("abnormal_goose_interval")
                severity = max(severity, "medium", key=lambda x: ["low","medium","high"].index(x))

    if not gocbRef and bus_num:
        reasons.append("missing_gocbRef_but_known_bus")
        severity = max(severity, "low", key=lambda x: ["low","medium","high"].index(x))

    return {"rule_violation": len(reasons) > 0, "severity": severity, "reasons": reasons}


def check_sv_rules(pkt, state):
    reasons = []
    severity = "low"
    cfg = state.config

    pkt["bus_num"] = get_packet_bus(pkt, cfg)
    identity_reasons, identity_severity = check_common_identity_rules(pkt, cfg)
    reasons.extend(identity_reasons)
    severity = max(severity, identity_severity, key=lambda x: ["low","medium","high"].index(x))

    src_mac = normalize_mac(pkt.get("src_mac"))
    bus_num = pkt.get("bus_num")
    excluded_buses = set(cfg.get("excluded_buses", []))
    if bus_num in excluded_buses:
        return {"rule_violation": False, "severity": "low", "reasons": ["excluded_bus"]}

    # SV policy in this lab is intentionally MAC-only. The publisher allowlist
    # is the only authoritative SV rule; timing and counter checks are removed
    # to stay aligned with the ML-training assumptions.
    sv_allow = {normalize_mac(m) for m in cfg.get("sv_publisher_macs", [])}
    if sv_allow and src_mac and src_mac not in sv_allow:
        reasons.append("sv_publisher_mac_mismatch")
        severity = "high"

    return {"rule_violation": len(reasons) > 0, "severity": severity, "reasons": reasons}


def check_rules(pkt, state):
    proto = pkt.get("protocol")
    if proto == "GOOSE":
        return check_goose_rules(pkt, state)
    if proto == "SV":
        return check_sv_rules(pkt, state)
    pkt["bus_num"] = get_packet_bus(pkt, state.config)
    return {"rule_violation": False, "severity": "low", "reasons": []}
