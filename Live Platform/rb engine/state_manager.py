class StateManager:
    """Tracks last-seen counters and timestamps per gocbRef and svID."""

    def __init__(self, config):
        # simple dicts keyed by identifier
        self.last_goose = {}  # gocbRef -> {stNum, sqNum, ts, src_mac}
        self.last_sv = {}     # svID -> {smpCnt, ts, src_mac}
        self.config = config or {}

    def get_goose_prev(self, gocbRef):
        return self.last_goose.get(gocbRef)

    def get_sv_prev(self, svID):
        return self.last_sv.get(svID)

    def update_goose(self, gocbRef, stNum, sqNum, ts, src_mac):
        if gocbRef is None:
            return
        self.last_goose[gocbRef] = {"stNum": stNum, "sqNum": sqNum, "ts": ts, "src_mac": src_mac}

    def update_sv(self, svID, smpCnt, ts, src_mac):
        if svID is None:
            return
        self.last_sv[svID] = {"smpCnt": smpCnt, "ts": ts, "src_mac": src_mac}
