#!/usr/bin/env python3
"""Offline analysis of the raw per-packet log written by bfrt_dump_log.py.

Standard library only (matplotlib is used for the plot if it happens to be installed).

For the sender's traffic it reconstructs, against switch time:
  * offered / sending rate seen at ingress   (delta cumulative ingress bytes / delta ingress ts)
  * output throughput at the egress port     (delta cumulative egress bytes / delta egress ts)
  * logical queue Q, and how fast it drains after its peak
  * ECN marks (CE set by the switch: ecn_in != 3 and ecn_out == 3), windowed mark fraction
and derives DCQCN reaction time, minimum rate, settled rate and recovery time.

Rates are IP-layer bytes (IPv4 total length). Time resolution is the sampling interval and
the averaging window (--window-us).
"""
import argparse
import csv
import statistics
import sys
from collections import Counter

M32 = 1 << 32


def sdiff(a, b):
    """Signed difference a - b of two 32-bit counters (handles wraparound)."""
    return ((a - b + (1 << 31)) & (M32 - 1)) - (1 << 31)


def unwrap(vals):
    out = [0]
    for i in range(1, len(vals)):
        out.append(out[-1] + sdiff(vals[i], vals[i - 1]))
    return out


def load(path):
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            rows.append({k: int(v) for k, v in r.items()})
    return rows


def median(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", help="raw CSV from bfrt_dump_log.py")
    ap.add_argument("--sender-port", type=int, default=None,
                    help="ingress dev port of the sender (default: port with most bytes)")
    ap.add_argument("--window-us", type=float, default=100.0, help="rate averaging window")
    ap.add_argument("--n", type=int, default=None, help="logical senders; prints expected C/n")
    ap.add_argument("--capacity-gbps", type=float, default=96.0, help="C in the P4 model (12 B/ns)")
    ap.add_argument("--drop-frac", type=float, default=0.10, help="rate drop that counts as a reaction")
    ap.add_argument("--recover-frac", type=float, default=0.95, help="fraction of baseline = recovered")
    ap.add_argument("--kmin", type=int, default=100 * 1024)
    ap.add_argument("--segments", default="",
                    help="comma-separated boundaries in us (e.g. 5000,12000) for per-segment stats")
    ap.add_argument("--out", default="incast_series.csv")
    ap.add_argument("--plot", default="incast_plot.png")
    args = ap.parse_args()

    rows = load(args.csv)
    if len(rows) < 10:
        sys.exit("too few records (%d)" % len(rows))

    # ---- time axes (global, chronological by sample order) ----
    t_ing_all = unwrap([r["ing_ts32"] for r in rows])
    eg_valid = [not (r["eg_ts32"] == 0 and r["eg_cum_bytes32"] == 0) for r in rows]
    eg_ts = []
    last = rows[0]["eg_ts32"]
    for r, ok in zip(rows, eg_valid):
        if ok:
            last = r["eg_ts32"]
        eg_ts.append(last)
    t_eg_all = unwrap(eg_ts)

    # ---- choose the sender's records ----
    by_port = {}
    for i, r in enumerate(rows):
        by_port.setdefault(r["ingress_port"], []).append(i)
    if args.sender_port is None:
        best = None
        for p, idx in by_port.items():
            tot = unwrap([rows[i]["ing_cum_bytes32"] for i in idx])[-1]
            if best is None or tot > best[1]:
                best = (p, tot)
        sender = best[0]
        print("sender port (auto): %d  (ports seen: %s)" % (sender, sorted(by_port)))
    else:
        sender = args.sender_port
    idx = [i for i in by_port.get(sender, []) if eg_valid[i]]
    if len(idx) < 10:
        sys.exit("too few valid records for sender port %d" % sender)
    eport = Counter(rows[i]["egress_port"] for i in idx).most_common(1)[0][0]
    dropped = [i for i in idx if rows[i]["egress_port"] != eport]
    idx = [i for i in idx if rows[i]["egress_port"] == eport]
    if dropped:
        print("note: %d records left via another egress port and were ignored" % len(dropped))
    print("egress port: %d, records used: %d" % (eport, len(idx)))

    n = len(idx)
    t = [t_ing_all[i] for i in idx]                       # ns
    teg = [t_eg_all[i] for i in idx]
    b_in = unwrap([rows[i]["ing_cum_bytes32"] for i in idx])
    b_out = unwrap([rows[i]["eg_cum_bytes32"] for i in idx])
    q = [rows[i]["q_bytes"] for i in idx]
    marked = [1 if (rows[i]["ecn_out"] == 3 and rows[i]["ecn_in"] != 3) else 0 for i in idx]
    ce_seen = [1 if rows[i]["ecn_out"] == 3 else 0 for i in idx]
    t0 = t[0]
    tus = [(x - t0) / 1000.0 for x in t]

    # ---- windowed rates and mark fraction ----
    W = args.window_us * 1000.0
    pm = [0]
    for m in marked:
        pm.append(pm[-1] + m)
    rate_in = [None] * n
    rate_out = [None] * n
    mark_frac = [None] * n
    j = 0
    for k in range(n):
        while j + 1 < k and t[k] - t[j + 1] >= W:
            j += 1
        dt = t[k] - t[j]
        if k > j and dt >= W:
            rate_in[k] = (b_in[k] - b_in[j]) * 8.0 / dt            # bits/ns = Gbps
            dte = teg[k] - teg[j]
            if dte > 0:
                rate_out[k] = (b_out[k] - b_out[j]) * 8.0 / dte
            mark_frac[k] = (pm[k + 1] - pm[j + 1]) / float(k - j)

    # ---- summary metrics ----
    print("\n==== summary (window %.0f us, %d records over %.2f ms) ====" %
          (args.window_us, n, tus[-1] / 1000.0))
    mark_idx = [k for k in range(n) if marked[k]]
    if not mark_idx:
        print("no sampled packet was CE-marked by the switch: no congestion signal in this log")
        base = median(rate_in[: max(5, n // 5)])
        print("rate (first 20%% of log): median %.2f Gbps" % base if base else "no rate yet")
    else:
        k_first, k_last = mark_idx[0], mark_idx[-1]
        pre = [rate_in[k] for k in range(k_first) if rate_in[k] is not None]
        base = median(pre) if pre else None
        print("sampled marks: %d of %d records; first at %.1f us, last at %.1f us" %
              (len(mark_idx), n, tus[k_first], tus[k_last]))
        if base is None:
            print("no pre-mark rate window: log starts too close to the first mark; "
                  "cannot compute reaction/recovery")
        else:
            print("baseline rate before first mark: %.2f Gbps" % base)
            thr_drop = (1.0 - args.drop_frac) * base
            k_react = next((k for k in range(k_first, n)
                            if rate_in[k] is not None and rate_in[k] < thr_drop), None)
            if k_react is None:
                print("rate never fell below %.2f Gbps after the first mark" % thr_drop)
            else:
                print("reaction: rate < %.0f%% of baseline %.1f us after the first mark "
                      "(resolution ~ window)" % ((1 - args.drop_frac) * 100, tus[k_react] - tus[k_first]))
            cand = [k for k in range(k_first, n) if rate_in[k] is not None]
            if cand:
                k_min = min(cand, key=lambda k: rate_in[k])
                print("minimum rate: %.2f Gbps at %.1f us" % (rate_in[k_min], tus[k_min]))
                thr_rec = args.recover_frac * base
                k_rec = next((k for k in range(k_min, n)
                              if rate_in[k] is not None and rate_in[k] >= thr_rec), None)
                if k_rec is None:
                    print("recovery: rate did not return to %.0f%% of baseline within the log" %
                          (args.recover_frac * 100))
                else:
                    print("recovery: >= %.0f%% of baseline %.1f us after the minimum" %
                          (args.recover_frac * 100, tus[k_rec] - tus[k_min]))
                    if tus[k_rec] > tus[k_last]:
                        print("          and %.1f us after the last sampled mark" %
                              (tus[k_rec] - tus[k_last]))
    tail = [rate_in[k] for k in range(int(n * 0.9), n)]
    settled = median(tail)
    if settled is not None:
        msg = "settled rate (last 10%% of log): %.2f Gbps" % settled
        if args.n:
            msg += "   (expected ~ C/n = %.2f Gbps)" % (args.capacity_gbps / args.n)
        print(msg)

    kq = max(range(n), key=lambda k: q[k])
    print("\nQ peak: %d bytes at %.1f us" % (q[kq], tus[kq]))
    k_dr = next((k for k in range(kq, n) if q[k] <= args.kmin), None)
    if k_dr is not None and k_dr > kq and t[k_dr] > t[kq]:
        drain = (q[kq] - q[k_dr]) / float(t[k_dr] - t[kq])
        print("Q drained from peak to <= KMIN in %.1f us (avg %.2f bytes/ns net drain)" %
              (tus[k_dr] - tus[kq], drain))
    else:
        print("Q did not drain below KMIN after its peak within the log")

    if args.segments:
        bounds = [0.0] + [float(x) for x in args.segments.split(",") if x] + [tus[-1] + 1]
        print("\nper segment (us): median rate in / out (Gbps), mean Q (bytes), mark fraction")
        for a, b in zip(bounds[:-1], bounds[1:]):
            ks = [k for k in range(n) if a <= tus[k] < b]
            if not ks:
                continue
            ri = median([rate_in[k] for k in ks])
            ro = median([rate_out[k] for k in ks])
            fm = sum(marked[k] for k in ks) / float(len(ks))
            fmt = lambda v: "n/a" if v is None else "%.2f" % v
            print("  [%.0f, %.0f): in %s  out %s  Q %.0f  marks %.3f" %
                  (a, b, fmt(ri), fmt(ro), sum(q[k] for k in ks) / len(ks), fm))

    # ---- series CSV ----
    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t_us", "rate_in_gbps", "rate_out_gbps", "q_bytes", "marked", "ce_seen",
                    "mark_fraction_window"])
        for k in range(n):
            w.writerow([round(tus[k], 3),
                        "" if rate_in[k] is None else round(rate_in[k], 4),
                        "" if rate_out[k] is None else round(rate_out[k], 4),
                        q[k], marked[k], ce_seen[k],
                        "" if mark_frac[k] is None else round(mark_frac[k], 4)])
    print("\nseries written to", args.out)

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(3, 1, sharex=True, figsize=(10, 8))
        xs = [(tus[k], rate_in[k], rate_out[k]) for k in range(n) if rate_in[k] is not None]
        ax[0].plot([x[0] for x in xs], [x[1] for x in xs], label="sending rate (ingress)")
        xo = [(x[0], x[2]) for x in xs if x[2] is not None]
        ax[0].plot([x[0] for x in xo], [x[1] for x in xo], label="throughput (egress)", alpha=0.7)
        ax[0].set_ylabel("Gbps")
        ax[0].legend()
        ax[1].plot(tus, q)
        ax[1].axhline(args.kmin, ls=":", c="gray")
        ax[1].set_ylabel("logical Q (bytes)")
        xm = [(tus[k], mark_frac[k]) for k in range(n) if mark_frac[k] is not None]
        ax[2].plot([x[0] for x in xm], [x[1] for x in xm])
        ax[2].set_ylabel("CE mark fraction")
        ax[2].set_xlabel("time (us)")
        fig.tight_layout()
        fig.savefig(args.plot, dpi=130)
        print("plot written to", args.plot)
    except ImportError:
        print("matplotlib not installed: skipped the plot (the series CSV has everything)")


if __name__ == "__main__":
    main()
