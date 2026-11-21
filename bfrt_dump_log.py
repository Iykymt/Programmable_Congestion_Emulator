# Run inside the BFRT shell on the Tofino host (same way as the snapshot collector).
#
#   1. start your traffic (perftest) / steps for n from the control plane
#   2. run this script: it clears + enables logging, waits DURATION_S, freezes logging,
#      then dumps the ring buffers to a raw CSV
#   3. copy the CSV off the switch and run analyze_incast_log.py on it
#
# Records are SAMPLED (1 in 64 packets by default, see SAMPLE_MASK in the P4 file) but the
# byte counters inside each record are cumulative over ALL packets, so rates are exact.

import csv
import time

PROGRAM = "logical_queue_inswitch"      # name of the compiled P4 program under bfrt.
PIPE = 1                                     # same pipe assumption as the snapshot collector
LOG_ENTRIES = 32768                          # must match LOG_ENTRIES in the P4 file
DURATION_S = 0.5                              # how long logging stays enabled
OUT_FILE = "/home/tofinoswitch/AI-NIC/incast_log_raw.csv"

prog = getattr(bfrt, PROGRAM)
ing = prog.pipe.Ingress
egr = prog.pipe.Egress


def key_name(k):
    return k.decode() if isinstance(k, bytes) else str(k)


def field(entry, suffix):
    """Value of the data field whose name ends with `suffix`, for the selected pipe."""
    for k, v in entry.data.items():
        if key_name(k).endswith(suffix):
            return v[PIPE] if isinstance(v, (list, tuple)) else v
    raise KeyError("no field ending in %s; fields are %s" %
                   (suffix, [key_name(k) for k in entry.data.keys()]))


def reg_write(reg, idx, value):
    try:
        reg.mod(REGISTER_INDEX=idx, f1=value)
    except Exception:
        reg.add(REGISTER_INDEX=idx, f1=value)


synced = True


def sync(*regs):
    global synced
    for r in regs:
        try:
            r.operation_register_sync()
        except Exception as e:
            synced = False
            print("register sync not available (%s); falling back to per-entry hardware reads" % e)


def read_entry(reg, idx):
    return reg.get(idx, from_hw=(not synced), print_ents=False)


# ---- run ----------------------------------------------------------------------------
reg_write(ing.log_en_reg, 0, 0)
reg_write(ing.slot_reg, 0, 0)
time.sleep(0.05)
reg_write(ing.log_en_reg, 0, 1)
print("Logging ON for %d s (start/continue your traffic now)..." % DURATION_S)
time.sleep(DURATION_S)
reg_write(ing.log_en_reg, 0, 0)
time.sleep(0.2)                       # let in-flight packets finish
print("Logging frozen. Reading ring buffers...")

sync(ing.slot_reg, ing.ring_tq, ing.ring_bytes_ecn, ing.ring_port_qidx,
     egr.ring_e_ts_ecn, egr.ring_e_bytes_port)

count = field(read_entry(ing.slot_reg, 0), ".f1")
first = max(0, count - LOG_ENTRIES)
print("sampled packets logged: %d (ring holds the last %d)" % (count, min(count, LOG_ENTRIES)))
if first > 0:
    print("WARNING: %d oldest samples were overwritten. Increase SAMPLE_MASK sparsity "
          "(e.g. 0x7F) or shorten DURATION_S." % first)

with open(OUT_FILE, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["sample", "slot", "ing_ts32", "q_bytes", "ing_cum_bytes32", "ecn_in",
                "ingress_port", "qidx", "eg_ts32", "ecn_out", "eg_cum_bytes32", "egress_port"])
    for g in range(first, count):
        slot = g % LOG_ENTRIES
        a = read_entry(ing.ring_tq, slot)
        b = read_entry(ing.ring_bytes_ecn, slot)
        c = read_entry(ing.ring_port_qidx, slot)
        d = read_entry(egr.ring_e_ts_ecn, slot)
        e = read_entry(egr.ring_e_bytes_port, slot)
        w.writerow([g, slot,
                    field(a, ".lo"), field(a, ".hi"),
                    field(b, ".lo"), field(b, ".hi"),
                    field(c, ".lo"), field(c, ".hi"),
                    field(d, ".lo"), field(d, ".hi"),
                    field(e, ".lo"), field(e, ".hi")])
        if (g - first) % 4096 == 0:
            print("  read %d / %d" % (g - first, count - first))

print("Done. Raw log saved to:", OUT_FILE)
