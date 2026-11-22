# Programmable Congestion Emulator

**IMPLEMENTATION DEMO URL:** https://drive.google.com/file/d/1ht1qorqjy49Sd23Kgfm5u8VwXonB0_64/
**DEMO URL :** https://docs.google.com/videos/d/1_cW-U_LdvFAWo00QrAR5wa4L_C__K6r1ddbryHbsNiY/play

Project 20, Group 31, CS5903 Distributed AI Training.
Members: Teesha Kukal (CS26MTECH12009), Chemboli Harshita (CS26RESCH11002).

One real RDMA sender behaves like **n** senders. A Tofino switch keeps a "logical queue" in a P4 register, and marks ECN from that queue. The real NIC gets real congestion signals and slows down for real. This lets us measure how fast a congestion-control algorithm (CCA) reacts to incast and how fast it recovers.

This project extends BEACON (a Tofino emulator that marks ECN on a timer) so the signal now follows the queue instead of a timer.

> Status: Part A (logical queue + ECN) and Part B (in-switch logging + offline analysis) work. Results are from **one run per n** and are preliminary. See [Status](#status).

## How it works

```
 netx6 (sender)            Intel Tofino switch                netx5 (receiver)
 ConnectX-5, DCQCN   -->  [ logical queue Q + RED ECN ]  -->  ConnectX-5
 port 7 (dev 180)         [ sampled in-switch log     ]       port 8 (dev 188)
        ^                          ^                                |
        |  CNP packets             | bfrt Python (control)          |
        +--------------------------+--------------------------------+
```

For every packet from the sender, the switch updates one number, Q (bytes):

```
dt    = now - previous packet time            (ns)
drain = 12 * dt                               (C = 12 bytes/ns, about 96 Gb/s)
fill  = n * packet length                     (n = 2^nshift = 1, 2, 4 or 8)
Q     = max(0, Q + fill - drain)
```

If Q is above the marking range and the packet is ECN-capable, the switch sets ECN to CE (11). The marking is RED-style:

- Below KMIN = 100 KB: no marking.
- KMIN to KMAX = 400 KB: marking chance grows linearly (about 7.3% at KMAX).
- At or above KMAX: always mark.

No packet is copied or delayed. Only the ECN signal is computed from Q. When the sender slows down, Q drains and marking stops.

**Tofino limits that shaped the design:** 32-bit integers only, no multiply or divide (so shifts and adds are used, and n is a power of two), one register access per packet, and a control-plane write takes about 600 µs (so n is changed only between steps).

### Part B: measuring inside the switch

BEACON uses a separate DPDK server to measure. Here the switch records the data itself:

- About 1 packet in 64 gets a log record (`SAMPLE_MASK = 0x3F`).
- Each record holds time, Q, ECN before and after marking, ports, and **cumulative byte counters for all packets**, so rates stay exact even though only a sample is logged.
- Ingress writes half of the record, egress writes the other half into the same slot. A 2-byte bridge header carries the slot number (it is removed before the packet leaves).
- Five ring buffers of 32,768 slots hold the log. The control plane reads them after logging is frozen.
- `analyze_incast_log.py` turns the log into rate, Q, mark fraction, reaction time, minimum rate, settled rate and recovery time.

The logging code only reads existing fields. It never changes Q or the marking (every added statement is tagged `LOG` in the P4 file).

## Testbed

| Item | Value |
|---|---|
| Switch | Intel Tofino 1, SDE 9.7.0, ports 5, 7, 8 at 100G |
| Sender | netx6, ConnectX-5 (`mlx5_0`), 50.0.0.2, switch port 7 (dev port 180) |
| Receiver | netx5, ConnectX-5 (`mlx5_0`), 50.0.0.1, switch port 8 (dev port 188) |
| CCA under test | Default DCQCN (ConnectX-5 supports DCQCN only) |
| Traffic | perftest `ib_write_bw`, RDMA write, 1 QP, 64 KB messages, 4096 MTU |
| Control link | 10G port to the switch host |

## Requirements

- Intel Tofino SDE 9.7.0 with the P4 compiler and BFRT Python (`run_switchd.sh`, `run_bfshell.sh`).
- perftest on both hosts.
- Python 3 on the analysis machine. `matplotlib` is optional.
- Versions of NIC firmware and perftest: [to be filled from the testbed].

## Quick start

All switch commands run on the Tofino host in `/home/tofinoswitch/AI-NIC/`.

**1. Compile.** Set `P4_NAME: logical_queue_inswitch` in `build/build_command`, then:

```bash
. set_sde_path
cd build && . build_command
```

**2. Start the switch.**

```bash
cd $SDE
./run_switchd.sh -p logical_queue_inswitch
```

**3. Open the control shell** in a second terminal and bring up ports 7 and 8:

```bash
./run_bfshell.sh
ucli
pm
port-add 7/- 100G NONE
an-set 7/- 2
port-enb 7/-
port-add 8/- 100G NONE
an-set 8/- 2
port-enb 8/-
show
```

Wait until both ports show `UP`. Then leave `ucli` and open `bfrt_python`.

**4. Set forwarding and n.** `nshift` 0, 1, 2, 3 gives n = 1, 2, 4, 8.

```python
l2 = bfrt.logical_queue_inswitch.pipe.Ingress.l2
l2.add_with_fwd(ingress_port=180, port=188, nshift=2, qidx=0)   # sender -> receiver, n = 4
l2.add_with_fwd(ingress_port=188, port=180, nshift=0, qidx=1)   # return direction (CNPs, ACKs)
l2.dump(from_hw=True)
```

If an entry already exists, use `l2.mod_with_fwd(...)` or `l2.clear()` and add again. Keep the return-direction entry.

**5. Start traffic.**

```bash
# netx5 (receiver)
ib_write_bw -d mlx5_0 -s 65536 -D 8
# netx6 (sender)
ib_write_bw -d mlx5_0 -s 65536 -D 8 50.0.0.1
```

`-D 8` runs for 8 seconds. Make the run longer than the logging window.

Optional: watch the NIC counters during the run.

```bash
# netx5
watch -d -n 1 'D=/sys/class/infiniband/mlx5_0/ports/1/hw_counters; for c in np_ecn_marked_roce_packets np_cnp_sent; do echo "$c $(cat $D/$c)"; done'
# netx6
watch -d -n 1 'D=/sys/class/infiniband/mlx5_0/ports/1/hw_counters; for c in rp_cnp_handled out_of_sequence local_ack_timeout_err; do echo "$c $(cat $D/$c)"; done'
```

**6. Capture the log.** Set `DURATION_S` in `bfrt_dump_log.py` (0.2 to 1 s was used), then in `bfrt_python`:

```python
exec(open('/home/tofinoswitch/AI-NIC/bfrt_dump_log.py').read())
```

It prints the number of sampled packets. If it prints a `WARNING ... overwritten` line, the start of the log was lost: shorten `DURATION_S` or use a sparser `SAMPLE_MASK` (for example `0x7F` or `0xFF`) and recompile.

**7. Copy the log** off the switch:

```bash
scp tofinoswitch@<switch-ip>:/home/tofinoswitch/AI-NIC/incast_log_raw.csv ./n4_run1_raw.csv
```

**8. Analyse.**

```bash
python3 analyze_incast_log.py n4_run1_raw.csv --sender-port 180 --n 4 \
        --window-us 1000 --out n4_run1_series.csv --plot n4_run1.png
```

**9. Repeat** for each n (change `nshift` with `l2.mod_with_fwd`, restart perftest).

### Stepped run (reaction and recovery)

Start the dump first, then raise n from a second bfrt shell while it runs:

```python
l2.mod_with_fwd(ingress_port=180, port=188, nshift=1, qidx=0)   # then 2, then 3
```

The log then holds a baseline, each step and the recovery. Read the step times from the plot and pass them to the analyzer with `--segments 5000,12000,...` (times in µs). Stepping is manual for now. A timed stepping script is not written yet.

### Snapshot collector (optional)

```python
exec(open('/home/tofinoswitch/AI-NIC/bfrt_collector_merged.py').read())
```

Writes `tofino_metadata.csv` for 30 s. It shows only the latest packet, so it is a sanity check.

## Analyzer options

| Option | Meaning | Default |
|---|---|---|
| `--sender-port` | Ingress dev port of the sender | busiest port |
| `--n` | Logical senders, prints the expected C / n | none |
| `--window-us` | Rate averaging window | 100 (we used 1000) |
| `--capacity-gbps` | C in the P4 model | 96 |
| `--drop-frac` | Rate drop that counts as a reaction | 0.10 |
| `--recover-frac` | Fraction of baseline that counts as recovered | 0.95 |
| `--kmin` | KMIN in bytes | 102400 |
| `--segments` | Step times in µs for per-segment stats | none |
| `--out`, `--plot` | Series CSV and three-panel plot | `incast_series.csv`, `incast_plot.png` |

Rates are IP-layer bytes. Reaction time cannot be finer than the window.

## Results so far

One run per n, all **preliminary**. Rates in Gb/s at the IP layer. C = 96 Gb/s.

| n | Model C / n | Settled rate (log) | Q peak | Marked / sampled | Log span | Outcome |
|---|---|---|---|---|---|---|
| 1 | above sender ceiling | 33.20 | 300 B | 0 / 3,110 | 200 ms | Uncongested baseline |
| 2 | above sender ceiling | 33.19 | 15,024 B | 0 / 3,135 | 200 ms | Below C (testbed limit) |
| 4 | 24 | 23.98 | 649,632 B (startup) | 58 / 5,281 | 463 ms | Matches the model |
| 8 | 12 | 5.16 | 111,408 B | 28 / 2,444 | 1,000 ms | Below the model (burst effect, hypothesis) |

- The sender cannot go above about 30 Gb/s of payload (33 Gb/s IP layer) because the PCIe link of netx5 trained down to 2.5 GT/s. So n = 1 and 2 never congest.
- Input and output rates are equal in all runs, so the switch drops nothing.
- At n = 8, one real 4,116-byte packet adds about 32.9 KB to Q, while only about 4 KB drains between back-to-back packets. So a short burst crosses KMIN even when the average rate is low. This is a hypothesis, not yet tested.
- Reaction time and recovery time are **not yet measured**. The n = 4 and n = 8 logs have no mark-free baseline. The stepped run is needed.

BEACON reference values (ECN for 2 µs, one flow, ConnectX-5): reaction about 5 µs, slow period about 300 µs, full recovery about 400 ms.

## Known limits

- Only incast, only DCQCN, only ConnectX-5.
- One logical queue and one constant drain rate. n is 1, 2, 4 or 8.
- The sender is capped near 30 Gb/s (see above).
- Sampling is 1 in 64 and the rings hold about 2.5 s at 30 Gb/s. 32-bit timestamps and byte counters wrap and are unwrapped offline (works while samples are less than about 2 s apart).
- The log covers one pipe (`PIPE = 1`) and IPv4 only. Only ECN-capable packets are marked.
- `dt` is clamped at 2^24 ns (about 16.8 ms) so the shifts cannot overflow.
- Changing n or the RED range needs the control plane (n) or a recompile (KMIN, KMAX).
- The snapshot collector is tied to pipe 1 and shows one packet at a time.

## Troubleshooting

- **Scripts fail with a missing program name:** `PROGRAM` in `bfrt_dump_log.py` and `bfrt_collector_merged.py` must equal the compiled name, `logical_queue_inswitch`.
- **`l2.add_with_fwd` says the entry exists:** use `l2.mod_with_fwd(...)`, or `l2.clear()` and add again.
- **n = 1 or 2 log shows Q = 0 and no marks:** expected. The sender is below the drain rate.
- **"oldest samples were overwritten":** the ring filled up. Shorten `DURATION_S` or sample less often.
- **No reaction or recovery numbers:** the log started after the rate settled. Start the dump first and step n during the run.

## Status

| Area | State |
|---|---|
| Logical queue (n = 1, 2, 4, 8 via the l2 table) | Working |
| RED-style ECN marking from Q | Working |
| In-switch sampled log and offline analysis | Working (runs captured for n = 1, 2, 4, 8) |
| Run-time change of n | Partial (by hand, no timed script) |

Next steps, in order: timed stepping script; explain the n = 8 result (repeat runs, NIC counter deltas, higher KMIN/KMAX); fix the sender PCIe limit; multicast or recirculation for several logical queues; a second CCA.
