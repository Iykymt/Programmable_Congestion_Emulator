/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/* Logical-queue (Nimble-style logical meter) for incast emulation on Tofino 1 (TNA),
 * plus in-switch measurement:
 *   (1) one-entry "latest value" telemetry registers (snapshot collector), and
 *   (2) a sampled per-packet LOG (ring buffers) for rate / Q / ECN analysis.
 *
 *   dt    = now - last_ts                     (ns)
 *   drain = 12 * dt                           (C = 12 B/ns ~ 96 Gbps)
 *   inc   = n * pkt_len                       (n senders emulated by one real sender)
 *   Q     = max(0, Q + inc - drain)           (virtual queue depth in bytes)
 *   ECN   = RED on Q  (KMIN = 100 KB, KMAX = 400 KB)
 *
 * The queue / RED / ECN statements are unchanged. Everything added for logging is marked
 * "LOG" and only READS existing fields; it never feeds back into the queue logic.
 *
 * Per-packet LOG design
 * ---------------------
 *  - Control plane sets log_en_reg = 1 to start and 0 to freeze logging.
 *  - Every IPv4 packet draws a random byte; ~1 in 64 packets (SAMPLE_MASK) is "sampled"
 *    and gets the next ring slot (free-running counter in slot_reg, slot = counter mod 32768).
 *    All other packets (and everything while frozen) use the extra DUMP slot, so the ring
 *    registers are written unconditionally and no gateway is needed in front of them.
 *  - The slot index travels with the packet in a 2-byte bridge header, so the egress
 *    pipeline writes its half of the record (final ECN, egress timestamp, egress bytes)
 *    into the SAME slot.
 *  - Cumulative byte counters (ingress: per logical queue, egress: per egress port) are
 *    sampled into the record, so rate = delta(bytes) / delta(timestamp) between records,
 *    even though only 1 in 64 packets is logged.
 *
 * Every if() below tests a single sign bit, an 8-bit value or an 8-bit slice, because
 * Tofino gateways reject 32-bit comparisons ("condition too complex").
 */

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<32> reg_entry_t;
typedef bit<32> reg_index_t;
typedef bit<16> log_idx_t;

enum bit<16> ether_type_t {
    IPV4 = 0x0800
}

const int MAX_ENTRIES = 512;

const bit<32> DT_CLAMP = 1 << 24;       // clamp dt (~16 ms) so shifts cannot overflow 32 bits
const bit<32> KMIN     = 100 * 1024;    // RED thresholds (bytes)
const bit<32> KMAX     = 400 * 1024;

/* ---------------- LOG parameters ---------------- */
const int        LOG_ENTRIES = 32768;               // ring size (slot index uses 15 bits)
const int        LOG_SLOTS   = LOG_ENTRIES + 1;     // + one DUMP slot for unsampled packets
const log_idx_t  LOG_DUMP    = 32768;               // index of the DUMP slot
const bit<8>     SAMPLE_MASK = 0x3F;                // sample 1 in 64 packets (0x00 = every packet)
// 0xFF samples 1 in 256, so the ring covers about 2.8 s. Use this for the stepped test

header ethernet_h {
    mac_addr_t   dst_addr;
    mac_addr_t   src_addr;
    ether_type_t ether_type;
}

header ipv4_h {
    bit<4>       version;
    bit<4>       ihl;
    bit<6>       diffserv;
    bit<2>       ecn;
    bit<16>      total_len;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      frag_offset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdr_checksum;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;
}

/* LOG: bridged metadata, ingress -> egress (stripped again before the packet leaves) */
header bridge_h {
    log_idx_t    log_idx;
}

/* LOG: 64-bit register entry made of two 32-bit halves (one stateful access writes both) */
struct pair32_t {
    bit<32> lo;
    bit<32> hi;
}

struct my_ingress_headers_t {
    bridge_h     bridge;
    ethernet_h   ethernet;
    ipv4_h       ipv4;
}

struct my_ingress_metadata_t {
    bit<32>        now;
    bit<32>        last_ts;
    bit<32>        len;
    bit<32>        dt;
    bit<32>        drain;
    bit<32>        drain_a;
    bit<32>        drain_b;
    bit<32>        inc;
    bit<32>        pos;        // inc - drain  (sign bit set when negative)
    bit<32>        neg;        // drain - inc
    bit<32>        q;          // logical queue depth after this packet
    bit<32>        kmax_d;     // q - KMAX   (sign bit clear => q >= KMAX)
    bit<32>        red_a;      // q - KMIN   (sign bit clear => q >= KMIN)
    bit<16>        red_p;      // RED mark threshold (15-bit scale)
    bit<16>        red_d;      // rnd - red_p (sign bit set => rnd < red_p => mark)
    bit<16>        rnd;        // random number, top bit cleared (0..32767)
    bit<8>         nshift;     // log2(n) emulated senders
    reg_index_t    qidx;       // which logical queue
    /* LOG */
    bit<32>        slot;       // free-running sample counter value
    bit<32>        bytes;      // cumulative bytes of this logical queue (after this packet)
    bit<8>         samp;       // sampling random byte (masked)
    bit<8>         log_en;     // logging enabled by the control plane
}

parser IngressParser(packet_in        pkt,
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition init_meta;
    }

    state init_meta {
        meta.now     = 0;
        meta.last_ts = 0;
        meta.len     = 0;
        meta.dt      = 0;
        meta.drain   = 0;
        meta.drain_a = 0;
        meta.drain_b = 0;
        meta.inc     = 0;
        meta.pos     = 0;
        meta.neg     = 0;
        meta.q       = 0;
        meta.kmax_d  = 0;
        meta.red_a   = 0;
        meta.red_p   = 0;
        meta.red_d   = 0;
        meta.rnd     = 0;
        meta.nshift  = 0;
        meta.qidx    = 0;
        /* LOG */
        meta.slot    = 0;
        meta.bytes   = 0;
        meta.samp    = 0;
        meta.log_en  = 0;
        hdr.bridge.setValid();
        hdr.bridge.log_idx = LOG_DUMP;      // default: record goes to the DUMP slot
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ether_type_t.IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

control Ingress(
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    Random<bit<16>>() rng;
    Random<bit<8>>()  rng_s;     // LOG: separate RNG for sampling, so sampling is independent of RED

    /* ---------- forwarding: entries are added from the control plane ---------- */
    action fwd(PortId_t port, bit<8> nshift, reg_index_t qidx) {
        ig_tm_md.ucast_egress_port = port;
        meta.nshift = nshift;
        meta.qidx = qidx;
    }

    table l2 {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            fwd;
        }
        size = 64;
    }

    /* ---------- last timestamp (read old, write new) ---------- */
    Register<reg_entry_t, reg_index_t>(MAX_ENTRIES) last_ts_reg;

    RegisterAction<reg_entry_t, reg_index_t, bit<32>>(last_ts_reg) swap_ts = {
        void apply(inout reg_entry_t register_data, out bit<32> last_ts) {
            last_ts = register_data;
            register_data = meta.now;
        }
    };

    /* ---------- dt (clamped) and drain = 12 * dt ---------- */
    action calc_dt() {
        meta.dt = meta.now - meta.last_ts;
    }

    action clamp_dt() {
        meta.dt = DT_CLAMP;
    }

    action drain_shifts() {
        meta.drain_a = meta.dt << 3;    // dt * 8
        meta.drain_b = meta.dt << 2;    // dt * 4
    }

    action drain_sum() {
        meta.drain = meta.drain_a + meta.drain_b;    // dt * 12
    }

    /* ---------- inc = n * len, n = 2^nshift ---------- */
    action get_len() {
        meta.len = (bit<32>)hdr.ipv4.total_len;
    }

    action inc_n1() {
        meta.inc = meta.len;
    }

    action inc_n2() {
        meta.inc = meta.len << 1;
    }

    action inc_n4() {
        meta.inc = meta.len << 2;
    }

    action inc_n8() {
        meta.inc = meta.len << 3;
    }

    table mult_n {
        key = {
            meta.nshift : exact;
        }
        actions = {
            inc_n1;
            inc_n2;
            inc_n4;
            inc_n8;
        }
        const entries = {
            0 : inc_n1();
            1 : inc_n2();
            2 : inc_n4();
            3 : inc_n8();
        }
        size = 8;
    }

    /* ---------- both differences; sign bit of pos tells which one is valid ---------- */
    action calc_diff() {
        meta.pos = meta.inc - meta.drain;
        meta.neg = meta.drain - meta.inc;
    }

    /* ---------- the logical queue itself ---------- */
    Register<reg_entry_t, reg_index_t>(MAX_ENTRIES) q_reg;

    RegisterAction<reg_entry_t, reg_index_t, bit<32>>(q_reg) q_grow = {
        void apply(inout reg_entry_t register_data, out bit<32> q_data) {
            register_data = register_data + meta.pos;
            q_data = register_data;
        }
    };

    RegisterAction<reg_entry_t, reg_index_t, bit<32>>(q_reg) q_shrink = {
        void apply(inout reg_entry_t register_data, out bit<32> q_data) {
            register_data = register_data |-| meta.neg;   // saturating subtract -> floor at 0
            q_data = register_data;
        }
    };

    /* ---------- ECN (RED) from Q, using sign bits only ---------- */
    action rnd_mask() {
        meta.rnd = meta.rnd & 16w0x7FFF;     // keep 15 bits so the sign-bit compare is valid
    }

    action q_sub_kmax() {
        meta.kmax_d = meta.q - KMAX;
    }

    action q_sub_kmin() {
        meta.red_a = meta.q - KMIN;
    }

    action red_slice() {
        meta.red_p = meta.red_a[22:7];       // (Q - KMIN) >> 7 : 0 .. ~2400 of 32768 (~7% at KMAX)
    }

    action rnd_sub() {
        meta.red_d = meta.rnd - meta.red_p;
    }

    action mark_ecn() {
        hdr.ipv4.ecn = 3;                    // CE
    }

    /* ================= TELEMETRY: latest-value ingress registers ================= */
    Register<bit<32>, bit<32>>(1) ingress_port_reg;

    RegisterAction<bit<32>, bit<32>, bit<32>>(ingress_port_reg) write_ingress_port = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = (bit<32>)ig_intr_md.ingress_port;
            result = register_data;
        }
    };

    Register<bit<32>, bit<32>>(1) ingress_timestamp_reg;

    RegisterAction<bit<32>, bit<32>, bit<32>>(ingress_timestamp_reg) write_ingress_timestamp = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = ig_prsr_md.global_tstamp[31:0];
            result = register_data;
        }
    };

    Register<bit<32>, bit<32>>(1) packet_color_reg;

    RegisterAction<bit<32>, bit<32>, bit<32>>(packet_color_reg) write_packet_color = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = (bit<32>)ig_tm_md.packet_color;
            result = register_data;
        }
    };

    /* ================= LOG: control, sampling, counters, ring buffers (ingress half) ================= */

    // Control plane writes 1 = log, 0 = frozen
    Register<bit<8>, bit<32>>(1) log_en_reg;

    RegisterAction<bit<8>, bit<32>, bit<8>>(log_en_reg) read_log_en = {
        void apply(inout bit<8> register_data, out bit<8> en) {
            en = register_data;
        }
    };

    action samp_mask() {
        meta.samp = meta.samp & SAMPLE_MASK;
    }

    // Free-running count of logged (sampled) packets; control plane resets it before a run
    Register<bit<32>, bit<32>>(1) slot_reg;

    RegisterAction<bit<32>, bit<32>, bit<32>>(slot_reg) next_slot = {
        void apply(inout bit<32> register_data, out bit<32> slot) {
            slot = register_data;
            register_data = register_data + 1;
        }
    };

    action set_slot() {
        hdr.bridge.log_idx = (bit<16>)meta.slot[14:0];     // slot = counter mod LOG_ENTRIES
    }

    // Cumulative IP bytes per logical queue (all IPv4 packets, sampled or not)
    Register<reg_entry_t, reg_index_t>(MAX_ENTRIES) bytes_reg;

    RegisterAction<reg_entry_t, reg_index_t, bit<32>>(bytes_reg) add_bytes = {
        void apply(inout reg_entry_t register_data, out bit<32> total) {
            register_data = register_data + meta.len;
            total = register_data;
        }
    };

    // Ring A: lo = ingress timestamp (ns, low 32 bits), hi = logical queue Q (bytes)
    Register<pair32_t, log_idx_t>(LOG_SLOTS) ring_tq;

    RegisterAction<pair32_t, log_idx_t, bit<32>>(ring_tq) log_tq = {
        void apply(inout pair32_t d, out bit<32> r) {
            d.lo = meta.now;
            d.hi = meta.q;
            r = d.lo;
        }
    };

    // Ring B: lo = cumulative ingress bytes of this queue, hi = ECN field BEFORE marking
    Register<pair32_t, log_idx_t>(LOG_SLOTS) ring_bytes_ecn;

    RegisterAction<pair32_t, log_idx_t, bit<32>>(ring_bytes_ecn) log_bytes_ecn = {
        void apply(inout pair32_t d, out bit<32> r) {
            d.lo = meta.bytes;
            d.hi = (bit<32>)hdr.ipv4.ecn;
            r = d.lo;
        }
    };

    // Ring C: lo = ingress port, hi = logical queue index
    Register<pair32_t, log_idx_t>(LOG_SLOTS) ring_port_qidx;

    RegisterAction<pair32_t, log_idx_t, bit<32>>(ring_port_qidx) log_port_qidx = {
        void apply(inout pair32_t d, out bit<32> r) {
            d.lo = (bit<32>)ig_intr_md.ingress_port;
            d.hi = meta.qidx;
            r = d.lo;
        }
    };
    /* ================= end LOG declarations ================= */

    apply {
        meta.now = (bit<32>)ig_intr_md.ingress_mac_tstamp[31:0];
        meta.rnd = rng.get();
        rnd_mask();
        meta.samp = rng_s.get();                          // LOG
        samp_mask();                                      // LOG
        meta.log_en = read_log_en.execute(0);             // LOG
        l2.apply();
        if (hdr.ipv4.isValid()) {
            if (meta.log_en == 1 && meta.samp == 0) {     // LOG: this packet is sampled -> real slot
                meta.slot = next_slot.execute(0);
                set_slot();
            }

            meta.last_ts = swap_ts.execute(meta.qidx);
            calc_dt();
            if (meta.dt[31:24] != 0) {          // dt >= 2^24, same as DT_CLAMP
                clamp_dt();
            }

            drain_shifts();
            drain_sum();
            get_len();
            meta.bytes = add_bytes.execute(meta.qidx);    // LOG: cumulative bytes
            mult_n.apply();

            calc_diff();
            if (meta.pos[31:31] == 0) {         // inc >= drain
                meta.q = q_grow.execute(meta.qidx);
            } else {
                meta.q = q_shrink.execute(meta.qidx);
            }

            /* LOG: write this packet's ingress record (Q is final, ECN not yet marked) */
            log_tq.execute(hdr.bridge.log_idx);
            log_bytes_ecn.execute(hdr.bridge.log_idx);
            log_port_qidx.execute(hdr.bridge.log_idx);

            q_sub_kmax();
            q_sub_kmin();
            red_slice();
            rnd_sub();

            if (hdr.ipv4.ecn != 0) {
                if (meta.kmax_d[31:31] == 0) {                                   // q >= KMAX
                    mark_ecn();
                } else if (meta.red_a[31:31] == 0 && meta.red_d[15:15] == 1) {   // q >= KMIN and rnd < red_p
                    mark_ecn();
                }
            }
        }

        /* TELEMETRY: capture latest packet's ingress metadata (index 0) */
        write_ingress_port.execute(0);
        write_ingress_timestamp.execute(0);
        write_packet_color.execute(0);
    }
}

control IngressDeparser(packet_out pkt,
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr.bridge);        // LOG: bridged slot index goes first
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
    }
}

/*************************************************************************
 ****************  E G R E S S   (checksum + telemetry + LOG)  ***********
 *************************************************************************/

struct my_egress_headers_t {
    bridge_h     bridge;
    ethernet_h   ethernet;
    ipv4_h       ipv4;
}

struct my_egress_metadata_t {
    bit<32>      len;          // LOG
    bit<32>      eg_bytes;     // LOG
}

parser EgressParser(packet_in        pkt,
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    state start {
        meta.len      = 0;
        meta.eg_bytes = 0;
        pkt.extract(eg_intr_md);
        transition parse_bridge;
    }

    state parse_bridge {                 // LOG: read the slot index set in ingress
        pkt.extract(hdr.bridge);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ether_type_t.IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

control Egress(
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    /* ================= TELEMETRY: latest-value egress registers ================= */

    // Egress port
    Register<bit<32>, bit<32>>(1) egress_port_reg;
    RegisterAction<bit<32>, bit<32>, bit<32>>(egress_port_reg) write_egress_port = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = (bit<32>)eg_intr_md.egress_port;
            result = register_data;
        }
    };

    // Egress queue ID
    Register<bit<32>, bit<32>>(1) egress_qid_reg;
    RegisterAction<bit<32>, bit<32>, bit<32>>(egress_qid_reg) write_egress_qid = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = (bit<32>)eg_intr_md.egress_qid;
            result = register_data;
        }
    };

    // Packet length
    Register<bit<32>, bit<32>>(1) packet_length_reg;
    RegisterAction<bit<32>, bit<32>, bit<32>>(packet_length_reg) write_packet_length = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = (bit<32>)eg_intr_md.pkt_length;
            result = register_data;
        }
    };

    // Enqueue queue depth
    Register<bit<32>, bit<32>>(1) enq_qdepth_reg;
    RegisterAction<bit<32>, bit<32>, bit<32>>(enq_qdepth_reg) write_enq_qdepth = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = (bit<32>)eg_intr_md.enq_qdepth;
            result = register_data;
        }
    };

    // Dequeue queue depth
    Register<bit<32>, bit<32>>(1) deq_qdepth_reg;
    RegisterAction<bit<32>, bit<32>, bit<32>>(deq_qdepth_reg) write_deq_qdepth = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = (bit<32>)eg_intr_md.deq_qdepth;
            result = register_data;
        }
    };

    // Enqueue timestamp
    Register<bit<32>, bit<32>>(1) enq_tstamp_reg;
    RegisterAction<bit<32>, bit<32>, bit<32>>(enq_tstamp_reg) write_enq_tstamp = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = (bit<32>)eg_intr_md.enq_tstamp;
            result = register_data;
        }
    };

    // Congestion status
    Register<bit<32>, bit<32>>(1) enq_congest_stat_reg;
    RegisterAction<bit<32>, bit<32>, bit<32>>(enq_congest_stat_reg) write_enq_congest_stat = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = (bit<32>)eg_intr_md.enq_congest_stat;
            result = register_data;
        }
    };

    Register<bit<32>, bit<32>>(1) deq_congest_stat_reg;
    RegisterAction<bit<32>, bit<32>, bit<32>>(deq_congest_stat_reg) write_deq_congest_stat = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = (bit<32>)eg_intr_md.deq_congest_stat;
            result = register_data;
        }
    };

    Register<bit<32>, bit<32>>(1) app_pool_congest_stat_reg;
    RegisterAction<bit<32>, bit<32>, bit<32>>(app_pool_congest_stat_reg) write_app_pool_congest_stat = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = (bit<32>)eg_intr_md.app_pool_congest_stat;
            result = register_data;
        }
    };

    // Egress parser timestamp: lower 32 bits
    Register<bit<32>, bit<32>>(1) egress_timestamp_reg;
    RegisterAction<bit<32>, bit<32>, bit<32>>(egress_timestamp_reg) write_egress_timestamp = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = eg_prsr_md.global_tstamp[31:0];
            result = register_data;
        }
    };

    /* ================= LOG: egress half of the record ================= */

    action get_len_e() {
        meta.len = (bit<32>)hdr.ipv4.total_len;
    }

    // Cumulative IP bytes leaving each egress port (all IPv4 packets, sampled or not)
    Register<bit<32>, PortId_t>(512) eg_bytes_reg;

    RegisterAction<bit<32>, PortId_t, bit<32>>(eg_bytes_reg) add_eg_bytes = {
        void apply(inout bit<32> register_data, out bit<32> total) {
            register_data = register_data + meta.len;
            total = register_data;
        }
    };

    // Ring D: lo = egress timestamp (ns, low 32 bits), hi = ECN field AFTER ingress marking
    Register<pair32_t, log_idx_t>(LOG_SLOTS) ring_e_ts_ecn;

    RegisterAction<pair32_t, log_idx_t, bit<32>>(ring_e_ts_ecn) log_e_ts_ecn = {
        void apply(inout pair32_t d, out bit<32> r) {
            d.lo = eg_prsr_md.global_tstamp[31:0];
            d.hi = (bit<32>)hdr.ipv4.ecn;
            r = d.lo;
        }
    };

    // Ring E: lo = cumulative bytes through this egress port, hi = egress port
    Register<pair32_t, log_idx_t>(LOG_SLOTS) ring_e_bytes_port;

    RegisterAction<pair32_t, log_idx_t, bit<32>>(ring_e_bytes_port) log_e_bytes_port = {
        void apply(inout pair32_t d, out bit<32> r) {
            d.lo = meta.eg_bytes;
            d.hi = (bit<32>)eg_intr_md.egress_port;
            r = d.lo;
        }
    };
    /* ================= end LOG declarations ================= */

    apply {
        /* TELEMETRY: capture latest packet's egress metadata (index 0) */
        write_egress_port.execute(0);
        write_egress_qid.execute(0);
        write_packet_length.execute(0);
        write_enq_qdepth.execute(0);
        write_deq_qdepth.execute(0);
        write_enq_tstamp.execute(0);
        write_enq_congest_stat.execute(0);
        write_deq_congest_stat.execute(0);
        write_app_pool_congest_stat.execute(0);
        write_egress_timestamp.execute(0);

        /* LOG: egress half of the record, same slot as the ingress half */
        if (hdr.ipv4.isValid()) {
            get_len_e();
            meta.eg_bytes = add_eg_bytes.execute(eg_intr_md.egress_port);
            log_e_ts_ecn.execute(hdr.bridge.log_idx);
            log_e_bytes_port.execute(hdr.bridge.log_idx);
        }
    }
}

control EgressDeparser(packet_out pkt,
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md,
    in    egress_intrinsic_metadata_t               eg_intr_md)
{
    Checksum() ipv4_checksum;

    apply {
        /* ECN bits may have changed in ingress, so recompute the IPv4 header checksum */
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.ecn,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        }
        /* bridge header is NOT emitted, so it is stripped before the packet leaves */
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
    }
}

Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
