/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<32> reg_entry_t;
typedef bit<32> reg_index_t;
typedef bit<7> PortId_Pad_t;
typedef bit<6> MirrorId_Pad_t;
  
enum bit<16> ether_type_t {
    IPV4 = 0x0800,
    ARP  = 0x0806,
    TPID = 0x8100,
    IPV6 = 0x86DD,
    MPLS = 0x8847,
    BTH  = 0x12B7
}

const PortId_t CPU_PORT = 66;
const int MAX_ENTRIES = 1024;

/* Table Sizes */
/* 
 * We use C preprocessor here so that we can easily overwrite
 * these constants from the command line
 */
#ifndef IPV4_HOST_SIZE
  #define IPV4_HOST_SIZE 65536
#endif

#ifndef IPV4_LPM_SIZE 
  #define IPV4_LPM_SIZE 12288
#endif

const int IPV4_HOST_TABLE_SIZE = IPV4_HOST_SIZE;
const int IPV4_LPM_TABLE_SIZE  = IPV4_LPM_SIZE;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    mac_addr_t   dst_addr;
    mac_addr_t   src_addr;
    ether_type_t ether_type;
}

header vlan_tag_h {
    bit<3>       pri;
    bit<1>       dei;
    bit<12>      vid;
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

/* UDP header — required for RoCEv2 (dst_port 4791) */
header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

/* BTH — RoCEv2 Base Transport Header (12 bytes) */
header bth_h {
    bit<8>  opcode;
    bit<1>  se;
    bit<1>  migration_req;
    bit<2>  pad_count;
    bit<4>  transport_hdr_ver;
    bit<16> partition_key;
    bit<1>  f_res1;
    bit<1>  b_res1;
    bit<6>  reserved;
    bit<24> dst_qp;
    bit<1>  ack_req;
    bit<7>  rsvd;
    bit<24> psn;
}

/*** Internal Headers ***/

typedef bit<4> header_type_t; 
typedef bit<4> header_info_t; 

const header_type_t HEADER_TYPE_BRIDGE         = 0xB;
const header_type_t HEADER_TYPE_MIRROR_INGRESS = 0xC;
const header_type_t HEADER_TYPE_MIRROR_EGRESS  = 0xD;
const header_type_t HEADER_TYPE_RESUBMIT       = 0xA;

/* 
 * This is a common "preamble" header that must be present in all internal
 * headers. The only time you do not need it is when you know that you are
 * not going to have more than one internal header type ever
 */

#define INTERNAL_HEADER         \
    header_type_t header_type;  \
    header_info_t header_info

header inthdr_h {
    INTERNAL_HEADER;
}

/* Bridged metadata */
header bridge_h {
    INTERNAL_HEADER;
    @padding PortId_Pad_t pad0; PortId_t ingress_port;

}

/* Ingress mirroring information */
const MirrorType_t ING_PORT_MIRROR = 3; 
const MirrorType_t EGR_PORT_MIRROR = 5;

header ing_port_mirror_h {
    INTERNAL_HEADER;
    @padding PortId_Pad_t   pad0;  PortId_t    ingress_port;
    @padding MirrorId_Pad_t pad1;  MirrorId_t  mirror_session;
}
header egr_port_mirror_h {
    INTERNAL_HEADER;
    @padding PortId_Pad_t    pad0; PortId_t    ingress_port;          /*  2 */
    @padding PortId_Pad_t    pad1; PortId_t    egress_port;           /*  2 */
    @padding MirrorId_Pad_t  pad2; MirrorId_t  mirror_session;
}

header timestamp_h {
    bit<48>      egress_global_timestamp;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

// Headers to parse in Ingress pipeline
struct my_ingress_headers_t {
    bridge_h     bridge;
    ethernet_h   ethernet;
    vlan_tag_h   vlan_tag;
    ipv4_h       ipv4;
    udp_h        udp;
    bth_h        bth;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

// Ingress metadata to use accross ingress pipeline
struct my_ingress_metadata_t {
    header_type_t  mirror_header_type;
    header_info_t  mirror_header_info;
    PortId_t       ingress_port;
    MirrorId_t     mirror_session;
    bit<5>         padding;
    bit<32>        ts_diff;
    bit<32>        end_time_2;
    bit<32>        ecn_config;
    bit<32>        qp_duration;
    bit<32>        qpn;
    /**** Throughput / timestamp measurement (post-trigger) ****/
    bit<32>        cur_ts;      /* lower 32b of arrival timestamp (ns)      */
    bit<32>        pkt_len;     /* wire bytes derived from hdr.ipv4.total_len */
    bit<32>        byte_count;  /* running byte total for this QP           */
    bit<32>        pkt_count;   /* running packet total for this QP         */
    bit<32>        first_ts;    /* ts of first post-trigger pkt of this QP  */
    bit<32>        elapsed;     /* cur_ts - first_ts (ns)                   */
    bit<32>        g_start;     /* ts of the first post-trigger packet      */
    bit<32>        g_elapsed;   /* cur_ts - g_start (ns), drives the bins   */
    bit<32>        capture_dur; /* capture length in ns, from capture_cfg   */
    bit<32>        cap_left;    /* capture_dur - g_elapsed; MSB set = over  */

    /**** Logical queue / adaptive ECN injection ****/
    bit<8>         lq_id;        /* which modelled bottleneck                */
    bit<32>        lq_idx;       /* lq_id widened for register addressing    */
    bit<1>         lq_valid;     /* this packet feeds a logical queue        */
    bit<1>         lq_arm;       /* injection window is open for this packet */
    bit<1>         lq_adapt;     /* run the closed-loop controller           */
    bit<1>         lq_flush;     /* tick gap too large: reset the queue      */
    bit<1>         lq_mark;      /* the coin came up mark                    */
    bit<1>         lq_ect;       /* outer IPv4 is ECT-capable                */
    bit<32>        lq_bytes;     /* pkt_len << LQ_N_SHIFT   (the n*A term)   */
    bit<32>        lq_tick;      /* cur_ts >> LQ_TICK_SHIFT                  */
    bit<32>        lq_dticks;    /* ticks elapsed since the previous packet  */
    bit<6>         lq_dtk;       /* dticks clamped to 0..LQ_MAX_K+1          */
    bit<32>        lq_drain;     /* dticks * C * T, from action data         */
    bit<32>        lq_up;        /* net bytes to add this packet             */
    bit<32>        lq_dn;        /* net bytes to subtract this packet        */
    bit<32>        lq_q;         /* Q after this packet                      */
    bit<32>        lq_qprev;     /* Q at the previous tick                   */
    bit<32>        lq_qtarget;   /* setpoint Q*                              */
    bit<16>        lq_qkey;      /* Q >> LQ_Q_KEY_SHIFT, range-match key     */
    bit<32>        lq_err_up;    /* unsigned positive half of the error      */
    bit<32>        lq_err_dn;    /* unsigned negative half of the error      */
    bit<32>        lq_padj;      /* magnitude applied to p_bias this tick    */
    bit<32>        lq_pbias;     /* adaptive bias, neutral at LQ_BIAS_ZERO   */
    bit<16>        lq_red;       /* static RED curve output                  */
    bit<16>        lq_ptotal;    /* final marking probability                */
    bit<16>        lq_rand;
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    // Parse headers progresively for operations in Ingress
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition init_meta;
    }

    // Initialise metadata
    state init_meta {
        /* Explicit per-field initialisation. The previous positional list had
         * to be kept exactly in step with the struct; adding the logical-queue
         * fields to it would silently misalign every value after the insertion
         * point, so it is spelled out instead. */
        meta.mirror_header_type = 0;
        meta.mirror_header_info = 0;
        meta.ingress_port       = 0;
        meta.mirror_session     = 0;
        meta.padding            = 0;
        meta.ts_diff            = 0;
        meta.end_time_2         = 0;
        meta.ecn_config         = 0;
        meta.qp_duration        = 0;
        meta.qpn                = 0;
        meta.cur_ts             = 0;
        meta.pkt_len            = 0;
        meta.byte_count         = 0;
        meta.pkt_count          = 0;
        meta.first_ts           = 0;
        meta.elapsed            = 0;
        meta.g_start            = 0;
        meta.g_elapsed          = 0;
        meta.capture_dur        = 0;
        meta.cap_left           = 0;

        meta.lq_id              = 0;
        meta.lq_idx             = 0;
        meta.lq_valid           = 0;
        meta.lq_arm             = 0;
        meta.lq_adapt           = 0;
        meta.lq_flush           = 0;
        meta.lq_mark            = 0;
        meta.lq_ect             = 0;
        meta.lq_bytes           = 0;
        meta.lq_tick            = 0;
        meta.lq_dticks          = 0;
        meta.lq_dtk             = 0;
        meta.lq_drain           = 0;
        meta.lq_up              = 0;
        meta.lq_dn              = 0;
        meta.lq_q               = 0;
        meta.lq_qprev           = 0;
        meta.lq_qtarget         = 0;
        meta.lq_qkey            = 0;
        meta.lq_err_up          = 0;
        meta.lq_err_dn          = 0;
        meta.lq_padj            = 0;
        meta.lq_pbias           = 0;
        meta.lq_red             = 0;
        meta.lq_ptotal          = 0;
        meta.lq_rand            = 0;

        hdr.bridge.setValid();
        hdr.bridge.header_type  = HEADER_TYPE_BRIDGE;
        hdr.bridge.header_info  = 0;

        hdr.bridge.ingress_port = ig_intr_md.ingress_port; 
        
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ether_type_t.TPID:  parse_vlan_tag;
            ether_type_t.IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ether_type_t.IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17      : parse_udp;   // UDP → check for RoCEv2
            default : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            ether_type_t.BTH  : parse_bth;   // RoCEv2 port
            default           : accept;      // non-RoCE UDP: don't error out
        }
    }

    state parse_bth {
        pkt.extract(hdr.bth);
        transition accept;
    }
}


    /***************** M A T C H - A C T I O N  *********************/
const bit<32> MAX_QPS = 2048;
/* MAX_QPS is 2^11, so a QP index is dst_qp[10:0] */

/* hdr.ipv4.total_len counts IP header + payload only. To get bytes on the
 * wire add Ethernet hdr (14) + FCS (4) + preamble/SFD (8) + IFG (12) = 38.
 * Set this to 0 if you want pure IP-level bytes instead. */
const bit<32> L2_WIRE_OVERHEAD = 38;

/* =========================================================================
 * C O N T I N U O U S   T I M E - B I N N E D   T H R O U G H P U T
 * -------------------------------------------------------------------------
 * One bin per fixed time interval, running continuously from the first
 * post-trigger packet until the capture window is full. Every packet adds
 * its wire bytes to the bin covering its arrival time:
 *
 *   global_bin = (now - capture_start) >> BIN_SHIFT
 *
 * The bin width MUST be a power of two nanoseconds — there is no divider in
 * the data plane, so the bin number is a bit-slice of elapsed time, not a
 * division. BIN_SHIFT=12 gives a 4096 ns (4.096 us) bin.
 *
 * SHARDING. 262144 bins x 32 bits = 1 MB, and a register array lives in ONE
 * MAU stage, so it cannot be one array. The bin space is therefore split
 * across SHARDS arrays of SHARD_BINS each; the top bits of the bin number
 * select the shard, the low bits index inside it. Only one shard is touched
 * per packet, and the shards are mutually exclusive, so the compiler can
 * pack them into separate SALUs.
 *
 *   bin   = elapsed[29:12]   (18 bits -> 262144 bins)
 *   shard = elapsed[29:28]   (2 bits  -> 4 arrays)
 *   off   = elapsed[27:12]   (16 bits -> 65536 bins per array)
 *   guard = elapsed[31:30] == 0   (still inside the 2^30 ns window)
 *
 * DEFAULT: 4.096 us bins x 262144 = 1.0737 s of capture, 1 MB of SRAM.
 *
 * If bf-p4c cannot fit this, the dials, in order of preference:
 *   SHARDS 2  -> 536 ms at 4.096 us,   512 KB   (guard becomes [31:29])
 *   SHARDS 1, BIN_SHIFT 14 -> 1.0737 s at 16.384 us, 256 KB
 * Both need the slices in the apply block changed to match; the arithmetic
 * is spelled out beside them.
 * =========================================================================*/
/* -------------------------------------------------------------------------
 * TPUT_PROFILE selects how many shard arrays the time series uses. This is
 * the main resource dial in the program.
 *
 * Two separate limits bite. Every register array needs a stateful ALU, and a
 * Tofino-1 stage has four of them; and the four-shard profile is 1 MB of
 * SRAM, which is more than any single stage holds, so it spreads over three
 * or four stages on memory alone. The logical queue below adds a chain of
 * roughly five DEPENDENT stages -- tick -> drain lookup -> Q -> qprev ->
 * p_bias -> signal -- that cannot be packed alongside anything downstream of
 * it. Together with the existing trigger/duration chain that is close to the
 * twelve ingress stages Tofino-1 has.
 *
 *   4 : 4 arrays, 4.096 us bins, 1.0737 s window, 1 MB    <- original
 *   2 : 2 arrays, 4.096 us bins, 536 ms window,   512 KB
 *   1 : 1 array, 16.384 us bins, 1.0737 s window, 256 KB  <- default with LQ
 *   0 : compiled out entirely
 *
 * On Tofino-1 the ingress pipeline cannot hold profile 4 AND the logical
 * queue; use 1 (or 0) while running injection experiments. The slices in the
 * apply block are switched to match automatically.
 * ---------------------------------------------------------------------- */
#ifndef TPUT_PROFILE
  #define TPUT_PROFILE 1
#endif

#if   TPUT_PROFILE == 4
  #define BIN_SHIFT 12
  const bit<32> BIN_NS     = 4096;
  const bit<32> SHARD_BINS = 65536;
  const bit<32> SHARDS     = 4;
#elif TPUT_PROFILE == 2
  #define BIN_SHIFT 12
  const bit<32> BIN_NS     = 4096;
  const bit<32> SHARD_BINS = 65536;
  const bit<32> SHARDS     = 2;
#elif TPUT_PROFILE == 1
  #define BIN_SHIFT 14
  const bit<32> BIN_NS     = 16384;
  const bit<32> SHARD_BINS = 65536;
  const bit<32> SHARDS     = 1;
#else
  #define BIN_SHIFT 14
  const bit<32> BIN_NS     = 16384;
  const bit<32> SHARD_BINS = 1;
  const bit<32> SHARDS     = 1;
#endif

const bit<32> TOTAL_BINS      = SHARDS * SHARD_BINS;

/* =========================================================================
 * L O G I C A L   Q U E U E   -   C O N G E S T I O N   I N J E C T I O N
 * -------------------------------------------------------------------------
 * Traffic runs 100G in / 100G out, so nothing ever physically queues and the
 * RNIC never sees a congestion signal. Reintroduce the missing state as a
 * LOGICAL queue driven by the arrival rate this pipeline already measures:
 *
 *       dQ/dt = n*A(t) - C
 *
 *   A(t) = observed arrival rate (already computed here as meta.pkt_len)
 *   n    = sender-replication multiplier: pretend n copies of this traffic
 *   C    = drain rate of the imaginary bottleneck we are modelling
 *   Q    = logical queue build-up, in bytes
 *
 * FILL happens on every packet:   Q += pkt_len << LQ_N_SHIFT
 * DRAIN is self-clocked off the packet timestamps this program already reads.
 *   Each packet computes  tick = cur_ts >> LQ_TICK_SHIFT  and the first packet
 *   of a new tick pays the drain for however many ticks elapsed:
 *
 *       Q += n*bytes - (dticks * C * T)
 *
 * WHY NOT A PACKET GENERATOR. The textbook way to drain is a pktgen timer app
 * firing every T ns. That needs a spare recirculation port and its own parser
 * path, and this ingress pipeline is already carrying ten register arrays.
 * Self-clocking off the data packets costs one extra register instead.
 *
 * WHY dticks MATTERS -- do not simplify this away. As the RNIC reacts, the
 * sender slows, inter-packet gaps grow past one tick, and ticks start being
 * SKIPPED. If a skipped tick meant a skipped drain, Q would freeze high
 * exactly when the sender is cooperating: a positive-feedback ratchet where
 * the injector marks harder the more the RNIC obeys. Simulated, at n=16 and
 * C=150 Gbps a 5 Gbps sender offers only 80 Gbps -- the logical queue should
 * be EMPTY -- but paying only one C*T per advance reports a 26 MB queue and
 * marks 89% of packets. Paying dticks*C*T gives 0%.
 *
 * NO MULTIPLIER IS USED. dticks*C*T is not computed; it is looked up.
 * lq_drain_tbl is an exact-match table on (lq_id, dticks clamped to 0..33)
 * whose action data holds the products 1*d, 2*d, ... 32*d that the control
 * plane precomputed. Beyond 32 ticks the link was idle long enough that any
 * real queue would have emptied, so the entry flushes Q instead.
 *
 * WHERE n LIVES. Scaling a queue is linear, so multiplying arrivals by n is
 * identical to dividing the drain rate and every byte threshold by n:
 *       dQ/dt = n*A - C   <=>   d(Q/n)/dt = A - C/n
 * n is therefore split as n = 2^LQ_N_SHIFT * n_res. The power-of-two part is a
 * free constant shift here; the residual is folded by the control plane into
 * the drain amounts and the thresholds. Set LQ_N_SHIFT = log2(n) for
 * power-of-two n and the register holds Q in exact real bytes.
 *
 * THE SIGNAL.
 *       p_total = clamp( red(Q) + p_bias - LQ_BIAS_ZERO, 0, LQ_P_MAX )
 *       mark iff Random<16>() < p_total  AND  IPv4 ECN is ECT(01|10)
 * red(Q) is a range-matched staircase, so any curve can be installed without
 * recompiling. p_bias is a two-sided PIE-style integrator updated once per
 * tick -- it escalates when the RNIC ignores the marks and backs off when it
 * over-reacts. See the adaptive block in the apply body.
 * =========================================================================*/

#ifndef LQ_ENABLE
  #define LQ_ENABLE 1
#endif
#ifndef LQ_TELEMETRY
  #define LQ_TELEMETRY 1
#endif

/* Drain tick. 2^9 = 512 ns. Q rides a sawtooth of amplitude C*T, so keep
 * C*T <= K_min/8; the control plane refuses anything coarser. */
#define LQ_TICK_SHIFT   9

/* 2^k part of the sender multiplier n. Set to log2(n) for power-of-two n and
 * reg_lq_q then holds real bytes. Must match LQ_N_SHIFT in the control plane. */
#define LQ_N_SHIFT      2

/* RED lookup granularity: Q >> 10 keeps the range-match key at 16 bits,
 * covering 64 MiB of logical queue in 1 KiB buckets. */
#define LQ_Q_KEY_SHIFT  10

/* Largest tick gap the drain table compensates exactly; beyond it, flush. */
#define LQ_MAX_K        32

/* Adaptive controller gains, as right-shift amounts (larger = gentler).
 * These depend on the byte scale of Q and on how fast the CCA under test
 * reacts -- run suggest_gains() in the control plane and recompile. Too large
 * a BETA (weak damping) is the classic failure: a slow limit cycle between
 * empty and K_max.
 *     ALPHA = log2( (4*tau_cca / T) * Q_TARGET / P_MAX )
 *     BETA  = log2( 3 * 2^ALPHA * (dQ/dt)max * T / Q_TARGET )      */
#define LQ_ALPHA_SHIFT  15
#define LQ_BETA_SHIFT   6

const bit<32> LQ_NUM      = 8;           /* modelled bottlenecks             */
const bit<32> LQ_Q_CAP    = 0x0FFFFFFF;  /* saturate Q, never wrap the SALU  */
const bit<32> LQ_P_MAX    = 65535;       /* 16-bit probability = 100%        */

/* p_bias is stored offset: neutral at LQ_BIAS_ZERO, below it suppresses the
 * RED curve, above it amplifies. LQ_BIAS_SPAN is the anti-windup clamp -- the
 * furthest the integrator may travel from neutral. Shrink it if the telemetry
 * shows p_bias parked against a rail. */
const bit<32> LQ_BIAS_ZERO = 65535;
const bit<32> LQ_BIAS_SPAN = 65535;
const bit<32> LQ_BIAS_HI   = LQ_BIAS_ZERO + LQ_BIAS_SPAN;
const bit<32> LQ_BIAS_LO   = LQ_BIAS_ZERO - LQ_BIAS_SPAN;

const bit<2>  ECN_ECT1 = 1;
const bit<2>  ECN_ECT0 = 2;
const bit<2>  ECN_CE   = 3;

/* How long the capture runs, in ns. Set from the control plane at runtime
 * exactly like the ECN marking duration (see capture_cfg below); this is only
 * the compiled-in default. 250000 * 4096 ns = 1.024 s, so the series fills
 * bins 0 .. 249999 and stops. MUST stay <= TOTAL_BINS * BIN_NS (1.0737 s). */
const bit<32> DEFAULT_CAPTURE_NS = 1024000000;

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{

    // Method to mark ecn field as CE(Congestion Experienced)
    action mark_ecn() {
        hdr.ipv4.ecn = 3; // Set ECN to Congestion Experienced (CE)
    }

    /* Open the injection window without marking. The logical queue decides
     * which packets inside the window actually get CE. Install this action in
     * duration_range instead of mark_ecn to switch a QP from "mark everything
     * for D nanoseconds" to occupancy-driven injection; the table keys and the
     * control-plane workflow are unchanged. */
    action lq_arm() {
        meta.lq_arm = 1;
    }

    /************** MIRRORING *****************/
    // Initialize mirroring metadata to start mirroring
    action mirror_pkt(MirrorId_t mirror_session) {
        ig_dprsr_md.mirror_type = ING_PORT_MIRROR;

        meta.mirror_header_type = HEADER_TYPE_MIRROR_INGRESS;
        meta.mirror_header_info = (header_info_t)ING_PORT_MIRROR;

        meta.ingress_port   = ig_intr_md.ingress_port;
        meta.mirror_session = mirror_session;
   
    }
    
    // Table to call mirror action based on key matching
    table pkt_mirror {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            mirror_pkt;
            NoAction;
        } 
        size = 512;
        default_action = NoAction();
    }

    // -------------------------------------------------------
    // Per-QP duration: action stores the looked-up duration
    // into meta so the rest of the pipeline can use it.
    // -------------------------------------------------------
    action set_qp_duration(bit<32> qp_duration_ns) {
        meta.qp_duration = qp_duration_ns;
    }

    action set_default_duration() {
        meta.qp_duration = 0; // fallback constant
    }

    // Match on the 24-bit Destination QP from the BTH header.
    // Populated by the control plane with per-QP durations.
    table qp_duration_tbl {
        key = {
            hdr.bth.dst_qp : exact;   // 24-bit RoCE BTH destination QP
        }
        actions = {
            set_qp_duration;
            set_default_duration;
        }
        size = 512;               // e.g. 1024 or however many QPs you support
        default_action = set_default_duration();
    }

    // -------------------------------------------------------
    // duration_range now uses meta.qp_duration instead of a
    // single global register — range match on ts_diff vs the
    // per-QP duration loaded above.
    // -------------------------------------------------------
    table duration_range {
        key = {
            hdr.bth.dst_qp : exact;   // 24-bit RoCE BTH destination QP
            meta.ecn_config          : exact;
            meta.ts_diff[31:20]      : range;
            meta.ts_diff[19:0]       : range;
        }
        actions = {
            mark_ecn;      // legacy: mark every packet inside the window
            lq_arm;        // new: open the window, let the logical queue decide
            NoAction;
        }
        size = 512;              // one entry per QP
        default_action = NoAction();
    }

    // ECN config register and its read action from bfrt control plane
    Register<reg_entry_t, reg_index_t>(MAX_ENTRIES) ecn_control_reg;
    RegisterAction<reg_entry_t, reg_index_t, bit<32>>(ecn_control_reg) read_ecn_config = {
            void apply(inout reg_entry_t register_data, out bit<32> config_data) {
                    config_data = register_data;
            }
    };

    Register<bit<32>, bit<32>>(MAX_ENTRIES) qpn;
    RegisterAction<bit<32>, bit<32>, bit<32>>(qpn) write_qpn = {
            void apply(inout bit<32> register_data, out bit<32> config_data) {
                    register_data = meta.qpn;
            }
    };


    // -------------------------------------------------------
    // Per-QP end_time register array — indexed by QP number.
    // Sized to MAX_QPS so each QP has its own slot.
    // -------------------------------------------------------
    Register<bit<32>, bit<32>>(MAX_QPS) end_time_reg_per_qp;
    RegisterAction<bit<32>, bit<32>, bit<32>>(end_time_reg_per_qp) read_write_end_time_per_qp = {
        void apply(inout bit<32> register_data, out bit<32> config_data) {
            // Store end timestamp only once (when slot is 0 / expired)
            if (register_data == 0) {
                register_data = meta.end_time_2;
            }
            config_data = register_data;
        }
    };
    
    /* =====================================================================
     * T H R O U G H P U T   +   T I M E S T A M P   A C C O U N T I N G
     * ---------------------------------------------------------------------
     * All four arrays are indexed by the same QP index (dst_qp[10:0]) and are
     * only updated for packets seen AFTER the trigger (ecn_config == 1).
     * There is no divider in the Tofino data plane, so the switch keeps the
     * numerator (bytes) and the denominator (elapsed ns); the control plane
     * does the division:
     *     Gbps = (byte_count * 8) / elapsed_ns
     * =====================================================================*/

    /* Running byte total per QP, fed from the IPv4 header length */
    Register<bit<32>, bit<32>>(MAX_QPS) byte_cnt_reg;
    RegisterAction<bit<32>, bit<32>, bit<32>>(byte_cnt_reg) add_bytes = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = register_data + meta.pkt_len;
            result        = register_data;
        }
    };

    /* Running packet total per QP */
    Register<bit<32>, bit<32>>(MAX_QPS) pkt_cnt_reg;
    RegisterAction<bit<32>, bit<32>, bit<32>>(pkt_cnt_reg) add_pkt = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = register_data + 1;
            result        = register_data;
        }
    };

    /* Timestamp of the FIRST post-trigger packet of the QP (latched once).
     * Control plane must zero this array before arming the trigger. */
    Register<bit<32>, bit<32>>(MAX_QPS) first_ts_reg;
    RegisterAction<bit<32>, bit<32>, bit<32>>(first_ts_reg) latch_first_ts = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data == 0) {
                register_data = meta.cur_ts;
            }
            result = register_data;
        }
    };

    /* ---------------------------------------------------------------------
     * How long the capture runs. Same shape as the ECN marking duration:
     * the length lives in action data, so the control plane sets it at
     * runtime without recompiling —
     *     capture_cfg.set_default_with_set_capture_duration(
     *                     capture_ns=1024000000)     # 250000 x 4096 ns
     * A keyless table always runs its default action, so this costs an
     * action-data lookup, not a stateful ALU.
     * ------------------------------------------------------------------- */
    action set_capture_duration(bit<32> capture_ns) {
        meta.capture_dur = capture_ns;
    }
    table capture_cfg {
        actions        = { set_capture_duration; }
        default_action = set_capture_duration(DEFAULT_CAPTURE_NS);
        size           = 1;
    }

    /* ---------------------------------------------------------------------
     * Capture start: the timestamp of the FIRST packet seen after the
     * trigger is armed, latched once at index 0. Every bin number in the
     * time series is measured from this instant, so all QPs and both
     * directions share one time origin. Control plane must clear this
     * register before arming the trigger.
     * ------------------------------------------------------------------- */
    Register<bit<32>, bit<32>>(1) capture_start_reg;
    RegisterAction<bit<32>, bit<32>, bit<32>>(capture_start_reg) latch_capture_start = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data == 0) {
                register_data = meta.cur_ts;
            }
            result = register_data;
        }
    };

    /* ---------------------------------------------------------------------
     * The time series: bytes accumulated per interval, sharded across four
     * arrays because 262144 x 32b cannot live in a single MAU stage.
     * Logical bin B lives at  shard[B >> 16] , index B & 0xFFFF.
     *
     * For an EXACT 5.000 us (or any non-power-of-two) bin, replace the
     * "elapsed >> BIN_SHIFT" index with a bin counter driven by the Tofino
     * packet generator: a timer app firing every 5000 ns whose packets do
     * bin_ctr_reg[0] += 1, with data packets reading that counter as their
     * bin index. Costs one pktgen app + one recirc port, but the bin edges
     * are then exact and drift-free — and the same pktgen packet can carry
     * the finished bin off-box, removing the array size limit entirely.
     * ------------------------------------------------------------------- */
#if TPUT_PROFILE >= 1
    Register<bit<32>, bit<32>>(SHARD_BINS) tput_bin_s0;
    RegisterAction<bit<32>, bit<32>, bit<32>>(tput_bin_s0) add_bin_s0 = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = register_data + meta.pkt_len;
            result        = register_data;
        }
    };
#endif
#if TPUT_PROFILE >= 2
    Register<bit<32>, bit<32>>(SHARD_BINS) tput_bin_s1;
    RegisterAction<bit<32>, bit<32>, bit<32>>(tput_bin_s1) add_bin_s1 = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = register_data + meta.pkt_len;
            result        = register_data;
        }
    };
#endif
#if TPUT_PROFILE >= 4
    Register<bit<32>, bit<32>>(SHARD_BINS) tput_bin_s2;
    RegisterAction<bit<32>, bit<32>, bit<32>>(tput_bin_s2) add_bin_s2 = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = register_data + meta.pkt_len;
            result        = register_data;
        }
    };
    Register<bit<32>, bit<32>>(SHARD_BINS) tput_bin_s3;
    RegisterAction<bit<32>, bit<32>, bit<32>>(tput_bin_s3) add_bin_s3 = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = register_data + meta.pkt_len;
            result        = register_data;
        }
    };
#endif

    /* Timestamp of the LAST (most recent) post-trigger packet of the QP */
    Register<bit<32>, bit<32>>(MAX_QPS) last_ts_reg;
    RegisterAction<bit<32>, bit<32>, bit<32>>(last_ts_reg) store_last_ts = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            result        = register_data;   /* previous packet's ts */
            register_data = meta.cur_ts;
        }
    };

    /* =====================================================================
     * L O G I C A L   Q U E U E   S T A T E
     * ---------------------------------------------------------------------
     * Four register arrays (plus three optional telemetry ones), all indexed
     * by lq_id. See the header comment for the model; the apply block below
     * wires them together. The four are a dependent chain -- tick feeds the
     * drain lookup, which feeds Q, which feeds qprev and p_bias -- so they
     * cannot share a stage with each other.
     * =====================================================================*/
#if LQ_ENABLE == 1

    /* --- the queue itself -------------------------------------------- *
     * One access per packet, so fill and drain are combined before the
     * register: the MAU computes the net delta and dispatches to whichever
     * of the three actions applies. */
    Register<bit<32>, bit<32>>(LQ_NUM, 0) reg_lq_q;

    /* net positive: this packet's bytes exceeded the drain owed */
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_lq_q) lq_q_add = {
        void apply(inout bit<32> q, out bit<32> rv) {
            bit<32> nq = q + meta.lq_up;
            if (nq > LQ_Q_CAP) {
                nq = LQ_Q_CAP;
            }
            q  = nq;
            rv = nq;
        }
    };

    /* net negative: the drain owed exceeded this packet's bytes */
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_lq_q) lq_q_sub = {
        void apply(inout bit<32> q, out bit<32> rv) {
            bit<32> nq = q - meta.lq_dn;
            if (q < meta.lq_dn) {
                nq = 0;
            }
            q  = nq;
            rv = nq;
        }
    };

    /* the gap exceeded LQ_MAX_K ticks: any real queue would have emptied,
     * so restart from this packet's bytes */
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_lq_q) lq_q_flush = {
        void apply(inout bit<32> q, out bit<32> rv) {
            q  = meta.lq_bytes;
            rv = meta.lq_bytes;
        }
    };

    /* --- the drain clock ---------------------------------------------- *
     * Holds the tick index of the last packet on this queue. Returning the
     * old value and storing the new one in a single access is what makes the
     * drain self-clocked: no packet generator, no recirculation port. */
    Register<bit<32>, bit<32>>(LQ_NUM, 0) reg_lq_tick;
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_lq_tick) lq_tick_swap = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v;
            v  = meta.lq_tick;
        }
    };

    /* --- Q one tick ago: the derivative term, i.e. is the RNIC reacting - */
    Register<bit<32>, bit<32>>(LQ_NUM, 0) reg_lq_qprev;
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_lq_qprev) lq_qprev_swap = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v;
            v  = meta.lq_q;
        }
    };

    /* --- adaptive marking bias, two-sided around LQ_BIAS_ZERO ---------- *
     * The register must be initialised to LQ_BIAS_ZERO by the control plane
     * before the trigger is armed. */
    /* Initial value is the NEUTRAL point, not zero: zero is the fully
     * suppressed rail, which would mute injection until the integrator
     * climbed all the way out of it. The control plane restores this value
     * on reset as well. */
    Register<bit<32>, bit<32>>(LQ_NUM, LQ_BIAS_ZERO) reg_lq_pbias;

    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_lq_pbias) lq_p_inc = {
        void apply(inout bit<32> p, out bit<32> rv) {
            bit<32> np = p + meta.lq_padj;
            if (np > LQ_BIAS_HI) {           /* anti-windup, upper rail */
                np = LQ_BIAS_HI;
            }
            p  = np;
            rv = np;
        }
    };

    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_lq_pbias) lq_p_dec = {
        void apply(inout bit<32> p, out bit<32> rv) {
            bit<32> np = p - meta.lq_padj;
            if (p < meta.lq_padj + LQ_BIAS_LO) {   /* anti-windup, lower rail */
                np = LQ_BIAS_LO;
            }
            p  = np;
            rv = np;
        }
    };

    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_lq_pbias) lq_p_read = {
        void apply(inout bit<32> p, out bit<32> rv) {
            rv = p;
        }
    };

#if LQ_TELEMETRY == 1
    /* CE marks injected by the logical queue, per modelled bottleneck */
    Register<bit<32>, bit<32>>(LQ_NUM, 0) reg_lq_marked;
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_lq_marked) lq_add_marked = {
        void apply(inout bit<32> c, out bit<32> rv) { c = c + 1; rv = c; }
    };

    /* Peak Q -- evidence the logical queue actually built up */
    Register<bit<32>, bit<32>>(LQ_NUM, 0) reg_lq_qmax;
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_lq_qmax) lq_track_max = {
        void apply(inout bit<32> m, out bit<32> rv) {
            if (m < meta.lq_q) {
                m = meta.lq_q;
            }
            rv = m;
        }
    };

    /* How often the tick gap exceeded LQ_MAX_K. Under the intended continuous
     * workload this should stay at zero; a rising count means the sender has
     * slowed past what the drain table compensates, so raise LQ_TICK_SHIFT or
     * extend the table. */
    Register<bit<32>, bit<32>>(LQ_NUM, 0) reg_lq_flushes;
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_lq_flushes) lq_add_flush = {
        void apply(inout bit<32> c, out bit<32> rv) { c = c + 1; rv = c; }
    };
#endif

    Random<bit<16>>() lq_rng;

    /* --- which logical queue does this packet feed? -------------------- *
     * Keyed on ingress port, so each direction of the bump-in-the-wire gets
     * its own modelled bottleneck: the queue on the ingress side models the
     * egress link the packet is about to leave by. Add hdr.bth.dst_qp to the
     * key for per-QP queues. */
    action lq_set(bit<8> lq_id) {
        meta.lq_id    = lq_id;
        meta.lq_valid = 1;
    }
    action lq_none() {
        meta.lq_id    = 0;
        meta.lq_valid = 0;
    }
    table lq_select {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = { lq_set; lq_none; }
        size = 64;
        default_action = lq_none();
    }

    /* --- per-queue model parameters ------------------------------------
     * q_target : setpoint Q* the controller defends
     * adapt_en : run the closed loop, or leave p_bias pinned and use the
     *            static RED curve alone
     * The drain amounts live in lq_drain_tbl, not here, because they depend
     * on how many ticks elapsed. */
    action lq_set_params(bit<32> q_target, bit<1> adapt_en) {
        meta.lq_qtarget = q_target;
        meta.lq_adapt   = adapt_en;
    }
    table lq_params {
        key = { meta.lq_id : exact; }
        actions = { lq_set_params; NoAction; }
        size = 16;
        default_action = NoAction();
    }

    /* --- the drain, as a lookup instead of a multiply -------------------
     * Key is (lq_id, dticks clamped to 0..LQ_MAX_K+1). The control plane
     * installs the precomputed products:
     *      dticks 0            -> no entry, drain 0 (same tick, fill only)
     *      dticks k in 1..32   -> lq_set_drain(k * C * T)
     *      dticks 33 (clamped) -> lq_do_flush()
     * Exact match on a 6-bit key, so no TCAM and no arithmetic. */
    action lq_set_drain(bit<32> amount) {
        meta.lq_drain = amount;
    }
    action lq_do_flush() {
        meta.lq_flush = 1;
    }
    table lq_drain_tbl {
        key = {
            meta.lq_id  : exact;
            meta.lq_dtk : exact;
        }
        actions = { lq_set_drain; lq_do_flush; NoAction; }
        size = 512;                       /* (LQ_MAX_K + 2) per queue */
        default_action = NoAction();
    }

    /* --- static RED curve: Q -> base marking probability ----------------
     * Installed as a staircase over Q >> LQ_Q_KEY_SHIFT:
     *      Q  <  K_min          no entry -> 0
     *      K_min <= Q < K_max   linear ramp 0 .. max_p
     *      Q  >= K_max          LQ_P_MAX
     * A table rather than arithmetic, so the (Q-K_min)*max_p/(K_max-K_min)
     * multiply-and-divide never appears, and any curve shape can be loaded
     * at runtime. The control plane shifts the whole curve up by C*T/2 so the
     * MEAN of the drain sawtooth crosses K_min rather than its peak. */
    action lq_set_red(bit<16> prob) {
        meta.lq_red = prob;
    }
    table lq_red_curve {
        key = {
            meta.lq_id  : exact;
            meta.lq_qkey : range;
        }
        actions = { lq_set_red; NoAction; }
        size = 1024;
        default_action = NoAction();
    }

    /* --- apply the signal ----------------------------------------------
     * Marks only when the window is armed, the coin came up, and the packet
     * is ECT-capable. Promoting Not-ECT to CE violates RFC 3168 and RNICs
     * ignore it anyway.
     *
     * To emit a different signal from the same Q, swap the action here:
     *   delay  -> hold for Q/C (needs a recirculation loop or egress hold)
     *   INT    -> push (qLen = meta.lq_q, txRate) into a telemetry header
     *   trim   -> truncate the payload, forward the header
     * Everything above this table is signal-agnostic. */
    action lq_mark_ce() {
        hdr.ipv4.ecn = ECN_CE;
    }
    table lq_apply_signal {
        key = {
            meta.lq_arm  : exact;
            meta.lq_mark : exact;
            meta.lq_ect  : exact;
        }
        actions = { lq_mark_ce; NoAction; }
        const entries = {
            (1w1, 1w1, 1w1) : lq_mark_ce();
        }
        size = 8;
        const default_action = NoAction();
    }
#endif

    apply {
        meta.qpn = (bit<32>)hdr.bth.dst_qp;
        write_qpn.execute(0);
        bit<32> end_time = 0;
        bit<32> reg_index = 0; // Using index 0 for global config

        /* QP index for every per-QP register array. dst_qp is 24 bits but the
         * arrays hold MAX_QPS(=2048) slots, so it MUST be masked down to 11
         * bits — an unmasked index silently aliases/goes out of range. */
        bit<32> qp_idx = (bit<32>)hdr.bth.dst_qp[10:0];   // 11 bits = 2048 slots

        // Only considering the first 32 bits of timestamps out of 48!!!
        // (32b of ns wraps every ~4.295 s — see notes on measurement windows)
        meta.cur_ts = ig_prsr_md.global_tstamp[31:0];

        /* Packet size taken straight from the packet header */
        if (hdr.ipv4.isValid()) {
            meta.pkt_len = (bit<32>)hdr.ipv4.total_len + L2_WIRE_OVERHEAD;
        }

        // Read ECN configuration from register
        meta.ecn_config = read_ecn_config.execute(reg_index);

        if (meta.ecn_config == 1) {
            // Store end time of first pkt after setting ecn flag

            qp_duration_tbl.apply();
            capture_cfg.apply();    /* how long should the capture run?     */

            //bit<32> end_time_2 = cur_tstamp + duration;
            bit<32> end_time_2 = meta.cur_ts + meta.qp_duration;
            meta.end_time_2 = end_time_2;

            // end_time = read_end_time_reg_2.execute(0);
            end_time = read_write_end_time_per_qp.execute(qp_idx);

            // Take difference between current and end ts to mark ecn
            meta.ts_diff = end_time - meta.cur_ts;
            duration_range.apply();

            /**** POST-TRIGGER THROUGHPUT / TIMESTAMP ACCOUNTING ****
             * Only RoCE packets (BTH valid) carry a QP, so gate on it.     */
            if (hdr.bth.isValid()) {
                meta.byte_count = add_bytes.execute(qp_idx);       // bytes
                meta.pkt_count  = add_pkt.execute(qp_idx);         // packets
                meta.first_ts   = latch_first_ts.execute(qp_idx);  // window start
                store_last_ts.execute(qp_idx);                     // window end
                /* Unsigned subtraction is wrap-safe as long as the window is
                 * shorter than 2^32 ns (~4.295 s). */
                meta.elapsed    = meta.cur_ts - meta.first_ts;

            }

            /**** CONTINUOUS TIME-BINNED THROUGHPUT (all traffic) ****
             * Counts every IPv4 packet arriving at this pipeline while the
             * trigger is armed — not just RoCE — so the series is the total
             * offered load at the switch.
             *
             * Bin numbering is progressive from the instant of capture start:
             *     bin 0      = [0, 4096) ns
             *     bin 1      = [4096, 8192) ns
             *     bin i      = [i*4096, (i+1)*4096) ns
             * and the control plane reads s0,s1,s2,s3 back to back to get one
             * flat array 0 .. 262143.
             *
             * TWO guards, both must hold:
             *  1. cap_left[31] == 0 — the configured duration has not run out.
             *     cap_left = capture_dur - g_elapsed counts DOWN, exactly like
             *     ts_diff in the ECN logic; when it goes negative it wraps and
             *     the sign bit flips, which is the cheapest possible test.
             *  2. g_elapsed[31:30] == 0 — structural backstop so a mis-set
             *     duration can never push an index past the array end.
             *
             * >>> The slices below are tied to BIN_SHIFT and SHARDS.
             *     SHARDS=4, BIN_SHIFT=12: guard [31:30], shard [29:28],
             *                             off [27:12]
             *     SHARDS=2, BIN_SHIFT=12: guard [31:29], shard [28:28],
             *                             off [27:12]  (drop s2/s3 below)
             *     SHARDS=1, BIN_SHIFT=14: guard [31:30], no shard,
             *                             off [29:14]  (keep s0 only)   <<< */
            meta.g_start   = latch_capture_start.execute(0);
            meta.g_elapsed = meta.cur_ts - meta.g_start;
            meta.cap_left  = meta.capture_dur - meta.g_elapsed;

#if TPUT_PROFILE == 4
            /* 4 shards, 4.096 us bins: guard [31:30], shard [29:28], off [27:12] */
            if (hdr.ipv4.isValid() && meta.cap_left[31:31] == 0) {
                if (meta.g_elapsed[31:30] == 0) {
                    bit<32> off = (bit<32>)meta.g_elapsed[27:12];
                    if (meta.g_elapsed[29:28] == 0) {
                        add_bin_s0.execute(off);
                    } else if (meta.g_elapsed[29:28] == 1) {
                        add_bin_s1.execute(off);
                    } else if (meta.g_elapsed[29:28] == 2) {
                        add_bin_s2.execute(off);
                    } else {
                        add_bin_s3.execute(off);
                    }
                }
            }
#elif TPUT_PROFILE == 2
            /* 2 shards, 4.096 us bins: guard [31:29], shard [28:28], off [27:12] */
            if (hdr.ipv4.isValid() && meta.cap_left[31:31] == 0) {
                if (meta.g_elapsed[31:29] == 0) {
                    bit<32> off = (bit<32>)meta.g_elapsed[27:12];
                    if (meta.g_elapsed[28:28] == 0) {
                        add_bin_s0.execute(off);
                    } else {
                        add_bin_s1.execute(off);
                    }
                }
            }
#elif TPUT_PROFILE == 1
            /* 1 shard, 16.384 us bins: guard [31:30], off [29:14] */
            if (hdr.ipv4.isValid() && meta.cap_left[31:31] == 0) {
                if (meta.g_elapsed[31:30] == 0) {
                    bit<32> off = (bit<32>)meta.g_elapsed[29:14];
                    add_bin_s0.execute(off);
                }
            }
#endif

            /* =============================================================
             * L O G I C A L   Q U E U E   +   A D A P T I V E   E C N
             * -------------------------------------------------------------
             * Runs inside the trigger window, so Q starts from zero at the
             * instant the experiment is armed and every run has the same
             * clean initial condition.
             * ===========================================================*/
#if LQ_ENABLE == 1
            lq_select.apply();

            if (meta.lq_valid == 1 && hdr.ipv4.isValid()) {
                meta.lq_idx = (bit<32>)meta.lq_id;

                /* The n*A(t) term. meta.pkt_len already carries the L2 wire
                 * overhead, so this is true wire cost against the modelled
                 * capacity, pre-scaled by the 2^k part of n. */
                meta.lq_bytes = meta.pkt_len << LQ_N_SHIFT;

                lq_params.apply();          /* Q* and the adaptive enable */

                /* ---- how much time has passed on this queue? ----------
                 * cur_ts is the low 32 bits of the global timestamp, so the
                 * tick index wraps every ~4.295 s. At the wrap dticks goes
                 * hugely negative-then-positive and maps to the flush entry,
                 * costing one reset of Q about every 4.3 seconds. That shows
                 * up in reg_lq_flushes; a count matching the run length in
                 * seconds is this wrap and is expected, a much larger count
                 * means the sender has slowed past the drain table's reach. */
                meta.lq_tick   = (bit<32>)meta.cur_ts[31:LQ_TICK_SHIFT];
                meta.lq_dticks = meta.lq_tick - lq_tick_swap.execute(meta.lq_idx);

                /* Clamp to the drain table's reach. Anything past LQ_MAX_K
                 * means the link was idle long enough that a real queue would
                 * have emptied, and maps to the flush entry. */
                if (meta.lq_dticks > LQ_MAX_K) {
                    meta.lq_dtk = (bit<6>)(LQ_MAX_K + 1);
                } else {
                    meta.lq_dtk = (bit<6>)meta.lq_dticks;
                }

                /* dticks * C * T, read out of action data. No multiplier. */
                lq_drain_tbl.apply();

                /* ---- Q += n*bytes - drain, in one register access ------ */
                if (meta.lq_flush == 1) {
                    meta.lq_q = lq_q_flush.execute(meta.lq_idx);
                } else if (meta.lq_bytes >= meta.lq_drain) {
                    meta.lq_up = meta.lq_bytes - meta.lq_drain;
                    meta.lq_q  = lq_q_add.execute(meta.lq_idx);
                } else {
                    meta.lq_dn = meta.lq_drain - meta.lq_bytes;
                    meta.lq_q  = lq_q_sub.execute(meta.lq_idx);
                }

                /* ---- adaptive controller, once per tick boundary -------
                 *   err  = Q - Q*        proportional
                 *   derr = Q - Q_prev    derivative: is the RNIC reacting?
                 * Split into unsigned up/down halves so each stateful ALU
                 * stays within one compare plus one add/subtract.
                 *
                 * Whichever path runs, it produces this packet's p_bias --
                 * a register may only be accessed once per packet, so the
                 * update actions return the new value rather than the
                 * pipeline reading it back. */
                if (meta.lq_dticks != 0 && meta.lq_adapt == 1) {
                    meta.lq_qprev = lq_qprev_swap.execute(meta.lq_idx);

                    if (meta.lq_q >= meta.lq_qtarget) {
                        meta.lq_err_up = (meta.lq_q - meta.lq_qtarget)
                                         >> LQ_ALPHA_SHIFT;
                    } else {
                        meta.lq_err_dn = (meta.lq_qtarget - meta.lq_q)
                                         >> LQ_ALPHA_SHIFT;
                    }
                    if (meta.lq_q >= meta.lq_qprev) {
                        meta.lq_err_up = meta.lq_err_up
                                       + ((meta.lq_q - meta.lq_qprev)
                                          >> LQ_BETA_SHIFT);
                    } else {
                        meta.lq_err_dn = meta.lq_err_dn
                                       + ((meta.lq_qprev - meta.lq_q)
                                          >> LQ_BETA_SHIFT);
                    }

                    if (meta.lq_err_up >= meta.lq_err_dn) {
                        meta.lq_padj  = meta.lq_err_up - meta.lq_err_dn;
                        meta.lq_pbias = lq_p_inc.execute(meta.lq_idx);
                    } else {
                        meta.lq_padj  = meta.lq_err_dn - meta.lq_err_up;
                        meta.lq_pbias = lq_p_dec.execute(meta.lq_idx);
                    }
                } else {
                    meta.lq_pbias = lq_p_read.execute(meta.lq_idx);
                }

                /* ---- derive the signal -------------------------------- *
                 * p_total = clamp(red(Q) + p_bias - LQ_BIAS_ZERO, 0, P_MAX) */
                meta.lq_qkey = (bit<16>)(meta.lq_q >> LQ_Q_KEY_SHIFT);
                lq_red_curve.apply();

                bit<32> psum = (bit<32>)meta.lq_red + meta.lq_pbias;
                if (psum <= LQ_BIAS_ZERO) {
                    meta.lq_ptotal = 0;
                } else if (psum >= LQ_BIAS_ZERO + LQ_P_MAX) {
                    meta.lq_ptotal = (bit<16>)LQ_P_MAX;
                } else {
                    meta.lq_ptotal = (bit<16>)(psum - LQ_BIAS_ZERO);
                }

                meta.lq_rand = lq_rng.get();
                if (meta.lq_rand < meta.lq_ptotal) {
                    meta.lq_mark = 1;
                }
                if (hdr.ipv4.ecn == ECN_ECT0 || hdr.ipv4.ecn == ECN_ECT1) {
                    meta.lq_ect = 1;
                }

                lq_apply_signal.apply();

#if LQ_TELEMETRY == 1
                lq_track_max.execute(meta.lq_idx);
                if (meta.lq_flush == 1) {
                    lq_add_flush.execute(meta.lq_idx);
                } else if (meta.lq_arm == 1 && meta.lq_mark == 1
                           && meta.lq_ect == 1) {
                    lq_add_marked.execute(meta.lq_idx);
                }
#endif
            }
#endif
        }

        // Forward packet based on ingress port
        if (ig_intr_md.ingress_port == 0xB4)
           ig_tm_md.ucast_egress_port = 0xBC;
        else if (ig_intr_md.ingress_port == 0xBC)
           ig_tm_md.ucast_egress_port = 0xB4;

        /* MIrroring */
        pkt_mirror.apply();
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Checksum() ipv4_checksum;
    Mirror()   ing_port_mirror;

    apply {
    
        /* 
         * If there is a mirror request, create a clone. 
         * Note: Mirror() externs emits the provided header, but also
         * appends the ORIGINAL ingress packet after those
         */
        if (ig_dprsr_md.mirror_type == ING_PORT_MIRROR) {
            ing_port_mirror.emit<ing_port_mirror_h>(
                meta.mirror_session,
                {
                    meta.mirror_header_type, meta.mirror_header_info,
                    0, meta.ingress_port,
                    0, meta.mirror_session
                    });
        }
   
        // Recalculate checksum as ecn field might have changed
        hdr.ipv4.hdr_checksum = ipv4_checksum.update(
                {hdr.ipv4.version,
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
                 hdr.ipv4.dst_addr});
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

// Headerts to parse at the Egress pipeline
struct my_egress_headers_t {
    bridge_h     bridge;
    ethernet_h   ethernet;
    vlan_tag_h   vlan_tag;
    ipv4_h       ipv4;
    timestamp_h  timestamp;
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/
// Egress metadata to use accross egress pipeline
struct my_egress_metadata_t {
    inthdr_h           inthdr;
    bridge_h           bridge;
    MirrorId_t         mirror_session;
    bool               ing_mirrored;
    bool               egr_mirrored;
    ing_port_mirror_h  ing_port_mirror;
    egr_port_mirror_h  egr_port_mirror;
    header_type_t      mirror_header_type;
    header_info_t      mirror_header_info;
    MirrorId_t         egr_mirror_session;
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    /* Extract intrinsic metadata and then inspect the next header
     * to determine if this is a bridge-metadata packet or a
     * mirrored-ingress/egress packet. */
    state start {
        meta.mirror_session        = 0;
        meta.ing_mirrored          = false;
        meta.egr_mirrored          = false;
        meta.mirror_header_type    = 0;
        meta.mirror_header_info    = 0;
        meta.egr_mirror_session    = 0;
        
        pkt.extract(eg_intr_md);
        meta.inthdr = pkt.lookahead<inthdr_h>();
           
        transition select(meta.inthdr.header_type, meta.inthdr.header_info) {
            ( HEADER_TYPE_BRIDGE,         _ ) :
                           parse_bridge;
            ( HEADER_TYPE_MIRROR_INGRESS, (header_info_t)ING_PORT_MIRROR ):
                           parse_ing_port_mirror;
            ( HEADER_TYPE_MIRROR_EGRESS,  (header_info_t)EGR_PORT_MIRROR ):
                           parse_egr_port_mirror;
            default : reject;
        }
    }

    state parse_bridge {
        pkt.extract(meta.bridge);
        transition accept;
    }

    state parse_ing_port_mirror {
        pkt.extract(meta.ing_port_mirror);
        meta.ing_mirrored   = true;
        meta.mirror_session = meta.ing_port_mirror.mirror_session;
        transition accept;
    }
    
    state parse_egr_port_mirror {
        pkt.extract(meta.egr_port_mirror);
        meta.egr_mirrored   = true;
        meta.mirror_session = meta.egr_port_mirror.mirror_session;
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    // Insert 48 bits timestamp in front of the packet for analysis
    action send_with_ts() {
        hdr.timestamp.setValid();
        hdr.timestamp.egress_global_timestamp[31:0] = eg_prsr_md.global_tstamp[31:0];
        hdr.timestamp.egress_global_timestamp[47:32] = eg_prsr_md.global_tstamp[47:32];
    }

    /* Table keyed on mirror_session and mirror flag extracted in parser.
     * And calls send_with_ts to append ts and forward */
    table mirrored_pkt {
        key = {
            meta.ing_mirrored       : ternary;
            meta.egr_mirrored       : ternary;
            meta.mirror_session     : exact;
        }

        actions = {
            send_with_ts();
            NoAction();
        }
        default_action = NoAction();
        size = 512;
    }

    // Initialize metadata for egress mirroring
    action egr_mirror(MirrorId_t mirror_session) {
        eg_dprsr_md.mirror_type     = EGR_PORT_MIRROR;
        meta.mirror_header_type     = HEADER_TYPE_MIRROR_EGRESS;
        meta.mirror_header_info     = (header_info_t)EGR_PORT_MIRROR;
        meta.egr_mirror_session     = mirror_session;
    }

    // Table to call mirror action based on key matching of ingress port and mirror session
    table egr_pkt_mirror {
        key = {
            meta.bridge.ingress_port   : exact;
        }
        actions = {
            egr_mirror;
            NoAction;
        }
        size = 512;
        default_action = NoAction();
    }

    apply {
        if (meta.bridge.isValid()) {                        // Condition for normal bridge packet
            egr_pkt_mirror.apply();
        } else if (meta.ing_port_mirror.isValid() ||
                   meta.egr_port_mirror.isValid()) {        // Condition for ingress or egress mirrored packet
           mirrored_pkt.apply();
        }
    }
}


    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md,
    in    egress_intrinsic_metadata_t               eg_intr_md)
{
    Mirror() egr_port_mirror;

    apply {
        // Emit egress mirror header only if  this packet marked EGR_PORT_MIRROR
        if (eg_dprsr_md.mirror_type == EGR_PORT_MIRROR) {
            egr_port_mirror.emit<egr_port_mirror_h>(
                meta.egr_mirror_session,
                {
                    meta.mirror_header_type,
                    meta.mirror_header_info,
                    0, meta.bridge.ingress_port,
                    0, eg_intr_md.egress_port,
                    0, meta.egr_mirror_session
                });
        }
        
        // Emit only the standard L2/L3 headers for outgoing packet
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);

        // EMIT TIMESTAMP HEADER IF IT'S VALID
        pkt.emit(hdr.timestamp);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
