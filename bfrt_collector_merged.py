import time
import csv

# Name of the compiled P4 program as it appears under `bfrt.` in the BFRT shell.
# Changed from "ts_ecn_tracker" to the merged program. Edit if you compile under another name.
PROGRAM = "logical_queue_inswitch"

prog = getattr(bfrt, PROGRAM)
ingress = prog.pipe.Ingress
egress = prog.pipe.Egress

output_file = "/home/tofinoswitch/AI-NIC/tofino_metadata.csv"

def read_register(reg, name):
    entry = reg.get(0, from_hw=True, print_ents=False)
    return entry.data[name]

start = time.time()
duration = 30
previous_timestamp = None

with open(output_file, "w", newline="") as f:

    writer = csv.writer(f)

    writer.writerow([
        "collection_time",
        "ingress_port",
        "ingress_timestamp",
        "packet_color",
        "egress_port",
        "egress_qid",
        "packet_length",
        "enq_qdepth",
        "deq_qdepth",
        "enq_timestamp",
        "enq_congest_stat",
        "deq_congest_stat",
        "app_pool_congest_stat",
        "egress_timestamp"
    ])

    print("Collecting metadata for 30 seconds...")

    while time.time() - start < duration:

        # Read ingress timestamp first
        ts_entry = ingress.ingress_timestamp_reg.get(
            0, from_hw=True, print_ents=False
        )

        timestamps = ts_entry.data[
            b'Ingress.ingress_timestamp_reg.f1'
        ]

        current_timestamp = timestamps[1]

        # Only write when the timestamp changes
        if current_timestamp != previous_timestamp:

            ingress_port = read_register(
                ingress.ingress_port_reg,
                b'Ingress.ingress_port_reg.f1'
            )

            packet_color = read_register(
                ingress.packet_color_reg,
                b'Ingress.packet_color_reg.f1'
            )

            egress_port = read_register(
                egress.egress_port_reg,
                b'Egress.egress_port_reg.f1'
            )

            egress_qid = read_register(
                egress.egress_qid_reg,
                b'Egress.egress_qid_reg.f1'
            )

            packet_length = read_register(
                egress.packet_length_reg,
                b'Egress.packet_length_reg.f1'
            )

            enq_qdepth = read_register(
                egress.enq_qdepth_reg,
                b'Egress.enq_qdepth_reg.f1'
            )

            deq_qdepth = read_register(
                egress.deq_qdepth_reg,
                b'Egress.deq_qdepth_reg.f1'
            )

            enq_timestamp = read_register(
                egress.enq_tstamp_reg,
                b'Egress.enq_tstamp_reg.f1'
            )

            enq_congest = read_register(
                egress.enq_congest_stat_reg,
                b'Egress.enq_congest_stat_reg.f1'
            )

            deq_congest = read_register(
                egress.deq_congest_stat_reg,
                b'Egress.deq_congest_stat_reg.f1'
            )

            app_pool_congest = read_register(
                egress.app_pool_congest_stat_reg,
                b'Egress.app_pool_congest_stat_reg.f1'
            )

            egress_timestamp = read_register(
                egress.egress_timestamp_reg,
                b'Egress.egress_timestamp_reg.f1'
            )

            writer.writerow([
                time.time(),
                ingress_port,
                current_timestamp,
                packet_color,
                egress_port,
                egress_qid,
                packet_length,
                enq_qdepth,
                deq_qdepth,
                enq_timestamp,
                enq_congest,
                deq_congest,
                app_pool_congest,
                egress_timestamp
            ])

            f.flush()
            previous_timestamp = current_timestamp

print("Collection finished.")
print("CSV saved to:", output_file)
