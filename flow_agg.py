from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import time
from feature_extractor import flow_features_extract, get_service
from threading import Lock
from predictor import predict_flow
import traceback
from database import safe_execute

log_lock = Lock()

flows = {}
flow_timeout = 10
connection_log = []

current_user_id = None
sniffing = False


def get_flow_key(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        sport = None
        dport = None
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        if UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        return (src, dst, sport, dport, proto)
    return None


def map_flag(packet):
    if not packet.haslayer(TCP):
        return 'OTH'
    flags = packet[TCP].flags
    syn = flags & 0x02
    ack = flags & 0x10
    rst = flags & 0x04
    fin = flags & 0x01
    if syn and not ack:
        return 'S0'
    if syn and ack:
        return 'S1'
    if rst and not ack:
        return 'REJ'
    if rst and ack:
        return 'RSTR'
    if fin or ack:
        return 'SF'
    return 'OTH'


def process_packet(packet):
    try:
        key = get_flow_key(packet)
        if key is None:
            return

        src, dst, sport, dport, proto = key
        reverse_key = (dst, src, dport, sport, proto)

        now = time.time()
        size = len(packet)

        if key in flows:
            flow_key = key
        elif reverse_key in flows:
            flow_key = reverse_key
        else:
            service = get_service(dport)
            if ICMP in packet:
                # Map ICMP types to KDD services
                icmp_type = packet[ICMP].type
                if icmp_type == 8: service = "eco_i"
                elif icmp_type == 0: service = "ecr_i"
                else: service = "icmp"

            flows[key] = {
                "start_time": now,
                "end_time": now,
                "packet_count": 1,
                "src_bytes": size,
                "dst_bytes": 0,
                "flag": map_flag(packet),
                "service": service
            }
            return

        flows[flow_key]["packet_count"] += 1
        flows[flow_key]["end_time"] = now
        flows[flow_key]["flag"] = map_flag(packet)

        if flow_key == key:
            flows[flow_key]["src_bytes"] += size
        else:
            flows[flow_key]["dst_bytes"] += size

        with log_lock:
            connection_log.append({
                "timestamp": now,
                "src": src,
                "dst": dst,
                "service": get_service(dport),
                "flag": map_flag(packet)
            })

    except Exception as e:
        print("Packet Processing error:", e)
        traceback.print_exc()


def cleanup_flows(force=False):
    now = time.time()

    for key in list(flows.keys()):
        flow = flows[key]

        if not force:
            with log_lock:
                connection_log.append({
                    "timestamp": flow["end_time"],
                    "src": key[0],
                    "dst": key[1],
                    "service": flow.get("service", "other"),
                    "flag": flow.get("flag", "OTH")
                })
                # Trim connection log
                while len(connection_log) > 5000:
                    connection_log.pop(0)

        if force or (now - flow["end_time"] > flow_timeout):
            with log_lock:
                features = flow_features_extract(key, flow, connection_log, now)

            # FIX: safe_execute now returns lastrowid directly
            flow_id = safe_execute(
                """INSERT INTO network_flows
                   (user_id, src_ip, dst_ip, src_port, dst_port, protocol_type,
                    service, flag, duration, src_bytes, dst_bytes, packet_count,
                    count, src_count, srv_count, same_srv_rate, diff_srv_rate,
                    src_diff_srv_rate, dst_host_count, dst_host_srv_count,
                    dst_host_diff_srv_rate, dst_host_same_srv_rate,
                    serror_rate, srv_serror_rate, dst_host_serror_rate)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (current_user_id, key[0], key[1], key[2], key[3],
                 features["protocol_type"],
                 features["service"],
                 features["flag"],
                 features["duration"],
                 features["src_bytes"],
                 features["dst_bytes"],
                 flow["packet_count"],
                 features["count"],
                 features["src_count"],
                 features["srv_count"],
                 features["same_srv_rate"],
                 features["diff_srv_rate"],
                 features["src_diff_srv_rate"],
                 features["dst_host_count"],
                 features["dst_host_srv_count"],
                 features["dst_host_diff_srv_rate"],
                 features["dst_host_same_srv_rate"],
                 features["serror_rate"],
                 features["srv_serror_rate"],
                 features["dst_host_serror_rate"])
            )

            if flow_id:
                predict_flow(features, flow, flow_id, current_user_id)

            del flows[key]


def packet_handler(packet):
    process_packet(packet)
    cleanup_flows()


def start_sniffing(user_id):
    global sniffing, current_user_id
    sniffing = True
    current_user_id = user_id
    print(f"[*] Sniffing started for user_id={user_id}")
    sniff(
        prn=packet_handler,
        store=False,
        stop_filter=lambda x: not sniffing,
        filter="ip and not multicast"
    )
    print("[*] Sniffing stopped.")


def stop_sniffing():
    global sniffing
    sniffing = False
    # Flush remaining flows so they aren't lost
    cleanup_flows(force=True)
