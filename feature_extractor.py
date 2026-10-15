import pandas as pd
import joblib


def flow_features_extract(key, flow, connection_log, now):
    src, dst, sport, dport, proto = key
    service = get_service(dport)
    duration = flow["end_time"] - flow["start_time"]

    if proto == 6:
        protocol = 'TCP'
    elif proto == 17:
        protocol = 'UDP'
    elif proto == 1:
        protocol = 'ICMP'
    else:
        protocol = 'OTHER'

    features = {
        "duration": duration,
        "protocol_type": protocol,
        "service": service,
        "flag": flow.get("flag", "OTH"),
        "src_bytes": flow.get("src_bytes", 0),
        "dst_bytes": flow.get("dst_bytes", 0),
        "count": get_count(dst, connection_log, now),
        "src_count": get_src_count(src, connection_log, now),
        "srv_count": get_srv_count(dst, service, connection_log, now),
        "same_srv_rate": get_same_srv_rate(dst, service, connection_log, now),
        "diff_srv_rate": get_diff_srv_rate(dst, service, connection_log, now),
        "src_diff_srv_rate": get_src_diff_srv_rate(src, connection_log, now),
        "dst_host_count": get_dst_host_count(dst, connection_log),
        "dst_host_srv_count": get_dst_host_srv_count(dst, service, connection_log),
        "dst_host_diff_srv_rate": get_dst_host_diff_srv_rate(dst, service, connection_log),
        "dst_host_same_srv_rate": get_dst_host_same_srv_rate(dst, service, connection_log),
        "serror_rate": get_serror_rate(dst, connection_log, now),
        "srv_serror_rate": get_srv_serror_rate(dst, service, connection_log, now),
        "dst_host_serror_rate": get_dst_host_serror_rate(dst, connection_log)
    }

    return features


def get_service(port):
    port_map = {
        20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "domain", 67: "dhcp", 68: "dhcp", 69: "tftp", 70: "gopher",
        79: "finger", 80: "http", 110: "pop3", 111: "sunrpc", 119: "nntp",
        123: "ntp", 137: "netbios_ns", 138: "netbios_dgm", 139: "netbios_ssn",
        143: "imap", 161: "snmp", 179: "bgp", 194: "irc", 443: "https",
        445: "microsoft_ds", 465: "smtps", 500: "isakmp", 514: "syslog",
        515: "printer", 520: "rip", 587: "smtp", 993: "imaps", 995: "pop3s",
        1433: "sql", 1521: "oracle", 2049: "nfs", 2082: "cpanel", 2083: "cpanel",
        2181: "zookeeper", 2222: "ssh", 2483: "oracle", 2484: "oracle",
        3000: "http", 3306: "mysql", 3389: "rdp", 3690: "svn",
        4444: "metasploit", 5432: "postgresql", 5631: "pcanywhere",
        5900: "vnc", 6000: "x11", 6379: "redis", 6667: "irc",
        7001: "weblogic", 7002: "weblogic", 8000: "http", 8008: "http",
        8080: "http", 8081: "http", 8443: "https", 9000: "http",
        9090: "http", 27017: "mongodb"
    }
    return port_map.get(port, "other")


def get_count(dst, connection_log, now):
    return sum(1 for c in connection_log if c["dst"] == dst and now - c["timestamp"] <= 2)


def get_src_count(src, connection_log, now):
    return sum(1 for c in connection_log if c["src"] == src and now - c["timestamp"] <= 2)


def get_srv_count(dst, service, connection_log, now):
    return sum(1 for c in connection_log
               if c["dst"] == dst and c["service"] == service and now - c["timestamp"] <= 2)


def get_same_srv_rate(dst, service, connection_log, now):
    same_host = [c for c in connection_log if c["dst"] == dst and now - c["timestamp"] <= 2]
    if not same_host:
        return 0
    return sum(1 for c in same_host if c["service"] == service) / len(same_host)


def get_diff_srv_rate(dst, service, connection_log, now):
    same_host = [c for c in connection_log if c["dst"] == dst and now - c["timestamp"] <= 2]
    if not same_host:
        return 0
    return sum(1 for c in same_host if c["service"] != service) / len(same_host)


def get_src_diff_srv_rate(src, connection_log, now):
    same_src = [c for c in connection_log if c["src"] == src and now - c["timestamp"] <= 2]
    if not same_src:
        return 0
    unique_services = set(c["service"] for c in same_src)
    return len(unique_services) / len(same_src)


def get_dst_host_count(dst, connection_log):
    return sum(1 for c in connection_log[-100:] if c["dst"] == dst)


def get_dst_host_srv_count(dst, service, connection_log):
    return sum(1 for c in connection_log[-100:]
               if c["dst"] == dst and c["service"] == service)


def get_dst_host_same_srv_rate(dst, service, connection_log):
    last_100 = [c for c in connection_log[-100:] if c["dst"] == dst]
    if not last_100:
        return 0
    return sum(1 for c in last_100 if c["service"] == service) / len(last_100)


def get_dst_host_diff_srv_rate(dst, service, connection_log):
    last_100 = [c for c in connection_log[-100:] if c["dst"] == dst]
    if not last_100:
        return 0
    return sum(1 for c in last_100 if c["service"] != service) / len(last_100)


def get_serror_rate(dst, connection_log, now):
    same_host = [c for c in connection_log if c["dst"] == dst and now - c["timestamp"] <= 2]
    if not same_host:
        return 0
    errors = [c for c in same_host if c["flag"] in ["S0", "REJ", "RSTR"]]
    return len(errors) / len(same_host)


def get_dst_host_serror_rate(dst, connection_log):
    last_100 = [c for c in connection_log[-100:] if c["dst"] == dst]
    if not last_100:
        return 0
    errors = [c for c in last_100 if c["flag"] in ["S0", "REJ", "RSTR"]]
    return len(errors) / len(last_100)


def get_srv_serror_rate(dst, service, connection_log, now):
    same_srv = [c for c in connection_log
                if c["dst"] == dst and c["service"] == service and now - c["timestamp"] <= 2]
    if not same_srv:
        return 0
    errors = [c for c in same_srv if c["flag"] in ["S0", "REJ", "RSTR"]]
    return len(errors) / len(same_srv)


columns_used_in_training = joblib.load("model_columns.pkl")


def prep_for_model(features):
    df = pd.DataFrame([features])
    df = pd.get_dummies(df)
    df = df.reindex(columns=columns_used_in_training, fill_value=0)
    return df
