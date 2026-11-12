#!/usr/bin/env python3
"""pcap_decode.py – разбор захвата трафика С2000-Ethernet (tcpdump/Wireshark, классический .pcap).

    tcpdump -i any host 192.168.1.50 -s 0 -w /tmp/capture.pcap
    python pcap_decode.py capture.pcap                 # все потоки
    python pcap_decode.py capture.pcap --to 192.168.1.10 --from 192.168.1.50

Понимает Ethernet (DLT 1), Linux cooked SLL (113) и SLL2 (276, это `-i any` в новых tcpdump).
`-i any` дублирует каждый кадр на нескольких интерфейсах – дубликаты (одинаковые адреса и данные
в пределах 50 мс) сворачиваются. Для каждого кадра печатается время, интервал от предыдущего и
расшифровка (запрос/ответ, адрес, значение, названия состояний).
"""
import argparse
import struct
import sys

import c2000pp as C
from bench_c2000pp import describe


def read_pcap(path):
    d = open(path, "rb").read()
    if d[:4] == b"\xd4\xc3\xb2\xa1":
        e = "<"
    elif d[:4] == b"\xa1\xb2\xc3\xd4":
        e = ">"
    else:
        raise SystemExit("нужен классический pcap (не pcapng): сохраните как 'pcap' или tcpdump -w")
    link = struct.unpack(e + "I", d[20:24])[0]
    i, out = 24, []
    while i + 16 <= len(d):
        s, us, cl, _ = struct.unpack(e + "IIII", d[i:i + 16])
        i += 16
        out.append((s + us / 1e6, d[i:i + cl]))
        i += cl
    return link, out


def udp_of(link, pk):
    if link == 1:
        proto, ip = struct.unpack(">H", pk[12:14])[0], pk[14:]
    elif link == 113:
        proto, ip = struct.unpack(">H", pk[14:16])[0], pk[16:]
    elif link == 276:
        proto, ip = struct.unpack(">H", pk[:2])[0], pk[20:]
    else:
        raise SystemExit(f"неизвестный тип канала {link}")
    if proto != 0x0800 or (ip[0] >> 4) != 4 or ip[9] != 17:
        return None
    ihl = (ip[0] & 15) * 4
    sp, dp, ul = struct.unpack(">HHH", ip[ihl:ihl + 6])
    return dict(src=".".join(map(str, ip[12:16])), dst=".".join(map(str, ip[16:20])),
                sp=sp, dp=dp, data=bytes(ip[ihl + 8:ihl + ul]))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--from", dest="src", default="")
    ap.add_argument("--to", dest="dst", default="")
    ap.add_argument("--port", type=int, default=40002)
    a = ap.parse_args()
    link, recs = read_pcap(a.pcap)
    seen, rows = {}, []
    for t, pk in recs:
        u = udp_of(link, pk)
        if not u or a.port not in (u["sp"], u["dp"]):
            continue
        if (a.src and u["src"] != a.src) or (a.dst and u["dst"] != a.dst):
            continue
        k = (u["src"], u["dst"], u["data"])
        if k in seen and t - seen[k] < 0.05:
            continue
        seen[k] = t
        rows.append((t, u))
    if not rows:
        print("нет UDP-кадров с этим портом/фильтром")
        return
    t0 = rows[0][0]
    flows = sorted({(u["src"], u["dst"]) for _, u in rows})
    print("потоки:", ", ".join(f"{s}->{d}" for s, d in flows))
    prev = {}
    for t, u in rows:
        f = (u["src"], u["dst"])
        dt = t - prev[f] if f in prev else 0.0
        prev[f] = t
        print(f"{t - t0:8.3f} +{dt:6.3f}  {u['src']}->{u['dst']}  {describe(u['data'])}")


if __name__ == "__main__":
    main()
