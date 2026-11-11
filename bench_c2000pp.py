#!/usr/bin/env python3
"""bench_c2000pp.py – замер скоростей обмена с С2000-ПП через С2000-Ethernet.

Ничего не запускает «в фоне»: утилита сама ведёт обмен по фазам, а сокет при этом
непрерывно слушается и КАЖДАЯ датаграмма (свои запросы, ответы, чужие ответы, heartbeat
конвертера) пишется в лог с временем. Лог – главный результат: его можно прислать для разбора.

Фазы (--phases, по умолчанию все, кроме switch – он пишет в ПП и требует --allow-write):
  listen   пассивное прослушивание N секунд: кто ещё опрашивает, есть ли heartbeat, зеркалирование
  info     тип/версия ПП, режим, лимиты
  single   M чтений одной зоны -> задержка (min/avg/p95/max)
  groups   чтение групп зон разного размера -> задержка и оценка цикла опроса на 16..512 зон
  stress   серии запросов «спина к спине» с разной паузой между ними -> потери/таймауты
  events   задержка чтения счётчика непрочитанных событий (регистр 46162, НЕ разрушающее)
  watch    ЖУРНАЛ СОБЫТИЙ: ждёт события и логирует их (РАЗРУШАЮЩЕЕ чтение, нужен --allow-write)
  switch   переключение шлейфа: команда, затем ~10 с таймлайн состояний; 2 цикла «снять/взять»

Примеры:
  python bench_c2000pp.py 172.16.20.29 --zones 1-16
  python bench_c2000pp.py 172.16.20.29 --zones 1-16 --phases switch --allow-write --test-zone 1
  python bench_c2000pp.py --sim            # самопроверка на встроенном эмуляторе, без железа
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import math
import struct
import sys
import time
from typing import Any, Dict, List, Optional

import c2000pp as C

log = logging.getLogger("bench")
wire = logging.getLogger("bench.wire")
RESULT: Dict[str, Any] = {}


# ----------------------------------------------------------------------------
def pct(vals: List[float], p: float) -> float:
    if not vals:
        return float("nan")
    v = sorted(vals)
    return v[min(len(v) - 1, int(math.ceil(p / 100 * len(v))) - 1)]


def stats_ms(vals_s: List[float]) -> Dict[str, float]:
    if not vals_s:
        return {}
    ms = [x * 1e3 for x in vals_s]
    return dict(n=len(ms), min=min(ms), avg=sum(ms) / len(ms), p50=pct(ms, 50),
                p95=pct(ms, 95), max=max(ms))


def fmt(st: Dict[str, float]) -> str:
    if not st:
        return "нет данных"
    return (f"n={st['n']:.0f}  min {st['min']:.1f}  avg {st['avg']:.1f}  p50 {st['p50']:.1f}  "
            f"p95 {st['p95']:.1f}  max {st['max']:.1f} мс")


def describe(data: bytes) -> str:
    """Человекочитаемое описание датаграммы (запрос или ответ)."""
    if data[:1] != b"\x10":
        return f"НЕ-0x10 ({len(data)} Б; heartbeat конвертера?) {data.hex(' ')}"
    try:
        fr = C.parse_datagram(data)
    except ValueError as e:
        return f"БИТЫЙ ({e}) {data.hex(' ')}"
    head = f"cnt={fr.counter:04x} fl={fr.flags:02x} slave={fr.slave} f={fr.func}"
    p = fr.payload
    if fr.is_exception:
        return f"{head} EXCEPTION {p[0]} ({C.EXC_TEXT.get(p[0], '?')})"
    if fr.func in (1, 2, 3, 4) and len(p) == 4:          # запрос чтения: addr, qty
        a, q = struct.unpack(">HH", p)
        return f"{head} read addr={a} qty={q}"
    if fr.func in (5, 6) and len(p) == 4:                # запрос записи / эхо записи
        a, v = struct.unpack(">HH", p)
        extra = ""
        if C.REG_ZONE_STATE <= a < C.REG_ZONE_STATE + 512:
            extra = f"  (зона {a - C.REG_ZONE_STATE + 1}, значение {v}: {C.state_name(v)})"
        return f"{head} write addr={a} val={v}{extra}"
    if fr.func in (3, 4) and p:                           # ответ чтения
        regs = [f"{int.from_bytes(p[1 + i:3 + i], 'big'):04x}" for i in range(0, len(p) - 1, 2)]
        names = ""
        if len(regs) <= 8:
            names = "  [" + ", ".join(C.state_name(C.resolve_state(int(r, 16) >> 8, int(r, 16) & 255))
                                      for r in regs) + "]"
        return f"{head} data {' '.join(regs)}{names}"
    return f"{head} {p.hex(' ')}"


class Rig:
    """Транспорт + слушатель всего трафика."""

    def __init__(self, a):
        self.a = a
        self.pp = C.C2000PP(a.host, a.port, slave_id=a.slave, zones=C.parse_zone_spec(a.zones),
                            local_port=a.local_port, timeout=a.timeout, retries=a.retries,
                            gap=a.gap, quarantine=a.quarantine)
        self.t = self.pp.t
        self.rx_log: List[tuple] = []            # (t, data) все входящие
        self.unmatched: List[tuple] = []

    async def start(self):
        self.t.tap = self._tap
        self.t.on_unmatched = self._unmatched
        await self.t.start()

    async def stop(self):
        await self.t.stop()

    def _tap(self, d: str, ts: float, data: bytes, addr):
        self.rx_log.append((ts, d, data))
        wire.debug("%s %s:%s  %s", "-->" if d == "tx" else "<--", addr[0], addr[1], describe(data))

    def _unmatched(self, fr, why):
        self.unmatched.append((time.time(), fr.raw))
        wire.info("<-- ЧУЖОЙ/НЕСОПОСТАВЛЕННЫЙ (%s): %s", why, describe(fr.raw))


# ----------------------------------------------------------------------------
async def phase_listen(r: Rig):
    n = r.a.listen
    log.info("== listen: пассивное прослушивание %.0f с (ничего не отправляем)", n)
    base = len(r.rx_log)
    await asyncio.sleep(n)
    rx = r.rx_log[base:]
    frames = [(ts, d) for ts, k, d in rx if k == "rx"]
    hb = [ts for ts, d in frames if d[:1] != b"\x10"]
    data = [(ts, d) for ts, d in frames if d[:1] == b"\x10"]
    log.info("получено датаграмм: %d (данные %d, служебных %d)", len(frames), len(data), len(hb))
    if len(hb) > 1:
        ints = [b - a for a, b in zip(hb, hb[1:])]
        log.info("heartbeat конвертера: период ~%.1f с, 10 байт: %s", sum(ints) / len(ints),
                 {d.hex(' ') for ts, d in frames if d[:1] != b'\x10'})
    if len(data) > 1:
        ints = [b[0] - a[0] for a, b in zip(data, data[1:])]
        log.info("интервалы между ответами других клиентов: min %.3f avg %.3f max %.3f с",
                 min(ints), sum(ints) / len(ints), max(ints))
    RESULT["listen"] = dict(seconds=n, frames=len(frames), data=len(data), heartbeats=len(hb))


async def phase_info(r: Rig):
    log.info("== info")
    try:
        info = await r.pp.read_device_info()
        log.info("ПП: %s", info)
        RESULT["info"] = info
    except C.C2000Error as e:
        log.error("info не удалось: %s", e)


async def phase_single(r: Rig):
    z, m = r.a.test_zone, r.a.reads
    log.info("== single: %d чтений зоны %d (пауза между запросами %.0f мс)", m, z, r.a.gap * 1e3)
    rtts, errs = [], 0
    for _ in range(m):
        try:
            await r.t.read_holding(C.REG_ZONE_STATE + z - 1, 1)
            rtts.append(r.t.rtts[-1])           # чистое время sendto -> ответ (без очереди/паузы)
        except C.C2000Error as e:
            errs += 1
            log.warning("ошибка: %s", e)
    st = stats_ms(rtts)
    log.info("задержка одиночного чтения: %s; ошибок %d", fmt(st), errs)
    RESULT["single"] = dict(stats=st, errors=errs)


async def phase_groups(r: Rig):
    zones = C.parse_zone_spec(r.a.zones)
    first = zones[0]
    avail = 1
    while first + avail in zones:
        avail += 1
    sizes = [s for s in (int(x) for x in r.a.group_sizes.split(",")) if s <= avail]
    log.info("== groups: подряд идущих зон от %d: %d; размеры групп %s, по %d повторов",
             first, avail, sizes, r.a.repeats)
    out = {}
    for sz in sizes:
        rtts, exc, tmo = [], 0, 0
        for _ in range(r.a.repeats):
            try:
                await r.t.read_holding(C.REG_ZONE_STATE + first - 1, sz)
                rtts.append(r.t.rtts[-1])
            except C.ModbusException as e:
                exc += 1
                log.warning("группа %d: %s", sz, e)
            except C.C2000Timeout:
                tmo += 1
        st = stats_ms(rtts)
        out[sz] = dict(stats=st, exceptions=exc, timeouts=tmo)
        log.info("группа %3d зон: %s; exception=%d timeout=%d", sz, fmt(st), exc, tmo)
    RESULT["groups"] = out
    # оценка цикла полного опроса
    log.info("-- оценка времени цикла опроса N зон (по p95 задержки + пауза %.0f мс):", r.a.gap * 1e3)
    est = {}
    for sz, v in out.items():
        if not v["stats"]:
            continue
        per = v["stats"]["p95"] / 1e3 + r.a.gap
        row = {n: math.ceil(n / sz) * per for n in (16, 64, 128, 256, 512)}
        est[sz] = row
        log.info("   группа %3d: " % sz + "  ".join(f"{n}зон≈{t:5.2f}с" for n, t in row.items()))
    RESULT["cycle_estimate_s"] = est
    if est:
        best = min(est, key=lambda s: est[s][512])
        c512 = est[best][512]
        log.info("РЕКОМЕНДАЦИЯ для 512 зон: группа %d, цикл ≈ %.1f с -> период опроса >= %.0f с, "
                 "таймаут устаревания >= %.0f с", best, c512, math.ceil(c512 * 2), math.ceil(c512 * 6))


async def phase_stress(r: Rig):
    zones = C.parse_zone_spec(r.a.zones)
    sz = min(8, len(zones))
    log.info("== stress: %d запросов подряд по %d зон при разной паузе между запросами", r.a.stress_n, sz)
    res = {}
    for gap in (0.0, 0.005, 0.01, 0.02, 0.05):
        r.t.gap = gap
        ok = tmo = exc = 0
        rtts = []
        t_all = time.perf_counter()
        for _ in range(r.a.stress_n):
            try:
                await r.t.read_holding(C.REG_ZONE_STATE + zones[0] - 1, sz)
                ok += 1
                rtts.append(r.t.rtts[-1])
            except C.C2000Timeout:
                tmo += 1
            except C.ModbusException:
                exc += 1
        dt = time.perf_counter() - t_all
        res[gap] = dict(ok=ok, timeouts=tmo, exceptions=exc, req_per_s=ok / dt, stats=stats_ms(rtts))
        log.info("пауза %4.0f мс: ok=%d timeout=%d exc=%d  %.1f запр/с  (rtt) %s", gap * 1e3, ok, tmo, exc,
                 ok / dt, fmt(stats_ms(rtts)))
    r.t.gap = r.a.gap
    RESULT["stress"] = {str(k): v for k, v in res.items()}
    good = [g for g, v in res.items() if v["timeouts"] == 0 and v["exceptions"] == 0]
    if good:
        log.info("наименьшая пауза без потерь: %.0f мс (в работе берите с запасом x2-x4)", min(good) * 1e3)


async def phase_events(r: Rig):
    log.info("== events: чтение счётчика непрочитанных событий (46162, не разрушающее)")
    rtts, v = [], None
    for _ in range(r.a.reads):
        try:
            v = (await r.t.read_holding(C.REG_UNREAD_EVENTS, 1))[0]
            rtts.append(r.t.rtts[-1])
        except C.C2000Error as e:
            log.warning("%s", e)
    log.info("непрочитанных событий в ПП: %s; задержка: %s", v if rtts else "?", fmt(stats_ms(rtts)))
    RESULT["events"] = dict(stats=stats_ms(rtts))


async def read_state(r: Rig, z: int):
    v = (await r.t.read_holding(C.REG_ZONE_STATE + z - 1, 1))[0]
    return C.resolve_state(v >> 8, v & 0xFF), v


async def phase_switch(r: Rig):
    if not r.a.allow_write:
        log.warning("== switch пропущен: он ПИШЕТ в ПП. Добавьте --allow-write")
        return
    z = r.a.test_zone
    log.info("== switch: зона %d, %d цикла(ов) «переключить – %.0f с – переключить обратно – %.0f с»",
             z, r.a.cycles, r.a.hold, r.a.hold)
    code0, _ = await read_state(r, z)
    armed0 = code0 in C.ARMED_CODES
    log.info("исходное состояние: %d (%s), считается %s", code0, C.state_name(code0),
             "ВЗЯТА" if armed0 else "СНЯТА")
    runs = []
    for cyc in range(r.a.cycles):
        for target in (not armed0, armed0):
            cmd = C.STATE_ARMED if target else C.STATE_DISARMED
            log.info("-- цикл %d: команда %s (%d)", cyc + 1, "ВЗЯТЬ" if target else "СНЯТЬ", cmd)
            tl: List[tuple] = []
            t0 = time.perf_counter()      # отсчёт – момент отправки команды
            try:
                await r.t.write_register(C.REG_ZONE_STATE + z - 1, cmd)
            except C.C2000Error as e:
                log.error("команда не прошла: %s", e)
                runs.append(dict(target=target, error=str(e)))
                continue
            t_echo = r.t.rtts[-1]
            log.info("   эхо записи через %.0f мс", t_echo * 1e3)
            last = None
            t_first_change = t_confirm = None
            flaps = 0
            confirmed = False
            while time.perf_counter() - t0 < r.a.hold:
                ts = time.perf_counter()
                try:
                    code, raw = await read_state(r, z)
                except C.C2000Error as e:
                    log.warning("   чтение: %s", e)
                    await asyncio.sleep(r.a.sample)
                    continue
                rel = ts - t0
                if code != last:
                    log.info("   t=%6.2f с  состояние %3d  %s", rel, code, C.state_name(code))
                    tl.append((round(rel, 3), code))
                    if last is not None and t_first_change is None:
                        t_first_change = rel
                    last = code
                is_t = (code in C.ARMED_CODES) == target
                if is_t and not confirmed:
                    confirmed, t_confirm = True, rel
                elif confirmed and not is_t:
                    flaps += 1
                    confirmed = False
                    log.warning("   !! МОРГАНИЕ: после подтверждения состояние ушло обратно (t=%.2f)", rel)
                await asyncio.sleep(max(0.0, r.a.sample - (time.perf_counter() - ts)))
            runs.append(dict(target="arm" if target else "disarm", echo_ms=t_echo * 1e3,
                             first_change_s=t_first_change, confirm_s=t_confirm, flaps=flaps,
                             timeline=tl))
            log.info("   итог: первое изменение %s, подтверждено %s, морганий %d",
                     f"{t_first_change:.2f} с" if t_first_change is not None else "нет",
                     f"{t_confirm:.2f} с" if t_confirm is not None else "НЕТ", flaps)
    # вернуть исходное, если надо
    code, _ = await read_state(r, z)
    if (code in C.ARMED_CODES) != armed0:
        log.info("возвращаю исходное состояние")
        await r.t.write_register(C.REG_ZONE_STATE + z - 1, C.STATE_ARMED if armed0 else C.STATE_DISARMED)
    RESULT["switch"] = runs
    arms = [x["confirm_s"] for x in runs if x.get("target") == "arm" and x.get("confirm_s") is not None]
    dis = [x["confirm_s"] for x in runs if x.get("target") == "disarm" and x.get("confirm_s") is not None]
    if arms:
        log.info("ВЗЯТИЕ подтверждается за %.2f–%.2f с", min(arms), max(arms))
    if dis:
        log.info("СНЯТИЕ подтверждается за %.2f–%.2f с", min(dis), max(dis))
    allc = arms + dis
    if allc:
        log.info("РЕКОМЕНДАЦИЯ: pending_timeout >= %.0f с (сейчас в библиотеке 15)", math.ceil(max(allc) * 2 + 3))


async def phase_watch(r: Rig):
    """Читает журнал событий ПП, пока вы вызываете события (обрыв/пожар шлейфа и т.п.)."""
    if not r.a.allow_write:
        log.warning("== watch пропущен: чтение журнала РАЗРУШАЮЩЕЕ (события помечаются прочитанными). "
                    "Добавьте --allow-write и убедитесь, что журналом больше никто не пользуется")
        return
    log.info("== watch: %.0f с, проверка журнала каждые %.2f с. ВЫЗЫВАЙТЕ СОБЫТИЯ НА ПП.",
             r.a.watch, r.a.watch_interval)
    end = time.perf_counter() + r.a.watch
    t0 = time.perf_counter()
    last_cnt, seen = None, []
    while time.perf_counter() < end:
        try:
            cnt = (await r.t.read_holding(C.REG_UNREAD_EVENTS, 1))[0]
            if cnt != last_cnt:
                log.info("t=%7.2f с  непрочитанных событий: %s", time.perf_counter() - t0, cnt)
                last_cnt = cnt
            for _ in range(min(cnt, 50)):
                tq = time.perf_counter() - t0
                ev = await r.pp.read_oldest_event(mark_read=True)
                if ev is None:
                    break
                state = ""
                if ev.zone:
                    try:
                        code, _ = await read_state(r, ev.zone)
                        state = f"  | состояние зоны сейчас: {code} {C.state_name(code)}"
                    except C.C2000Error:
                        pass
                log.info("t=%7.2f с  СОБЫТИЕ №%d код %d «%s»  зона=%s раздел=%s польз.=%s реле=%s/%s время ПП=%s%s",
                         tq, ev.number, ev.code, ev.name, ev.zone, ev.section, ev.user, ev.relay,
                         ev.relay_state, ev.time, state)
                seen.append(dict(t=round(tq, 2), number=ev.number, code=ev.code, name=ev.name,
                                 zone=ev.zone, section=ev.section, user=ev.user, time=ev.time))
        except C.C2000Error as e:
            log.warning("журнал: %s", e)
        await asyncio.sleep(r.a.watch_interval)
    RESULT["watch"] = seen
    log.info("итого событий прочитано: %d", len(seen))


PHASES = dict(listen=phase_listen, info=phase_info, single=phase_single, groups=phase_groups,
              stress=phase_stress, events=phase_events, watch=phase_watch, switch=phase_switch)


# ----------------------------------------------------------------------------
async def start_sim(a):
    """Встроенный эмулятор (из test_c2000pp) – чтобы проверить саму утилиту без железа."""
    import random
    from test_c2000pp import FakeConverter
    loop = asyncio.get_running_loop()
    srv = 42000 + random.randint(0, 500)
    zones = {i: (24 << 8) for i in range(1, 65)}
    zones[1] = 112 << 8
    fake = FakeConverter(srv + 1000, zones)
    fake.arm_delay, fake.fire = 1.7, {1}
    tr, _ = await loop.create_datagram_endpoint(lambda: fake, local_addr=("127.0.0.1", srv))
    a.host, a.port, a.local_port, a.zones = "127.0.0.1", srv, srv + 1000, "1-64"
    a.listen, a.reads, a.repeats, a.stress_n, a.hold, a.cycles = 1.0, 10, 3, 20, 4.0, 1
    a.allow_write = True
    a.watch, a.watch_interval = 3.0, 0.3
    from test_c2000pp import make_event
    loop.call_later(0.6, lambda: fake.events.append(make_event(1, 45, zone=1, section=1)))
    loop.call_later(1.4, lambda: fake.events.append(make_event(2, 37, zone=5, section=2)))
    asyncio.get_running_loop().call_later(0.3, fake.heartbeat)
    return tr


async def main_async(a) -> int:
    sim_tr = await start_sim(a) if a.sim else None
    r = Rig(a)
    try:
        await r.start()
    except C.C2000Error as e:
        log.error("%s", e)
        return 2
    t0 = time.time()
    try:
        for name in a.phases.split(","):
            name = name.strip()
            if name not in PHASES:
                log.error("неизвестная фаза %s (есть: %s)", name, ",".join(PHASES))
                continue
            await PHASES[name](r)
    finally:
        await r.stop()
        if sim_tr:
            sim_tr.close()
    RESULT["transport_stats"] = r.t.stats
    RESULT["rtt_overall"] = r.t.rtt_stats()
    log.info("== итог транспорта: %s", r.t.stats)
    log.info("   сопоставленных ответов: задержка %s", r.t.rtt_stats())
    if r.unmatched:
        log.info("   чужих/несопоставленных кадров за время теста: %d (см. лог)", len(r.unmatched))
    RESULT["duration_s"] = time.time() - t0
    with open(a.json, "w", encoding="utf-8") as f:
        json.dump(RESULT, f, ensure_ascii=False, indent=1, default=str)
    log.info("лог: %s ; сводка: %s", a.log, a.json)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host", nargs="?", default="")
    ap.add_argument("--port", type=int, default=40002, help="UDP-порт конвертера")
    ap.add_argument("--local-port", type=int, default=None, help="локальный порт (по умолчанию = --port)")
    ap.add_argument("--slave", type=int, default=1)
    ap.add_argument("--zones", default="1-16", help="какие зоны существуют/опрашиваются, напр. 1-64")
    ap.add_argument("--test-zone", type=int, default=1)
    ap.add_argument("--phases", default="listen,info,single,groups,stress,events",
                    help="через запятую; switch добавьте явно вместе с --allow-write")
    ap.add_argument("--allow-write", action="store_true", help="разрешить фазе switch писать в ПП")
    ap.add_argument("--listen", type=float, default=12.0, help="секунд пассивного прослушивания")
    ap.add_argument("--reads", type=int, default=30)
    ap.add_argument("--repeats", type=int, default=10)
    ap.add_argument("--group-sizes", default="1,2,4,8,16,32,64")
    ap.add_argument("--stress-n", type=int, default=60)
    ap.add_argument("--cycles", type=int, default=2)
    ap.add_argument("--hold", type=float, default=10.0, help="секунд наблюдения после каждой команды")
    ap.add_argument("--sample", type=float, default=0.25, help="период чтения зоны в фазе switch, с")
    ap.add_argument("--watch", type=float, default=120.0, help="фаза watch: сколько секунд ждать события")
    ap.add_argument("--watch-interval", type=float, default=0.5, help="фаза watch: период проверки журнала, с")
    ap.add_argument("--timeout", type=float, default=1.5)
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--gap", type=float, default=0.02)
    ap.add_argument("--quarantine", type=float, default=0.4)
    ap.add_argument("--sim", action="store_true", help="эмулятор вместо железа (самопроверка)")
    stamp = time.strftime("%Y%m%d_%H%M%S")
    ap.add_argument("--log", default=f"bench_{stamp}.log")
    ap.add_argument("--json", default=f"bench_{stamp}.json")
    a = ap.parse_args(argv)
    if not a.host and not a.sim:
        ap.error("нужен host (или --sim)")
    if a.sim:
        for ph in ("watch", "switch"):
            if ph not in a.phases:
                a.phases += "," + ph
    fmt_ = logging.Formatter("%(asctime)s.%(msecs)03d %(message)s", "%H:%M:%S")
    fh = logging.FileHandler(a.log, "w", "utf-8"); fh.setFormatter(fmt_); fh.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout); ch.setFormatter(fmt_); ch.setLevel(logging.INFO)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG); root.addHandler(fh); root.addHandler(ch)
    logging.getLogger("c2000pp").setLevel(logging.INFO)
    return asyncio.run(main_async(a))


if __name__ == "__main__":
    raise SystemExit(main())
