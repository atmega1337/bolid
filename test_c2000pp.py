"""Тесты: python -m unittest -v test_c2000pp"""
import asyncio, random, struct, time, unittest
import c2000pp as C


def make_event(number, code, zone=None, section=None, user=None, hms=(12, 0, 0), dmy=(10, 11, 26)):
    """Собрать 28 байт события как у ПП: номер(2) длина(1) код(1) поля… (дополнено нулями)."""
    f = b""
    if zone is not None: f += bytes((3, 2)) + struct.pack(">H", zone)
    if section is not None: f += bytes((2, 2)) + struct.pack(">H", section)
    if user is not None: f += bytes((1, 2)) + struct.pack(">H", user)
    f += bytes((11, 6)) + bytes(hms) + bytes(dmy)
    return (struct.pack(">H", number) + bytes((len(f) + 1, code)) + f).ljust(28, b"\0")


def bhex(s): return bytes.fromhex(s.replace(" ", ""))


class Wire(unittest.TestCase):
    def test_crc_real_capture(self):
        # кадры из реального обмена (запрос типа/версии и ответ: тип 36, версия 3.01)
        fr = C.parse_datagram(bhex("10 09 2e f5 50 01 03 04 00 24 01 2d") + struct.pack("<H", C.crc16(bhex("01 03 04 00 24 01 2d"))))
        self.assertEqual((fr.slave, fr.func, fr.payload), (1, 3, bhex("04 00 24 01 2d")))

    def test_reject(self):
        good = C.wrap_request(C.build_adu(1, 3, bhex("b4 48 00 02")), 5)
        C.parse_datagram(good)
        for bad in (good[:-1], b"\x11" + good[1:], good[:1] + b"\x20" + good[2:],
                    good[:4] + b"\x11" + good[5:], good[:-3] + b"\x00" + good[-2:]):
            with self.assertRaises(ValueError): C.parse_datagram(bad)

    def test_request_format_matches_scada(self):
        # из захвата настоящего SCADA: 10 08 04 17 10 01 03 b4 48 00 02 + CRC
        self.assertEqual(C.wrap_request(C.build_adu(1, 3, bhex("b4 48 00 02")), 0x0417)[:11],
                         bhex("10 08 04 17 10 01 03 b4 48 00 02"))

    def test_doc_event_example(self):   # РЭ стр.51: событие №32
        p = bhex("1C 00 20 19 6D 03 02 00 08 02 02 00 03 18 02 01 05 01 02 00 01 0B 06 0C 20 10 05 05 11")
        ev = C.parse_event(p)
        self.assertEqual((ev.number, ev.code, ev.zone, ev.section, ev.section_id, ev.user, ev.time),
                         (32, 0x6D, 8, 3, 261, 1, "2017-05-05 12:32:16"))

    def test_doc_event_relay(self):
        p = bhex("1C 00 21 11 80 05 02 00 0C 07 02 00 01 0B 06 0C 22 01 07 04 0E")
        ev = C.parse_event(p)
        self.assertEqual((ev.relay, ev.relay_state, ev.time), (12, 1, "2014-04-07 12:34:01"))

    def test_empty_event(self):
        self.assertIsNone(C.parse_event(bhex("1C 00 00") + bytes(25)))

    def test_state_resolve(self):   # реальные ответы: 0xC1C7, 0x1800, 0xFB00
        self.assertEqual(C.resolve_state(0x18, 0), 24)
        self.assertEqual(C.resolve_state(0xFB, 0), 251)
        self.assertEqual(C.resolve_state(0xC1, 0xC7), 199 if C.STATE_PRIORITY[199] > C.STATE_PRIORITY[193] else 193)
        self.assertEqual(C.resolve_state(0, 0), 0)

    def test_zone_spec(self):
        self.assertEqual(C.parse_zone_spec("1-3, 7;9"), [1, 2, 3, 7, 9])


class FakeConverter(asyncio.DatagramProtocol):
    """Эмулятор С2000-Ethernet + С2000-ПП. Отвечает на фиксированный порт клиента."""
    def __init__(self, reply_port, zones):
        self.reply_port, self.zones, self.cnt = reply_port, zones, 0x1900
        self.relays = {1: False}
        self.faults = {}          # сценарии сбоев: name -> callable(request_adu) -> действие
        self.seen = []
        self.arm_delay = 0.0      # через сколько секунд взятие становится видно в состоянии
        self.fire = set()         # «пожарные» зоны: снятие даёт состояние 112, а не 109
        self.ignore_writes = False
        self.events = []          # очередь событий журнала: готовые 28 байт (номер,длина,код,поля)
    def heartbeat(self):
        self.cnt = (self.cnt + 1) & 0xFFFF           # служебная датаграмма занимает номер счётчика
        self.t.sendto(bytes.fromhex("ed9c22014869 01bc1800".replace(" ", "")), ("127.0.0.1", self.reply_port))
    def connection_made(self, t): self.t = t
    def send(self, adu, flags=0x50, delay=0):
        self.cnt = (self.cnt + 1) & 0xFFFF
        pkt = bytes((0x10, len(adu), self.cnt >> 8, self.cnt & 255, flags)) + adu
        loop = asyncio.get_running_loop()
        loop.call_later(delay, self.t.sendto, pkt, ("127.0.0.1", self.reply_port))
    def reply(self, func, body, **kw):
        b = bytes((1, func)) + body
        self.send(b + struct.pack("<H", C.crc16(b)), **kw)
    def datagram_received(self, data, addr):
        adu = data[5:]; func = adu[1]; self.seen.append(adu)
        hook = self.faults.get("hook")
        act = hook(adu) if hook else None
        if act == "drop": return
        if isinstance(act, tuple) and act[0] == "late":      # ответ придёт после таймаута клиента
            delay = act[1]
        else: delay = 0
        if isinstance(act, tuple) and act[0] == "exc":
            return self.reply(func | 0x80, bytes((act[1],)))
        if func == 3:
            addr_, qty = struct.unpack(">HH", adu[2:6])
            if 40000 <= addr_ < 40512:
                regs = []
                for z in range(addr_ - 39999, addr_ - 39999 + qty):
                    if z not in self.zones:
                        return self.reply(0x83, b"\x03")
                    regs.append(self.zones[z])
                return self.reply(3, bytes((2 * qty,)) + b"".join(struct.pack(">H", r) for r in regs), delay=delay)
            if addr_ == 46152:
                return self.reply(3, b"\x04\x00\x24\x01\x2d")
            if addr_ == 46162:
                return self.reply(3, b"\x02" + struct.pack(">H", len(self.events)))
            if addr_ == 46264:
                ev = self.events[0] if self.events else bytes(28)
                return self.reply(3, b"\x1c" + ev)
            return self.reply(0x83, b"\x02")
        if func == 6 and struct.unpack(">H", adu[2:4])[0] == 46163:
            if self.events: self.events.pop(0)
            return self.reply(6, adu[2:6])
        if func == 6:
            addr_, val = struct.unpack(">HH", adu[2:6])
            z = addr_ - 39999
            if not self.ignore_writes:
                if val == 24 and self.arm_delay:
                    asyncio.get_running_loop().call_later(self.arm_delay, self.zones.__setitem__, z, 24 << 8)
                elif val == 109 and z in self.fire:
                    self.zones[z] = 112 << 8
                else:
                    self.zones[z] = val << 8
            return self.reply(6, adu[2:6], delay=delay)
        if func == 2:
            return self.reply(2, b"\x01\x00")


async def make(zones, **kw):
    loop = asyncio.get_running_loop()
    srv_port = 41000 + random.randint(0, 800)
    cli_port = srv_port + 1000
    fake = FakeConverter(cli_port, dict(zones))
    tr, _ = await loop.create_datagram_endpoint(lambda: fake, local_addr=("127.0.0.1", srv_port))
    pp = C.C2000PP("127.0.0.1", srv_port, local_port=cli_port, zones=list(zones),
                   timeout=0.4, quarantine=0.25, **kw)
    return fake, tr, pp


class Integration(unittest.IsolatedAsyncioTestCase):
    async def test_group_read_and_no_mixup(self):
        zs = {i: (24 << 8) if i % 2 else (109 << 8) for i in range(1, 21)}
        fake, tr, pp = await make(zs)
        await pp.t.start()
        try:
            ch = await pp.poll_all()
            self.assertEqual(len(ch), 20)
            for i in range(1, 21): self.assertEqual(pp.zones[i].code, 24 if i % 2 else 109)
            self.assertEqual(len(fake.seen), 3)       # 8+8+4 – группы, а не 20 запросов
        finally:
            await pp.stop(); tr.close()

    async def test_late_reply_is_not_mixed(self):
        """Старая ошибка: запоздалый ответ на зону N попадал в зону N+1."""
        zs = {1: 24 << 8, 2: 109 << 8, 3: 0xFB00}
        fake, tr, pp = await make(zs, group_size=1)
        await pp.t.start()
        calls = {"n": 0}
        def hook(adu):
            if adu[1] == 3 and struct.unpack(">H", adu[2:4])[0] == 40000:
                calls["n"] += 1
                if calls["n"] == 1: return ("late", 0.55)      # первый ответ опоздает
        fake.faults["hook"] = hook
        try:
            await pp.poll_all()
            self.assertEqual([pp.zones[i].code for i in (1, 2, 3)], [24, 109, 251])
            self.assertGreaterEqual(pp.t.stats["timeouts"], 1)
        finally:
            await pp.stop(); tr.close()

    async def test_exception3_isolates_absent_zone(self):
        zs = {1: 24 << 8, 2: 24 << 8, 4: 109 << 8}                 # зоны 3 нет
        fake, tr, pp = await make(zs); pp.set_zones([1, 2, 3, 4])
        await pp.t.start()
        try:
            await pp.poll_all()
            self.assertEqual(pp.zones[3].status, C.ZoneStatus.NO_DATA)
            self.assertEqual((pp.zones[1].code, pp.zones[2].code, pp.zones[4].code), (24, 24, 109))
            n = len(fake.seen); await pp.poll_all()
            self.assertEqual(len(fake.seen) - n, 2)                # зона 3 не мешает: группы 1-2 и 4
        finally:
            await pp.stop(); tr.close()

    async def test_exception15_retried(self):
        fake, tr, pp = await make({1: 24 << 8})
        await pp.t.start()
        n = {"k": 0}
        def hook(adu):
            if adu[1] == 3:
                n["k"] += 1
                if n["k"] <= 2: return ("exc", 15)
        fake.faults["hook"] = hook
        try:
            await pp.poll_all(); self.assertEqual(pp.zones[1].code, 24)
        finally:
            await pp.stop(); tr.close()

    async def test_garbage_and_duplicates_ignored(self):
        fake, tr, pp = await make({1: 24 << 8})
        await pp.t.start()
        try:
            # мусор на порт клиента до и во время опроса
            for junk in (b"\x00\x01", b"\x10\x05\x00\x00\x10\x01\x03\x00\x00\x00", bytes(40)):
                tr.sendto(junk, ("127.0.0.1", fake.reply_port))
            await pp.poll_all(); self.assertEqual(pp.zones[1].code, 24)
            self.assertGreaterEqual(pp.t.stats["bad_frames"], 1)      # 0x10 + битая длина
            self.assertGreaterEqual(pp.t.stats["other_frames"], 2)    # не-0x10 (как heartbeat)
        finally:
            await pp.stop(); tr.close()

    async def test_command_has_priority_and_refreshes(self):
        zs = {i: 109 << 8 for i in range(1, 6)}
        fake, tr, pp = await make(zs, group_size=1)
        await pp.t.start()
        try:
            poll = asyncio.create_task(pp.poll_all())
            await asyncio.sleep(0)
            await pp.arm_zone(3)
            await poll
            order = [(a[1], struct.unpack(">H", a[2:4])[0]) for a in fake.seen]
            self.assertLess(order.index((6, 40002)), 5)            # команда не ждёт конца опроса
            await pp.poll_all(); self.assertEqual(pp.zones[3].code, 24)
        finally:
            await pp.stop(); tr.close()

    async def test_timeout_marks_zone_and_recovers(self):
        fake, tr, pp = await make({1: 24 << 8}, poll_interval=0.5, stale_timeout=1.0)
        down = {"v": False}
        fake.faults["hook"] = lambda adu: "drop" if down["v"] else None
        await pp.start()
        events = []; pp.add_listener(lambda n, p: events.append(n))
        try:
            await asyncio.sleep(0.8); self.assertEqual(pp.zones[1].status, C.ZoneStatus.OK)
            down["v"] = True
            await asyncio.sleep(3.0)
            self.assertEqual(pp.zones[1].status, C.ZoneStatus.TIMEOUT)
            self.assertFalse(pp.available)
            down["v"] = False
            await asyncio.sleep(3.0)
            self.assertEqual(pp.zones[1].status, C.ZoneStatus.OK); self.assertTrue(pp.available)
            self.assertIn("availability", events)
        finally:
            await pp.stop(); tr.close()

    async def test_foreign_reply_triggers_refresh(self):
        fake, tr, pp = await make({1: 24 << 8}, poll_interval=30)
        await pp.start()
        try:
            await asyncio.sleep(0.5); n = len(fake.seen)
            # «чужой» валидный ответ на нашу порт, пока мы ничего не ждём
            fake.reply(3, b"\x02\x6d\x00")
            await asyncio.sleep(0.6)
            self.assertGreater(len(fake.seen), n)                  # был внеплановый опрос
        finally:
            await pp.stop(); tr.close()


class Behaviour(unittest.IsolatedAsyncioTestCase):
    async def test_arm_with_delay_no_flicker(self):
        """Взятие видно в состоянии лишь через ~1 с: switch не должен моргать on->off->on."""
        fake, tr, pp = await make({1: 112 << 8}, poll_interval=0.5, stale_timeout=5)
        fake.arm_delay = 1.0; fake.fire = {1}
        await pp.start()
        seq = []
        pp.add_listener(lambda n, p: seq.append(pp.zones[1].armed))
        try:
            await asyncio.sleep(0.6)
            self.assertFalse(pp.zones[1].armed)
            seq.clear()
            await pp.arm_zone(1)
            t_end = time.monotonic() + 3.0
            while time.monotonic() < t_end:
                seq.append(pp.zones[1].armed); await asyncio.sleep(0.05)
            self.assertTrue(seq[0] is True and all(seq), f"моргание: {seq}")
            self.assertEqual(pp.zones[1].code, 24); self.assertIsNone(pp.zones[1].pending)
            # снятие пожарного шлейфа -> 112, тоже без моргания
            seq.clear(); await pp.disarm_zone(1)
            t_end = time.monotonic() + 2.0
            while time.monotonic() < t_end:
                seq.append(pp.zones[1].armed); await asyncio.sleep(0.05)
            self.assertFalse(any(seq), f"моргание при снятии: {seq}")
            self.assertEqual(pp.zones[1].code, 112)
        finally:
            await pp.stop(); tr.close()

    async def test_pending_expires_when_not_confirmed(self):
        fake, tr, pp = await make({1: 109 << 8}, poll_interval=0.5, stale_timeout=5, pending_timeout=1.0)
        fake.ignore_writes = True
        await pp.start()
        try:
            await asyncio.sleep(0.6); await pp.arm_zone(1)
            self.assertTrue(pp.zones[1].armed)
            await asyncio.sleep(1.6)
            self.assertFalse(pp.zones[1].armed); self.assertIsNone(pp.zones[1].pending)
        finally:
            await pp.stop(); tr.close()

    async def test_write_error_clears_pending(self):
        fake, tr, pp = await make({1: 109 << 8})
        fake.faults["hook"] = lambda adu: ("exc", 4) if adu[1] == 6 else None
        await pp.t.start()
        try:
            with self.assertRaises(C.ModbusException): await pp.arm_zone(1)
            self.assertIsNone(pp.zones[1].pending); self.assertFalse(pp.zones[1].armed)
        finally:
            await pp.stop(); tr.close()

    async def test_foreign_command_decoded(self):
        """Другой клиент взял зону 2: конвертер прислал эхо записи и нам – разбираем адрес/значение."""
        fake, tr, pp = await make({1: 109 << 8, 2: 109 << 8}, poll_interval=30)
        await pp.start()
        got = []
        pp.add_listener(lambda n, p: got.append((n, p)) if n == "foreign_command" else None)
        try:
            await asyncio.sleep(0.5)
            fake.reply(6, struct.pack(">HH", 40001, 24))
            await asyncio.sleep(0.2)
            self.assertEqual(got, [("foreign_command", dict(zone=2, code=24))])
            self.assertTrue(pp.zones[2].armed); self.assertFalse(pp.zones[1].armed)
        finally:
            await pp.stop(); tr.close()

    async def test_heartbeat_not_counted_as_loss(self):
        fake, tr, pp = await make({1: 24 << 8})
        await pp.t.start()
        try:
            await pp.poll_all(); fake.heartbeat(); await asyncio.sleep(0.05); await pp.poll_all()
            self.assertEqual(pp.t.stats["heartbeats"], 1)
            self.assertEqual(pp.t.stats["lost_by_counter"], 0)
            self.assertEqual(pp.t.stats["bad_frames"], 0)
        finally:
            await pp.stop(); tr.close()

    async def test_failfast_big_config(self):
        """ПП/конвертер недоступны: цикл по 512 зонам не должен длиться минутами."""
        zs = {i: 24 << 8 for i in range(1, 129)}
        fake, tr, pp = await make(zs)
        fake.faults["hook"] = lambda adu: "drop"
        await pp.t.start()
        try:
            t0 = time.monotonic(); await pp.poll_all()
            self.assertLess(time.monotonic() - t0, 4.0)               # 16 групп*~1.9 с = 30 с без fail-fast
            self.assertEqual(len(fake.seen), pp.t.retries + 1)        # одна группа × все попытки
        finally:
            await pp.stop(); tr.close()

    async def test_restart_same_port(self):
        """Перезагрузка интеграции из-за смены настроек: порт должен освобождаться сразу."""
        loop = asyncio.get_running_loop()
        fake, tr, pp = await make({1: 24 << 8})
        port = pp.t.local_port
        await pp.stop()
        for _ in range(6):
            p2 = C.C2000PP("127.0.0.1", pp.t.port, local_port=port, zones=[1], timeout=0.4)
            await p2.start(); await p2.stop()
        tr.close()

    async def test_set_armed_waits_for_confirmation(self):
        fake, tr, pp = await make({1: 112 << 8}, poll_interval=5, stale_timeout=20)
        fake.arm_delay = 0.9; fake.fire = {1}
        await pp.start()
        try:
            await asyncio.sleep(0.3)
            t0 = time.monotonic()
            self.assertTrue(await pp.set_armed(1, True, wait=5))
            self.assertGreater(time.monotonic() - t0, 0.8)           # дождались задержки взятия
            self.assertTrue(await pp.set_armed(1, False, wait=5))      # снятие подтверждено
            self.assertEqual(pp.zones[1].code, 112)
        finally:
            await pp.stop(); tr.close()

    async def test_event_journal_read_and_zone_refresh(self):
        """use_events: события читаются по порядку, журнал опустошается, зона события перечитывается."""
        fake, tr, pp = await make({1: 24 << 8, 5: 24 << 8}, poll_interval=30, stale_timeout=60,
                                  use_events=True, event_interval=0.2)
        await pp.start()
        got = []
        pp.add_listener(lambda n, p: got.append(p) if n == "event" else None)
        try:
            await asyncio.sleep(0.4)
            fake.zones[5] = 243 << 8                                  # пожар в зоне 5
            fake.events += [make_event(7, 45, zone=1, section=1), make_event(8, 37, zone=5, section=2)]
            await asyncio.sleep(1.0)
            self.assertEqual([(e.number, e.code, e.zone) for e in got], [(7, 45, 1), (8, 37, 5)])
            self.assertEqual(got[1].time, "2026-11-10 12:00:00")
            self.assertEqual(fake.events, [])                          # прочитано -> удалено
            self.assertEqual(pp.zones[5].code, 243)                    # зона перечитана без ожидания опроса
        finally:
            await pp.stop(); tr.close()

    async def test_rtt_stats(self):
        fake, tr, pp = await make({i: 24 << 8 for i in range(1, 9)})
        await pp.t.start()
        try:
            for _ in range(5): await pp.poll_all()
            st = pp.t.rtt_stats()
            self.assertEqual(st["n"], 5); self.assertLess(st["max"], 100)
        finally:
            await pp.stop(); tr.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
