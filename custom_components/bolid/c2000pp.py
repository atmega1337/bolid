"""c2000pp.py – клиент преобразователя протокола «С2000-ПП» (АО НВП «Болид») версии 3.xx
через конвертер С2000-Ethernet (UDP, «прозрачный шлюз» Modbus-RTU).

Только стандартная библиотека, Python >= 3.9, asyncio.
Основано на РЭ АЦДР.426469.020 РЭп (изм. 19) и разборе реального обмена/клиента HUB-C2000PP.

Быстрый старт::

    async with C2000PP("192.168.1.50", 40002, zones=range(1, 21)) as pp:
        pp.add_listener(lambda name, payload: print(name, payload))
        await asyncio.sleep(60)

CLI::  python c2000pp.py 192.168.1.50 monitor --zones 1-20
"""
from __future__ import annotations

import asyncio
import collections
import itertools
import logging
import re
import struct
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

__version__ = "2.1.0"

# Названия состояний (табл. 1.1.5.12.1)
STATES: Dict[int, str] = {
    1: "Восстановление сети 220 В",
    2: "Авария сети 220 В",
    3: "Тревога проникновения",
    4: "Помеха",
    5: "Отключение звука",
    6: "Помеха устранена",
    7: "Ручное включение исполнительного устройства",
    8: "Ручное выключение исполнительного устройства",
    9: "Активация УДП",
    10: "Восстановление УДП",
    14: "Подбор кода",
    15: "Дверь открыта",
    17: "Неудачное взятие",
    18: "Предъявлен код принуждения",
    19: "Тест",
    20: "Вход в режим тестирования",
    21: "Выход из режима тестирования",
    22: "Восстановление контроля",
    23: "Задержка взятия",
    24: "Взятие входа на охрану",
    25: "Доступ закрыт",
    26: "Доступ отклонен",
    27: "Дверь взломана",
    28: "Доступ предоставлен",
    29: "Запрет доступа",
    30: "Восстановление доступа",
    31: "Дверь закрыта",
    32: "Проход",
    33: "Дверь заблокирована",
    34: "Идентификация",
    35: "Восстановление технологического входа",
    36: "Нарушение технологического входа",
    37: "Пожар",
    38: "Нарушение 2-го техно логического входа",
    39: "Восстановление нормы оборудования",
    40: "Пожар 2",
    41: "Неисправность оборудования",
    42: "Неизвестное устройство",
    43: "Предупреждение",
    44: "Внимание!",
    45: "Обрыв входа",
    46: "Обрыв ДПЛС",
    47: "Восстановление ДПЛС",
    48: "Сработка 2-го датчика",
    58: "Тихая тревога",
    61: "Сброс конфигурации",
    62: "Изменение конфигурации",
    67: "Изменение даты",
    69: "Журнал заполнен",
    70: "Журнал переполнен",
    71: "Понижение уровня",
    72: "Норма уровня",
    73: "Изменение времени",
    74: "Повышение уровня",
    75: "Аварийное повышение уровня",
    76: "Повышение температуры",
    77: "Аварийное понижение уровня",
    78: "Температура в норме",
    79: "Тревога затопления",
    80: "Восстановление датчика затопления",
    82: "Неисправность термометра",
    83: "Восстановление термометра",
    84: "Начало локального программирования",
    109: "Снятие входа с охраны",
    110: "Тревога сброшена",
    111: "Включение ШС",
    112: "Отключение ШС",
    113: "Включение выхода",
    114: "Отключение выхода",
    117: "Восстановление снятого входа",
    118: "Тревога входа",
    119: "Нарушение снятого входа",
    121: "Обрыв выхода",
    122: "КЗ выхода",
    123: "Восстановление выхода",
    126: "Потеря связи с выходом",
    127: "Восстановление связи с выходом",
    128: "Изменение состояния выхода",
    130: "Включение насоса",
    131: "Выключение насоса",
    135: "Ошибка при автоматическом тестировании",
    137: "Пуск",
    138: "Неудачный пуск",
    139: "Неудачный пуск пожаротушения",
    140: "Тест",
    141: "Задержка пуска АУП",
    142: "Автоматика АУП выключена",
    143: "Отмена пуска АУП",
    144: "Тушение",
    145: "Аварийный пуск АУП",
    146: "Пуск АУП",
    147: "Блокировка пуска АУП",
    148: "Автоматика АУП включена",
    149: "Взлом корпуса прибора",
    150: "Пуск речевого оповещения",
    151: "Отмена пуска РО",
    152: "Восстановление корпуса прибора",
    153: "ИУ в рабочем состоянии",
    154: "ИУ в исходном состоянии",
    155: "Отказ ИУ",
    156: "Ошибка ИУ",
    157: "Сброс задержки",
    158: "Восстановление внутренней зоны",
    159: "Задержка пуска РО",
    161: "Останов задержки пуска АУП",
    162: "Увеличение задержки пуска",
    164: "Саботаж",
    165: "Ошибка параметров входа",
    186: "Требуется замена батареи",
    187: "Потеря связи со входом",
    188: "Восстановление связи со входом",
    189: "Потеря связи по ДПЛС1",
    190: "Потеря связи по ДПЛС2",
    191: "Восстановление связи по ДПЛС1",
    192: "Отключение выходного напряжения",
    193: "Подключение выходного напряжения",
    194: "Перегрузка источника питания",
    195: "Перегрузка источника питания устранена",
    196: "Неисправность зарядного устройства",
    197: "Восстановление зарядного устройства",
    198: "Неисправность источника питания",
    199: "Восстановление источника питания",
    200: "Восстановление батареи",
    201: "Восстановление связи по ДПЛС2",
    202: "Неисправность батареи",
    203: "Перезапуск прибора",
    204: "Требуется обслуживание",
    205: "Ошибка теста АКБ",
    206: "Понижение температуры",
    211: "Батарея разряжена",
    212: "Разряд резервной батареи",
    213: "Восстановление резервной батареи",
    214: "Короткое замыкание входа",
    215: "Короткое замыкание ДПЛС",
    216: "Сработка датчика",
    217: "Отключение ветви RS-485",
    218: "Восстановление ветви RS-485",
    220: "Срабатывание СДУ",
    221: "Отказ СДУ",
    222: "Повышение напряжения ДПЛС",
    223: "Отметка наряда",
    224: "Некорректный ответ устройства в ДПЛС",
    225: "Неустойчивый ответ устройства в ДПЛС",
    229: "Задержка пуска",
    230: "Останов задержки пуска",
    231: "Остановка",
    232: "Увеличение задержки пуска",
    233: "Сброс задержки пуска",
    237: "Раздел снят по принуждению",
    241: "Раздел взят",
    242: "Раздел снят",
    249: "Окончание локального программирования",
    250: "Потеряна связь с прибором",
    251: "Восстановлена связь с прибором",
    252: "Подмена прибора",
    253: "Включение пульта С2000М",
    254: "Прошел день – отметка времени",
    255: "Прошел час – отметка времени",
}

# Приоритеты состояний (255 – наивысший), табл. 1.1.5.12.1
STATE_PRIORITY: Dict[int, int] = {
    1: 150,
    2: 199,
    3: 238,
    4: 222,
    5: 132,
    6: 144,
    7: 101,
    8: 100,
    9: 178,
    10: 165,
    14: 102,
    15: 175,
    17: 204,
    18: 239,
    19: 0,
    20: 106,
    21: 105,
    22: 137,
    23: 183,
    24: 174,
    25: 154,
    26: 131,
    27: 211,
    28: 129,
    29: 130,
    30: 151,
    31: 168,
    32: 128,
    33: 210,
    34: 127,
    35: 162,
    36: 163,
    37: 243,
    38: 161,
    39: 161,
    40: 244,
    41: 218,
    42: 103,
    43: 241,
    44: 242,
    45: 221,
    46: 205,
    47: 147,
    48: 93,
    58: 240,
    61: 92,
    62: 91,
    67: 126,
    69: 125,
    70: 124,
    71: 177,
    72: 170,
    73: 123,
    74: 181,
    75: 215,
    76: 180,
    77: 214,
    78: 169,
    79: 236,
    80: 173,
    82: 217,
    83: 159,
    84: 122,
    109: 185,
    110: 121,
    111: 139,
    112: 134,
    113: 138,
    114: 133,
    117: 184,
    118: 237,
    119: 186,
    121: 213,
    122: 212,
    123: 158,
    126: 226,
    127: 142,
    128: 97,
    130: 182,
    131: 172,
    135: 208,
    137: 250,
    138: 231,
    139: 245,
    140: 120,
    141: 252,
    142: 189,
    143: 235,
    144: 255,
    145: 254,
    146: 253,
    147: 190,
    148: 171,
    149: 194,
    150: 251,
    151: 234,
    152: 146,
    153: 179,
    154: 166,
    155: 229,
    156: 223,
    157: 98,
    158: 160,
    159: 249,
    161: 247,
    162: 90,
    164: 95,
    165: 219,
    186: 193,
    187: 227,
    188: 143,
    189: 192,
    190: 191,
    191: 136,
    192: 203,
    193: 157,
    194: 202,
    195: 156,
    196: 201,
    197: 155,
    198: 200,
    199: 152,
    200: 149,
    201: 135,
    202: 198,
    203: 117,
    204: 216,
    205: 197,
    206: 176,
    211: 196,
    212: 195,
    213: 148,
    214: 220,
    215: 207,
    216: 94,
    217: 145,
    218: 116,
    220: 187,
    221: 232,
    222: 206,
    223: 104,
    224: 225,
    225: 224,
    229: 248,
    230: 246,
    231: 233,
    232: 88,
    233: 89,
    237: 113,
    241: 115,
    242: 114,
    249: 96,
    250: 228,
    251: 141,
    252: 230,
    253: 110,
    254: 109,
    255: 108,
}

# ----------------------------------------------------------------------------
#  Протокол
# ----------------------------------------------------------------------------
STATE_ARMED = 24        # взятие на охрану
STATE_DISARMED = 109    # снятие с охраны
STATE_ARMING_DELAY = 23
STATE_LINK_RESTORED = 251
STATE_ARM_FAILED = 17     # «Неудачное взятие»
ARMED_CODES = frozenset({STATE_ARMED, STATE_ARMING_DELAY})

REG_ZONE_STATE = 40000
REG_SECTION_STATE = 44096
REG_COIL_RELAY = 10000
REG_MAX_RELAYS = 46144          # 46144..46150 – лимиты БД
REG_TYPE_VERSION = 46152
REG_NEWEST_EVENT = 46160
REG_OLDEST_EVENT = 46161
REG_UNREAD_EVENTS = 46162
REG_MARK_EVENT_READ = 46163
REG_READ_OLDEST_EVENT = 46264
DI_MODE = 8                     # 0 – Slave, 1 – Master
DI_MASTER_LINK = 9
DI_TAMPER = 10
DI_POWER = 11

EXC_TEXT = {1: "функция не поддерживается", 2: "адрес недоступен",
            3: "недопустимое значение (нет такой зоны/прибора?)",
            4: "ошибка обработки (нет связи с прибором?)",
            6: "устройство занято", 15: "данные ещё не получены"}


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


class C2000Error(Exception):
    """Базовая ошибка библиотеки."""


class C2000Timeout(C2000Error):
    """Нет (корректного) ответа в отведённое время."""


class C2000NotConnected(C2000Error):
    """Клиент не запущен."""


class ModbusException(C2000Error):
    def __init__(self, code: int, request: str = ""):
        self.code = code
        super().__init__(f"Modbus exception {code} ({EXC_TEXT.get(code, '?')}) на {request}")


@dataclass
class Frame:
    slave: int
    func: int
    payload: bytes
    flags: int = 0
    counter: int = 0
    raw: bytes = b""

    @property
    def is_exception(self) -> bool:
        return bool(self.func & 0x80)


def wrap_request(adu: bytes, counter: int) -> bytes:
    """Обёртка C2000-Ethernet: 10 LEN CNT_H CNT_L 10 + Modbus RTU (с CRC)."""
    return bytes((0x10, len(adu), (counter >> 8) & 0xFF, counter & 0xFF, 0x10)) + adu


def build_adu(slave: int, func: int, data: bytes) -> bytes:
    body = bytes((slave, func)) + data
    return body + struct.pack("<H", crc16(body))


def parse_datagram(data: bytes) -> Frame:
    """Строгий разбор датаграммы. Любое нарушение -> ValueError.
    Правила те же, что у эталонного клиента HUB-C2000PP:
    b0==0x10, b1+5==len, младший нибл b4==0, CRC Modbus сходится."""
    if len(data) < 9:
        raise ValueError("слишком короткая датаграмма")
    if data[0] != 0x10:
        raise ValueError("нет маркера 0x10")
    if data[1] + 5 != len(data):
        raise ValueError("длина не совпадает с заголовком")
    if data[4] & 0x0F:
        raise ValueError("неизвестный флаг заголовка")
    adu = data[5:]
    if crc16(adu) != 0:
        raise ValueError("ошибка CRC")
    return Frame(slave=adu[0], func=adu[1], payload=bytes(adu[2:-2]),
                 flags=data[4], counter=(data[2] << 8) | data[3], raw=bytes(data))


# ----------------------------------------------------------------------------
#  Модели данных
# ----------------------------------------------------------------------------
def resolve_state(hi: int, lo: int) -> int:
    """Из двух состояний регистра (ст. и мл. байт) берём приоритетное по табл. 1.1.5.12.1."""
    cands = [c for c in (hi, lo) if c]
    if not cands:
        return 0
    return max(cands, key=lambda c: STATE_PRIORITY.get(c, 0))


def state_name(code: int) -> str:
    if code == 0:
        return "Нет состояния"
    return STATES.get(code, f"Неизвестное состояние ({code})")


class ZoneStatus:
    OK = "ok"              # свежие данные
    PENDING = "pending"    # ещё ни разу не получали
    NO_DATA = "no_data"    # ПП отвечает ошибкой: зоны нет / данных нет
    TIMEOUT = "timeout"    # давно не обновлялась


@dataclass
class ZoneData:
    number: int
    code: int = 0
    code2: int = 0
    status: str = ZoneStatus.PENDING
    updated: float = 0.0          # time.monotonic() последнего успеха
    updated_wall: float = 0.0     # time.time()
    error: str = ""
    recheck: int = 0              # счётчик перезапросов (для 251)
    pending: Optional[bool] = None   # ожидаемое состояние после команды: True – взять, False – снять
    pending_until: float = 0.0       # monotonic, до какого момента ждём подтверждения

    @property
    def name(self) -> str:
        return state_name(self.code)

    @property
    def priority(self) -> int:
        return STATE_PRIORITY.get(self.code, 0)

    @property
    def armed_actual(self) -> bool:
        """Реальное состояние по данным ПП."""
        return self.code in ARMED_CODES

    @property
    def armed(self) -> bool:
        """Эффективное состояние: пока идёт подтверждение команды – ожидаемое (без «моргания»)."""
        if self.pending is not None and time.monotonic() < self.pending_until:
            return self.pending
        return self.armed_actual

    def age(self) -> Optional[float]:
        return None if not self.updated else time.monotonic() - self.updated


@dataclass
class PPEvent:
    number: int
    code: int
    zone: Optional[int] = None
    section: Optional[int] = None
    section_id: Optional[int] = None
    user: Optional[int] = None
    relay: Optional[int] = None
    relay_state: Optional[int] = None
    time: Optional[str] = None

    @property
    def name(self) -> str:
        return state_name(self.code)


def parse_event(payload: bytes) -> Optional[PPEvent]:
    """payload = ответ func 3 без адреса/функции: [byte_count][номер(2)][длина][код][поля...]"""
    if len(payload) < 5:
        return None
    number = (payload[1] << 8) | payload[2]
    if number == 0:
        return None                          # буфер пуст
    dlen, code = payload[3], payload[4]
    fields = payload[5:5 + max(dlen - 1, 0)]
    ev = PPEvent(number=number, code=code)
    i = 0
    while i + 2 <= len(fields):
        ftype, flen = fields[i], fields[i + 1]
        data = fields[i + 2:i + 2 + flen]
        i += 2 + flen
        if len(data) < flen:
            break
        val = int.from_bytes(data, "big") if ftype != 11 else 0
        if ftype == 1: ev.user = val
        elif ftype == 2: ev.section = val
        elif ftype == 3: ev.zone = val
        elif ftype == 5: ev.relay = val
        elif ftype == 7: ev.relay_state = val
        elif ftype == 24: ev.section_id = val
        elif ftype == 11 and flen == 6:
            h, mi, s, d, mo, y = data
            if d and mo:
                ev.time = f"{2000 + y:04d}-{mo:02d}-{d:02d} {h:02d}:{mi:02d}:{s:02d}"
    return ev


# ----------------------------------------------------------------------------
#  Транспорт: один сокет, одна очередь, строгое сопоставление ответов
# ----------------------------------------------------------------------------
@dataclass
class _Req:
    func: int
    data: bytes
    validate: Callable[[bytes], bool]
    label: str


def _req_read_regs(func: int, addr: int, qty: int) -> _Req:
    return _Req(func, struct.pack(">HH", addr, qty),
                lambda p: len(p) == 1 + 2 * qty and p[0] == 2 * qty,
                f"read(f{func}) {addr}+{qty}")


def _req_read_bits(func: int, addr: int, qty: int) -> _Req:
    n = (qty + 7) // 8
    return _Req(func, struct.pack(">HH", addr, qty),
                lambda p: len(p) == 1 + n and p[0] == n,
                f"read(f{func}) {addr}+{qty}")


def _req_write(func: int, addr: int, value: int) -> _Req:
    data = struct.pack(">HH", addr, value)
    return _Req(func, data, lambda p, d=data: p == d, f"write(f{func}) {addr}={value}")


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, owner: "C2000Transport"):
        self.owner = owner

    def datagram_received(self, data, addr):
        self.owner._on_datagram(data, addr)

    def error_received(self, exc):
        self.owner._log.debug("UDP error: %s", exc)

    def connection_lost(self, exc):
        fut = self.owner._closed
        if fut is not None and not fut.done():
            fut.set_result(None)


class C2000Transport:
    """Сериализованный обмен Modbus-RTU поверх UDP-обёртки C2000-Ethernet.

    * Один сокет, привязанный к local_port (С2000-Ethernet шлёт ответы на фиксированный порт).
    * Ровно один запрос «в полёте»; остальные ждут в очереди (приоритет: 0 – команды,
      1 – события, 2 – плановый опрос).
    * Ответ принимается только если совпали: IP источника, заголовок, длина, CRC, адрес,
      функция и ФОРМА (длина данных/эхо). Всё остальное – «unmatched» и не попадает в данные.
    * После таймаута включается «карантин»: запоздавшие ответы отбрасываются, пока линия
      не успокоится, затем запрос повторяется.
    """

    def __init__(self, host: str, port: int = 40002, *, slave_id: int = 1,
                 local_port: Optional[int] = None, timeout: float = 1.5, retries: int = 2,
                 busy_retries: int = 5, quarantine: float = 0.4, gap: float = 0.02,
                 reuse_port: bool = False):
        self.host, self.port, self.slave_id = host, port, slave_id
        self.local_port = port if local_port is None else local_port
        self.timeout, self.retries, self.busy_retries = timeout, retries, busy_retries
        self.quarantine, self.gap, self.reuse_port = quarantine, gap, reuse_port
        self._log = logging.getLogger("c2000pp.transport")
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._queue: "asyncio.PriorityQueue" = asyncio.PriorityQueue()
        self._worker: Optional[asyncio.Task] = None
        self._seq = itertools.count()
        self._counter = 0
        self._pending: Optional[tuple] = None      # (_Req, Future)
        self._quarantine_until = 0.0
        self._last_rx_counter: Optional[int] = None
        self.last_ok: float = 0.0                  # monotonic последнего валидного ответа
        self.on_unmatched: Optional[Callable[[Frame, str], None]] = None
        #: tap(direction, wall_time, data, addr) – «прослушка» всех датаграмм (tx/rx) для отладки
        self.tap: Optional[Callable[[str, float, bytes, tuple], None]] = None
        self._closed: Optional[asyncio.Future] = None
        self._hb_since = 0                         # heartbeat'ов конвертера с прошлого кадра
        self._t_tx = 0.0
        self.rtts: "collections.deque[float]" = collections.deque(maxlen=500)   # секунды
        self.stats = dict(tx=0, rx_ok=0, timeouts=0, bad_frames=0, foreign_ip=0, heartbeats=0,
                          other_frames=0, unmatched=0, lost_by_counter=0, exceptions=0,
                          quarantined=0)

    def rtt_stats(self) -> Dict[str, float]:
        """Время «запрос -> валидный ответ» по последним ответам, мс."""
        r = sorted(self.rtts)
        if not r:
            return {}
        return dict(n=len(r), min=r[0] * 1e3, avg=sum(r) / len(r) * 1e3,
                    p95=r[min(len(r) - 1, int(len(r) * 0.95))] * 1e3, max=r[-1] * 1e3)

    # --- жизненный цикл -----------------------------------------------------
    async def start(self):
        if self._transport:
            return
        loop = asyncio.get_running_loop()
        kw = dict(local_addr=("0.0.0.0", self.local_port))
        if self.reuse_port:
            kw["reuse_port"] = True
        self._closed = loop.create_future()
        last: Optional[OSError] = None
        # Порт после close() освобождается не мгновенно (закрытие сокета – на следующей итерации
        # цикла), поэтому при перезагрузке интеграции пробуем занять его несколько раз.
        for _ in range(15):
            try:
                self._transport, _ = await loop.create_datagram_endpoint(
                    lambda: _Protocol(self), **kw)
                last = None
                break
            except OSError as e:
                last = e
                await asyncio.sleep(0.2)
        if last is not None:
            raise C2000Error(
                f"Не удалось занять UDP-порт {self.local_port}: {last}. Скорее всего порт держит "
                f"другой процесс (второй экземпляр интеграции, HUB-C2000PP, SCADA)."
            ) from last
        self._worker = asyncio.create_task(self._run(), name="c2000-worker")

    async def stop(self):
        if self._worker:
            self._worker.cancel()
            await asyncio.gather(self._worker, return_exceptions=True)
            self._worker = None
        while not self._queue.empty():
            _, _, _, fut = self._queue.get_nowait()
            if not fut.done():
                fut.set_exception(C2000NotConnected("клиент остановлен"))
        if self._transport:
            self._transport.close()
            self._transport = None
            if self._closed is not None:       # ждём реального закрытия сокета (порт свободен)
                try:
                    await asyncio.wait_for(self._closed, 2.0)
                except asyncio.TimeoutError:
                    pass

    @property
    def running(self) -> bool:
        return self._transport is not None

    # --- приём --------------------------------------------------------------
    def _on_datagram(self, data: bytes, addr):
        if self.tap:
            try:
                self.tap("rx", time.time(), data, addr)
            except Exception:                           # noqa
                self._log.exception("tap")
        if addr[0] != self.host:
            self.stats["foreign_ip"] += 1
            return
        if data[:1] != b"\x10":
            # Собственные служебные датаграммы конвертера (раз в ~10 с, 10 байт, напр.
            # ed 9c 22 01 48 69 01 bc 18 00). Они занимают номер в счётчике, но данных не несут.
            self.stats["other_frames"] += 1
            if len(data) == 10:
                self.stats["heartbeats"] += 1
            self._hb_since += 1
            return
        try:
            fr = parse_datagram(data)
        except ValueError as e:
            self.stats["bad_frames"] += 1
            self._log.debug("битый кадр (%s): %s", e, data.hex(" "))
            return
        if self._last_rx_counter is not None:
            gap = ((fr.counter - self._last_rx_counter - 1) & 0xFFFF) - self._hb_since
            if 0 < gap < 1000:     # счётчик конвертера (свой для каждого получателя) +1 на датаграмму
                self.stats["lost_by_counter"] += gap
        self._last_rx_counter = fr.counter
        self._hb_since = 0

        now = time.monotonic()
        if now < self._quarantine_until:
            self.stats["quarantined"] += 1
            self._log.debug("карантин: отброшен %s", data.hex(" "))
            return
        if self._pending is None:
            self._unmatched(fr, "нет ожидающего запроса")
            return
        req, fut = self._pending
        if fr.slave != self.slave_id:
            self._unmatched(fr, f"чужой адрес {fr.slave}")
        elif fr.func == req.func and req.validate(fr.payload):
            self._finish(fut, fr)
        elif fr.func == (req.func | 0x80) and len(fr.payload) == 1:
            self.stats["exceptions"] += 1
            self._finish(fut, fr)
        else:
            self._unmatched(fr, f"не соответствует запросу {req.label}")

    def _finish(self, fut: asyncio.Future, fr: Frame):
        self.stats["rx_ok"] += 1
        self.last_ok = time.monotonic()
        self.rtts.append(time.perf_counter() - self._t_tx)
        if not fut.done():
            fut.set_result(fr)

    def _unmatched(self, fr: Frame, why: str):
        self.stats["unmatched"] += 1
        self._log.debug("unmatched (%s): %s", why, fr.raw.hex(" "))
        if self.on_unmatched:
            try:
                self.on_unmatched(fr, why)
            except Exception:                          # noqa
                self._log.exception("on_unmatched")

    # --- очередь ------------------------------------------------------------
    async def request(self, req: _Req, priority: int = 2) -> bytes:
        """Вернуть payload ответа. Бросает ModbusException / C2000Timeout."""
        if not self._transport:
            raise C2000NotConnected("клиент не запущен")
        fut = asyncio.get_running_loop().create_future()
        await self._queue.put((priority, next(self._seq), req, fut))
        return await fut

    async def _run(self):
        while True:
            _, _, req, fut = await self._queue.get()
            if fut.done():
                continue
            try:
                fut.set_result(await self._execute(req))
            except asyncio.CancelledError:
                if not fut.done():
                    fut.set_exception(C2000NotConnected("клиент остановлен"))
                raise
            except Exception as e:                    # noqa
                if not fut.done():
                    fut.set_exception(e)
            await asyncio.sleep(self.gap)

    async def _execute(self, req: _Req) -> bytes:
        attempts, busy = 0, 0
        while True:
            try:
                fr = await self._exchange(req)
            except C2000Timeout:
                attempts += 1
                if attempts > self.retries:
                    raise
                continue
            if fr.is_exception:
                code = fr.payload[0]
                if code in (6, 15) and busy < self.busy_retries:   # «занято» / «данные ещё не получены»
                    busy += 1
                    await asyncio.sleep(0.3 * busy)
                    continue
                raise ModbusException(code, req.label)
            return fr.payload

    async def _exchange(self, req: _Req) -> Frame:
        loop = asyncio.get_running_loop()
        wait = self._quarantine_until - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)
        fut = loop.create_future()
        self._pending = (req, fut)
        self._counter = (self._counter + 1) & 0xFFFF
        pkt = wrap_request(build_adu(self.slave_id, req.func, req.data), self._counter)
        self._t_tx = time.perf_counter()
        self._transport.sendto(pkt, (self.host, self.port))
        self.stats["tx"] += 1
        if self.tap:
            try:
                self.tap("tx", time.time(), pkt, (self.host, self.port))
            except Exception:                           # noqa
                self._log.exception("tap")
        try:
            return await asyncio.wait_for(fut, self.timeout)
        except asyncio.TimeoutError:
            self.stats["timeouts"] += 1
            self._quarantine_until = time.monotonic() + self.quarantine
            raise C2000Timeout(f"нет ответа на {req.label}") from None
        finally:
            self._pending = None

    # --- операции Modbus ----------------------------------------------------
    async def read_holding(self, addr, qty, priority=2) -> List[int]:
        p = await self.request(_req_read_regs(3, addr, qty), priority)
        return list(struct.unpack(f">{qty}H", p[1:]))

    async def read_input(self, addr, qty, priority=2) -> List[int]:
        p = await self.request(_req_read_regs(4, addr, qty), priority)
        return list(struct.unpack(f">{qty}H", p[1:]))

    async def read_coils(self, addr, qty, priority=2) -> List[bool]:
        p = await self.request(_req_read_bits(1, addr, qty), priority)
        return [bool(p[1 + i // 8] >> (i % 8) & 1) for i in range(qty)]

    async def read_discrete(self, addr, qty, priority=2) -> List[bool]:
        p = await self.request(_req_read_bits(2, addr, qty), priority)
        return [bool(p[1 + i // 8] >> (i % 8) & 1) for i in range(qty)]

    async def write_register(self, addr, value, priority=0):
        await self.request(_req_write(6, addr, value), priority)

    async def write_coil(self, addr, on: bool, priority=0):
        await self.request(_req_write(5, addr, 0xFF00 if on else 0), priority)


# ----------------------------------------------------------------------------
#  Высокоуровневый клиент
# ----------------------------------------------------------------------------
Listener = Callable[[str, Any], None]


class C2000PP:
    """Клиент С2000-ПП: кэш зон + независимые опрос / команды / слушатель.

    Модель работы
    -------------
    * ``start()`` открывает сокет и запускает фоновые задачи:
        - опрос всех зон каждые ``poll_interval`` секунд (по расписанию, без дрейфа);
        - (опционально, ``use_events=True``) быстрый опрос журнала событий;
        - досрочный опрос, если по линии пришёл «чужой» валидный ответ.
    * Команды (``arm_zone`` и т.п.) идут в ту же очередь с высшим приоритетом, поэтому
      никогда не «сталкиваются» с опросом; после команды зона перечитывается.
    * Если зона не обновлялась дольше ``stale_timeout`` – её статус ``ZoneStatus.TIMEOUT``.
    * События для подписчиков (``add_listener``): ``"zones"`` (set изменённых номеров),
      ``"availability"`` (bool), ``"event"`` (PPEvent), ``"poll"`` (статистика цикла).
    """

    def __init__(self, host: str, port: int = 40002, *, slave_id: int = 1,
                 zones: Iterable[int] = (), poll_interval: float = 10.0,
                 stale_timeout: Optional[float] = None, group_size: int = 8,
                 use_events: bool = False, event_interval: float = 2.0,
                 refresh_on_foreign: bool = True, absent_retry: float = 60.0,
                 pending_timeout: float = 15.0, **transport_kw):
        self.t = C2000Transport(host, port, slave_id=slave_id, **transport_kw)
        self._log = logging.getLogger("c2000pp")
        self.poll_interval = poll_interval
        st = stale_timeout if stale_timeout else max(3 * poll_interval + 5, 30.0)
        if st <= poll_interval:        # таймаут устаревания обязан быть больше периода опроса
            self._log.warning("stale_timeout (%s) <= poll_interval (%s): увеличен", st, poll_interval)
            st = poll_interval * 2 + 1
        self.stale_timeout = st
        self.pending_timeout = pending_timeout
        self.last_poll_duration = 0.0
        self.group_size = max(1, min(group_size, 100))
        self.use_events, self.event_interval = use_events, event_interval
        self.refresh_on_foreign, self.absent_retry = refresh_on_foreign, absent_retry
        self.zones: Dict[int, ZoneData] = {}
        self.set_zones(zones)
        self._listeners: List[Listener] = []
        self._tasks: List[asyncio.Task] = []
        self._poll_lock = asyncio.Lock()
        self._wake = asyncio.Event()
        self._extra_refresh: Set[int] = set()
        self._last_foreign_refresh = 0.0
        self._absent_since: Dict[int, float] = {}
        self._available: Optional[bool] = None
        self.info: Dict[str, Any] = {}
        self.t.on_unmatched = self._on_unmatched

    # --- конфигурация / подписки -------------------------------------------
    def set_zones(self, zones: Iterable[int]):
        wanted = {int(z) for z in zones if 1 <= int(z) <= 512}
        for z in wanted:
            self.zones.setdefault(z, ZoneData(z))
        for z in list(self.zones):
            if z not in wanted:
                del self.zones[z]

    def add_listener(self, cb: Listener) -> Callable[[], None]:
        self._listeners.append(cb)
        return lambda: self._listeners.remove(cb) if cb in self._listeners else None

    def _emit(self, name: str, payload: Any = None):
        for cb in list(self._listeners):
            try:
                cb(name, payload)
            except Exception:                           # noqa
                self._log.exception("listener")

    # --- жизненный цикл -----------------------------------------------------
    async def start(self):
        await self.t.start()
        self._tasks = [asyncio.create_task(self._poll_loop(), name="c2000-poll"),
                       asyncio.create_task(self._watchdog_loop(), name="c2000-watchdog")]
        if self.use_events:
            self._tasks.append(asyncio.create_task(self._event_loop(), name="c2000-events"))

    async def stop(self):
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []
        await self.t.stop()

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *a):
        await self.stop()

    @property
    def available(self) -> bool:
        """Есть ли связь: валидный ответ получен не позже stale_timeout назад."""
        return bool(self.t.last_ok) and time.monotonic() - self.t.last_ok < self.stale_timeout

    # --- одиночные операции -------------------------------------------------
    async def read_device_info(self) -> Dict[str, Any]:
        r = await self.t.read_holding(REG_TYPE_VERSION, 2, priority=1)
        typ, ver = r
        self.info.update(type=typ, version=f"{ver // 100}.{ver % 100:02d}", version_raw=ver)
        try:
            bits = await self.t.read_discrete(DI_MODE, 4, priority=1)
            self.info.update(mode="master" if bits[0] else "slave", master_link=bits[1],
                             tamper=bits[2], power_fault=bits[3])
        except C2000Error as e:
            self._log.debug("статус ПП недоступен: %s", e)
        try:
            lim = await self.t.read_holding(REG_MAX_RELAYS, 7, priority=1)
            self.info.update(max_relays=lim[0], max_zones=lim[1], max_sections=lim[2],
                             max_events=lim[5])
        except C2000Error:
            pass
        return dict(self.info)

    async def read_zone(self, n: int) -> ZoneData:
        """Принудительно перечитать одну зону (в обход расписания)."""
        z = self.zones.setdefault(n, ZoneData(n))
        await self._read_group([n], priority=1)
        return z

    async def set_zone_state(self, zone: int, code: int):
        """Записать состояние зоны. Для взятия/снятия включается режим «ожидание подтверждения»:
        ``ZoneData.armed`` показывает целевое состояние, пока ПП не подтвердит его (обычно 1–3 с,
        у приборов с задержкой взятия дольше) или не истечёт ``pending_timeout``."""
        d = self.zones.get(zone)
        track = code in (STATE_ARMED, STATE_DISARMED) and d is not None
        if track:
            self._set_pending(d, code == STATE_ARMED)
        try:
            await self.t.write_register(REG_ZONE_STATE + zone - 1, code, priority=0)
        except Exception:
            if track:
                self._clear_pending(d)
            raise
        if track:
            self.request_refresh([zone], delays=(0.4, 1.0, 2.0, 3.0, 4.5, 6.5, 9.0, 12.0),
                                 only_pending=True)
        else:
            self.request_refresh([zone], delays=(1.0, 5.0))

    def _set_pending(self, d: ZoneData, target: bool):
        d.pending, d.pending_until = target, time.monotonic() + self.pending_timeout
        self._emit("zones", {d.number})

    def _clear_pending(self, d: ZoneData):
        if d.pending is not None:
            d.pending = None
            self._emit("zones", {d.number})

    async def arm_zone(self, zone: int):
        await self.set_zone_state(zone, STATE_ARMED)

    async def disarm_zone(self, zone: int):
        await self.set_zone_state(zone, STATE_DISARMED)

    async def set_armed(self, zone: int, armed: bool, wait: float = 0.0) -> bool:
        """Взять/снять зону и (если wait>0) дождаться подтверждения от ПП до ``wait`` секунд.
        Возвращает True, если реальное состояние стало целевым. Для ожидания клиент должен быть
        запущен через ``start()`` (фоновые перечитывания зоны после команды)."""
        await (self.arm_zone if armed else self.disarm_zone)(zone)
        end = time.monotonic() + wait
        while wait and time.monotonic() < end:
            if self.zones[zone].pending is None:
                break
            await asyncio.sleep(0.1)
        return self.zones[zone].armed_actual == armed

    async def set_section_state(self, section: int, code: int):
        await self.t.write_register(REG_SECTION_STATE + section - 1, code, priority=0)
        self.request_refresh(list(self.zones), delays=(1.0, 5.0))

    async def arm_section(self, section: int):
        await self.set_section_state(section, STATE_ARMED)

    async def disarm_section(self, section: int):
        await self.set_section_state(section, STATE_DISARMED)

    async def read_section(self, section: int) -> Tuple[int, int, str]:
        v = (await self.t.read_holding(REG_SECTION_STATE + section - 1, 1, priority=1))[0]
        code = resolve_state(v >> 8, v & 0xFF)
        return v >> 8, v & 0xFF, state_name(code)

    async def read_relays(self, first: int, count: int) -> List[bool]:
        return await self.t.read_coils(REG_COIL_RELAY + first - 1, count, priority=1)

    async def set_relay(self, relay: int, on: bool):
        await self.t.write_coil(REG_COIL_RELAY + relay - 1, on, priority=0)

    def request_refresh(self, zones: Iterable[int], delays: Iterable[float] = (0.0,),
                        only_pending: bool = False):
        """Запросить внеплановое перечитывание зон (через delays секунд).
        only_pending=True – читать только если зона всё ещё ждёт подтверждения команды."""
        loop = asyncio.get_running_loop()
        zs = [z for z in zones if z in self.zones]
        for d in delays:
            loop.call_later(d, self._queue_extra, zs, only_pending)

    def _queue_extra(self, zs: List[int], only_pending: bool = False):
        if only_pending:
            zs = [z for z in zs if z in self.zones and self.zones[z].pending is not None]
            if not zs:
                return
        self._extra_refresh.update(zs)
        self._wake.set()

    # --- чтение зон ---------------------------------------------------------
    def _groups(self, zones: List[int]) -> List[List[int]]:
        out: List[List[int]] = []
        for z in sorted(zones):
            if out and z == out[-1][-1] + 1 and len(out[-1]) < self.group_size:
                out[-1].append(z)
            else:
                out.append([z])
        return out

    async def _read_group(self, group: List[int], priority: int = 2) -> Set[int]:
        """Прочитать группу; при ошибке группы – разбить на одиночные запросы."""
        changed: Set[int] = set()
        try:
            regs = await self.t.read_holding(REG_ZONE_STATE + group[0] - 1, len(group), priority)
        except ModbusException as e:
            if len(group) > 1:
                for z in group:
                    changed |= await self._read_group([z], priority)
                return changed
            changed |= self._mark_error(group[0], ZoneStatus.NO_DATA, str(e))
            return changed
        except C2000Timeout as e:
            # нет связи с конвертером/ПП: пробрасываем наверх, poll_all прервёт цикл
            # (иначе при 512 зонах и выключенном ПП цикл длился бы минутами).
            for z in group:
                self._mark_error(z, None, str(e))
            raise
        for z, v in zip(group, regs):
            changed |= self._apply(z, v >> 8, v & 0xFF)
        return changed

    def _apply(self, z: int, hi: int, lo: int) -> Set[int]:
        d = self.zones.setdefault(z, ZoneData(z))
        code = resolve_state(hi, lo)
        before = (d.code, d.code2, d.status)
        d.code, d.code2, d.status, d.error = code, lo if code == hi else hi, ZoneStatus.OK, ""
        d.updated, d.updated_wall = time.monotonic(), time.time()
        self._absent_since.pop(z, None)
        if d.pending is not None:
            # подтверждение: достигли цели (для «взять» – 23/24) ИЛИ взятие провалилось (17)
            if d.armed_actual == d.pending or (d.pending and code == STATE_ARM_FAILED):
                d.pending = None
                before = before + ("pending",)     # заставит отправить изменение даже при том же code
        # 251 = «связь восстановлена»: ПП ещё не знает реальное состояние – перечитываем чуть позже
        if code == STATE_LINK_RESTORED and d.recheck < 30:
            d.recheck += 1
            self.request_refresh([z], delays=(2.0,))
        elif code != STATE_LINK_RESTORED:
            d.recheck = 0
        return {z} if before != (d.code, d.code2, d.status) else set()

    def _mark_error(self, z: int, status: Optional[str], err: str) -> Set[int]:
        d = self.zones.setdefault(z, ZoneData(z))
        before = d.status
        d.error = err
        if status == ZoneStatus.NO_DATA:
            d.status = ZoneStatus.NO_DATA
            self._absent_since[z] = time.monotonic()
        return {z} if before != d.status else set()

    async def poll_all(self, zones: Optional[Iterable[int]] = None, priority: int = 2) -> Set[int]:
        """Один цикл опроса. Возвращает номера зон, у которых что-то изменилось."""
        async with self._poll_lock:
            t_start = time.perf_counter()
            now = time.monotonic()
            targets = [z for z in (zones if zones is not None else self.zones) if z in self.zones]
            # зоны без данных не мешают групповым запросам: перечитываем их редко и по одной
            absent = [z for z in targets if self.zones[z].status == ZoneStatus.NO_DATA
                      and now - self._absent_since.get(z, 0) < self.absent_retry]
            live = [z for z in targets if z not in absent]
            changed: Set[int] = set()
            aborted = False
            for g in self._groups(live):
                try:
                    changed |= await self._read_group(g, priority)
                except C2000Timeout as e:
                    self._log.warning("опрос прерван (нет ответа): %s", e)
                    aborted = True
                    break
            changed |= self._check_stale()
            self.last_poll_duration = time.perf_counter() - t_start
            if self.last_poll_duration > self.poll_interval and not aborted:
                self._log.warning("цикл опроса %.2f с дольше периода %.2f с – увеличьте период "
                                  "или размер группы", self.last_poll_duration, self.poll_interval)
            self._emit("poll", dict(ok=self.available, changed=len(changed), aborted=aborted,
                                    duration=self.last_poll_duration))
            if changed:
                self._emit("zones", changed)
            self._update_availability()
            return changed

    def _check_stale(self) -> Set[int]:
        changed = set()
        now = time.monotonic()
        for z, d in self.zones.items():
            if d.status == ZoneStatus.OK and now - d.updated > self.stale_timeout:
                d.status, d.error = ZoneStatus.TIMEOUT, "данные не обновлялись"
                changed.add(z)
        return changed

    def _check_pending(self) -> Set[int]:
        """Команда не подтвердилась за pending_timeout – возвращаем реальное состояние."""
        out = set()
        now = time.monotonic()
        for z, d in self.zones.items():
            if d.pending is not None and now >= d.pending_until:
                d.pending = None
                out.add(z)
        return out

    def _update_availability(self):
        av = self.available
        if av != self._available:
            self._available = av
            self._emit("availability", av)

    # --- фоновые задачи -----------------------------------------------------
    async def _poll_loop(self):
        next_t = time.monotonic()
        while True:
            try:
                await self.poll_all()
            except asyncio.CancelledError:
                raise
            except Exception:                           # noqa
                self._log.exception("ошибка цикла опроса")
            next_t += self.poll_interval
            if next_t < time.monotonic():               # цикл затянулся – не копим «долг»
                next_t = time.monotonic() + 1.0
            while True:
                left = next_t - time.monotonic()
                if left <= 0:
                    break
                try:
                    await asyncio.wait_for(self._wake.wait(), left)
                except asyncio.TimeoutError:
                    break
                self._wake.clear()
                if self._extra_refresh:
                    zs, self._extra_refresh = sorted(self._extra_refresh), set()
                    try:
                        ch = await self.poll_all(zs, priority=1)
                    except Exception:                   # noqa
                        self._log.exception("внеплановый опрос")

    async def _watchdog_loop(self):
        while True:
            await asyncio.sleep(1.0)
            ch = self._check_stale() | self._check_pending()
            if ch:
                self._emit("zones", ch)
            self._update_availability()

    def _on_unmatched(self, fr: Frame, why: str):
        """Валидный кадр, который не ответ на наш запрос. С2000-Ethernet рассылает ответы на ВСЕ
        настроенные IP, поэтому сюда попадают ответы на запросы других клиентов.

        * Эхо записи (func 5/6) самоописывающее (адрес+значение) – разбираем точно: чужая команда
          взять/снять зону -> ждём подтверждения и быстро перечитываем именно эту зону.
        * Ответы на чтение не содержат адреса регистра – разобрать нельзя; считаем, что состояние
          могло измениться, и (не чаще раза в 3 с) перечитываем все зоны."""
        if not self.refresh_on_foreign or fr.func not in (1, 2, 3, 4, 5, 6, 15, 16):
            return
        if fr.func == 6 and len(fr.payload) == 4:
            addr, val = struct.unpack(">HH", fr.payload)
            if REG_ZONE_STATE <= addr < REG_ZONE_STATE + 512:
                z = addr - REG_ZONE_STATE + 1
                d = self.zones.get(z)
                if d is not None:
                    self._emit("foreign_command", dict(zone=z, code=val))
                    if val in (STATE_ARMED, STATE_DISARMED):
                        self._set_pending(d, val == STATE_ARMED)
                        self.request_refresh([z], delays=(0.4, 1.0, 2.0, 3.0, 4.5, 6.5, 9.0, 12.0),
                                             only_pending=True)
                    else:
                        self.request_refresh([z], delays=(1.0, 5.0))
                return
        now = time.monotonic()
        if now - self._last_foreign_refresh < 3.0:
            return
        self._last_foreign_refresh = now
        self._emit("foreign", fr)
        self._queue_extra(list(self.zones))

    async def _event_loop(self):
        """Журнал событий ПП. ВНИМАНИЕ: чтение журнала разрушающее – если событиями
        пользуется ещё кто-то (HUB, SCADA), включайте только в одном месте."""
        while True:
            await asyncio.sleep(self.event_interval)
            try:
                for _ in range(20):
                    cnt = (await self.t.read_holding(REG_UNREAD_EVENTS, 1, priority=1))[0]
                    if not cnt:
                        break
                    ev = await self.read_oldest_event()
                    if ev is None:
                        break
                    self._emit("event", ev)
                    if ev.zone and ev.zone in self.zones:
                        self.request_refresh([ev.zone])
            except asyncio.CancelledError:
                raise
            except C2000Error as e:
                self._log.debug("опрос событий: %s", e)

    async def read_oldest_event(self, mark_read: bool = True) -> Optional[PPEvent]:
        p = await self.t.request(_req_read_regs(3, REG_READ_OLDEST_EVENT, 14), priority=1)
        ev = parse_event(p)
        if ev and mark_read:
            await self.t.write_register(REG_MARK_EVENT_READ, ev.number, priority=1)
        return ev

    # --- удобное --------------------------------------------------------------
    def snapshot(self) -> Dict[int, Dict[str, Any]]:
        return {z: dict(code=d.code, name=d.name, status=d.status, age=d.age(), armed=d.armed,
                        armed_actual=d.armed_actual, pending=d.pending, error=d.error)
                for z, d in sorted(self.zones.items())}


def parse_zone_spec(spec: str) -> List[int]:
    """'1-10, 15, 20-22' -> [1..10, 15, 20, 21, 22]"""
    out: List[int] = []
    for part in re.split(r"[,\s;]+", spec.strip()):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return sorted({z for z in out if 1 <= z <= 512})


# ----------------------------------------------------------------------------
#  CLI:  python c2000pp.py 192.168.1.50 monitor --zones 1-20
# ----------------------------------------------------------------------------
async def _cli(argv: Optional[List[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="С2000-ПП через С2000-Ethernet (UDP)")
    ap.add_argument("host")
    ap.add_argument("cmd", choices=["info", "zones", "monitor", "arm", "disarm", "relay", "events"])
    ap.add_argument("arg", nargs="?", help="номер зоны / реле; для relay: <номер> on|off")
    ap.add_argument("arg2", nargs="?")
    ap.add_argument("--port", type=int, default=40002)
    ap.add_argument("--slave", type=int, default=1)
    ap.add_argument("--zones", default="1-16")
    ap.add_argument("--interval", type=float, default=10)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    zones = parse_zone_spec(a.zones)
    pp = C2000PP(a.host, a.port, slave_id=a.slave, zones=zones, poll_interval=a.interval,
                 use_events=(a.cmd == "events"))
    await pp.t.start()                      # без фонового опроса для разовых команд
    try:
        if a.cmd == "info":
            print(await pp.read_device_info())
        elif a.cmd == "zones":
            await pp.poll_all()
            for z, d in pp.snapshot().items():
                print(f"{z:4d}  {d['status']:8s} {d['code']:4d}  {d['name']}  {d['error']}")
        elif a.cmd in ("arm", "disarm"):
            z = int(a.arg)
            await (pp.arm_zone if a.cmd == "arm" else pp.disarm_zone)(z)
            await asyncio.sleep(1.0)
            print((await pp.read_zone(z)).name)
        elif a.cmd == "relay":
            await pp.set_relay(int(a.arg), a.arg2 == "on")
            print((await pp.read_relays(int(a.arg), 1))[0])
        elif a.cmd == "events":
            while True:
                ev = await pp.read_oldest_event()
                if not ev:
                    break
                print(ev)
        elif a.cmd == "monitor":
            pp.add_listener(lambda n, p: print(time.strftime("%H:%M:%S"), n, p)
                            if n != "poll" else None)
            await pp.start()
            while True:
                await asyncio.sleep(3600)
    finally:
        await pp.stop()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(_cli()))
    except KeyboardInterrupt:
        pass
