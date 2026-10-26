"""
Auto-Buy Sniper — Bitta faylga jamlangan to'liq Full-Stack + Worker ilova (`sniper_all_in_one.py`).
Serverga (Render, Railway, VPS yoki lokal kompyuterga) joylash maksimal darajada oson bo'lishi uchun:
- Backend API (FastAPI)
- Orqa fonda 24/7 ishlovchi Sniper Worker (`asyncio` background task sifatida bitta jarayonda)
- Web UI (Tailwind CSS SPA — `/` manzilda to'g'ridan-to'g'ri ochiladi)
- PaxtaGram Bot API (`https://paxta.online/bot<token>/<method>`) va standart REST API dual-mode adapteri
- Ma'lumotlar bazasi (PostgreSQL `asyncpg` + Redis `redis.asyncio`, yoki qo'shimcha bazasiz In-Memory auto-fallback)
hammasi SHU BITTA FAYL ichida jamlangan.

Ishga tushirish:
    pip install fastapi "uvicorn[standard]" httpx cryptography pydantic
    python3 sniper_all_in_one.py
    # Yoki Render Start Command:
    uvicorn sniper_all_in_one:app --host 0.0.0.0 --port ${PORT:-8000}
"""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, List, Optional

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Response,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

try:
    import asyncpg  # type: ignore
except ImportError:
    asyncpg = None

try:
    import redis.asyncio as aioredis  # type: ignore
except ImportError:
    aioredis = None

# ============================================================================
# 1. KONFIGURATSIYA VA LOGLASH
# ============================================================================
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("sniper")


def log_json(level: str, event: str, **kwargs: Any) -> None:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "event": event,
        **kwargs,
    }
    logger.info(json.dumps(payload, default=str))


@dataclass
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "memory://local")
    redis_url: str = os.getenv("REDIS_URL", "memory://local")
    jwt_secret: str = os.getenv("JWT_SECRET", "change-me-super-secret-jwt-key-2026")
    jwt_expire_minutes: int = int(os.getenv("JWT_EXPIRE_MINUTES", "1440"))
    master_key: str = os.getenv("MASTER_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
    external_api_base: str = os.getenv("EXTERNAL_API_BASE", "https://paxta.online")
    default_recipient_id: str = os.getenv("DEFAULT_RECIPIENT_ID", "5")
    poll_interval_ms: int = int(os.getenv("POLL_INTERVAL_MS", "250"))
    max_concurrent_buys: int = int(os.getenv("MAX_CONCURRENT_BUYS", "50"))
    enable_background_worker: bool = os.getenv("ENABLE_WORKER", "true").lower() in ("true", "1", "yes")


def get_settings() -> Settings:
    return Settings()


# ============================================================================
# 2. AES-GCM (256-BIT) SHIFRLASH VA JWT FUNKSIYALARI
# ============================================================================
COOKIE_NAME = "sniper_token"


def _resolve_master_key(raw_key: str | None = None) -> bytes:
    key_str = raw_key if raw_key is not None else get_settings().master_key
    try:
        decoded = base64.b64decode(key_str)
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass
    raw_bytes = key_str.encode("utf-8")
    return raw_bytes if len(raw_bytes) == 32 else hashlib.sha256(raw_bytes).digest()


def encrypt_api_key(api_key: str) -> bytes:
    aesgcm = AESGCM(_resolve_master_key())
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, api_key.encode("utf-8"), None)


def decrypt_api_key(encrypted_blob: bytes) -> str:
    if isinstance(encrypted_blob, memoryview):
        encrypted_blob = bytes(encrypted_blob)
    aesgcm = AESGCM(_resolve_master_key())
    return aesgcm.decrypt(encrypted_blob[:12], encrypted_blob[12:], None).decode("utf-8")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def create_jwt_token(user_id: str, email: str) -> str:
    settings = get_settings()
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": str(user_id),
        "email": email,
        "iat": now,
        "exp": now + settings.jwt_expire_minutes * 60,
    }
    seg1 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    seg2 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(
        settings.jwt_secret.encode("utf-8"),
        f"{seg1}.{seg2}".encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{seg1}.{seg2}.{_b64url_encode(sig)}"


def decode_jwt_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        expected_sig = hmac.new(
            settings.jwt_secret.encode("utf-8"),
            f"{h_b64}.{p_b64}".encode("ascii"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(expected_sig, _b64url_decode(s_b64)):
            raise ValueError("Invalid signature")
        payload = json.loads(_b64url_decode(p_b64).decode("utf-8"))
        if int(payload.get("exp", 0)) < int(time.time()):
            raise ValueError("Token expired")
        return payload
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token xatosi: {exc}")


# ============================================================================
# 3. MA'LUMOTLAR BAZASI VA REDIS QATLAMI (POSTGRESQL + IN-MEMORY AUTO-FALLBACK)
# ============================================================================
SCHEMA_SQL = """
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE,
  api_key_enc BYTEA NOT NULL,
  external_user_id TEXT,
  base_url TEXT DEFAULT 'https://paxta.online',
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS gifts (
  gift_id TEXT PRIMARY KEY,
  name TEXT,
  star_price INT NOT NULL,
  total_supply INT,
  remaining INT,
  image_url TEXT,
  updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS buy_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  min_stars INT NOT NULL,
  max_stars INT NOT NULL,
  qty_per_gift INT NOT NULL,
  gift_ids TEXT[],
  daily_budget_stars INT NOT NULL,
  priority INT DEFAULT 100,
  active BOOLEAN DEFAULT true,
  dry_run BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS orders (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id),
  rule_id UUID REFERENCES buy_rules(id) ON DELETE SET NULL,
  gift_id TEXT,
  qty_requested INT,
  qty_filled INT DEFAULT 0,
  stars_spent INT DEFAULT 0,
  status TEXT,
  latency_ms INT,
  error TEXT,
  idempotency_key TEXT UNIQUE,
  created_at TIMESTAMPTZ DEFAULT now()
);
"""


class InMemoryRecord(dict):
    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


class InMemoryAsyncPGPool:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self.users: dict[str, dict[str, Any]] = {}
        self.gifts: dict[str, dict[str, Any]] = {}
        self.buy_rules: dict[str, dict[str, Any]] = {}
        self.orders: dict[str, dict[str, Any]] = {}
        self.idempotency_index: dict[str, str] = {}

    async def fetchval(self, query: str, *args: Any) -> Any:
        row = await self.fetchrow(query, *args)
        return list(row.values())[0] if row else None

    async def fetch(self, query: str, *args: Any) -> list[InMemoryRecord]:
        q = " ".join(query.strip().split()).lower()
        async with self._lock:
            if "from buy_rules" in q and "between min_stars and max_stars" in q:
                star_price, gift_id = int(args[0]), str(args[1])
                matched = [
                    InMemoryRecord(r.copy())
                    for r in self.buy_rules.values()
                    if r.get("active", True)
                    and r["min_stars"] <= star_price <= r["max_stars"]
                    and (not r.get("gift_ids") or gift_id in r["gift_ids"])
                ]
                matched.sort(key=lambda r: (r.get("priority", 100), r.get("created_at", "")))
                return matched

            if "from buy_rules" in q and "where r.user_id = $1" in q:
                user_id = str(args[0])
                today = datetime.now(timezone.utc).date()
                res = []
                for r in self.buy_rules.values():
                    if str(r["user_id"]) == user_id:
                        spent = sum(
                            int(o.get("stars_spent", 0))
                            for o in self.orders.values()
                            if str(o.get("rule_id")) == str(r["id"])
                            and o.get("status") == "success"
                            and o["created_at"].date() == today
                        )
                        cp = r.copy()
                        cp["spent_today"] = spent
                        res.append(InMemoryRecord(cp))
                res.sort(key=lambda r: (r.get("priority", 100), r.get("created_at", "")))
                return res

            if "from gifts" in q:
                items = [InMemoryRecord(g.copy()) for g in self.gifts.values()]
                items.sort(key=lambda g: g.get("updated_at", datetime.now(timezone.utc)), reverse=True)
                return items

            if "from orders" in q:
                items = [InMemoryRecord(o.copy()) for o in self.orders.values()]
                if "where user_id = $1" in q and args:
                    uid = str(args[0])
                    items = [o for o in items if str(o.get("user_id")) == uid]
                items.sort(key=lambda o: o.get("created_at", datetime.now(timezone.utc)), reverse=True)
                return items
            return []

    async def fetchrow(self, query: str, *args: Any) -> InMemoryRecord | None:
        q = " ".join(query.strip().split()).lower()
        async with self._lock:
            if q.startswith("select 1"):
                return InMemoryRecord({"?column?": 1})

            if "insert into users" in q:
                email, api_key_enc, ext_id, base_url = args[0], args[1], args[2], args[3]
                for u in self.users.values():
                    if u["email"] == email:
                        u.update({"api_key_enc": api_key_enc, "external_user_id": ext_id, "base_url": base_url})
                        return InMemoryRecord(u.copy())
                uid = str(uuid.uuid4())
                u_obj = {
                    "id": uid,
                    "email": email,
                    "api_key_enc": api_key_enc,
                    "external_user_id": ext_id,
                    "base_url": base_url,
                    "created_at": datetime.now(timezone.utc),
                }
                self.users[uid] = u_obj
                return InMemoryRecord(u_obj.copy())

            if "from users where id = $1" in q:
                u = self.users.get(str(args[0]))
                return InMemoryRecord(u.copy()) if u else None

            if "update gifts set remaining = remaining -" in q:
                gift_id, qty = str(args[0]), int(args[1])
                g = self.gifts.get(gift_id)
                if not g or g["remaining"] < qty:
                    return None
                g["remaining"] -= qty
                g["updated_at"] = datetime.now(timezone.utc)
                return InMemoryRecord(g.copy())

            if "insert into gifts" in q:
                gift_id = str(args[0])
                g_obj = {
                    "gift_id": gift_id,
                    "name": str(args[1]),
                    "star_price": int(args[2]),
                    "total_supply": int(args[3]),
                    "remaining": int(args[4]),
                    "image_url": str(args[5] or ""),
                    "updated_at": datetime.now(timezone.utc),
                }
                self.gifts[gift_id] = g_obj
                return InMemoryRecord(g_obj.copy())

            if "from gifts where gift_id = $1" in q:
                g = self.gifts.get(str(args[0]))
                return InMemoryRecord(g.copy()) if g else None

            if "insert into buy_rules" in q:
                rid = str(uuid.uuid4())
                r_obj = {
                    "id": rid,
                    "user_id": str(args[0]),
                    "name": str(args[1]),
                    "min_stars": int(args[2]),
                    "max_stars": int(args[3]),
                    "qty_per_gift": int(args[4]),
                    "gift_ids": list(args[5]) if args[5] else None,
                    "daily_budget_stars": int(args[6]),
                    "priority": int(args[7]),
                    "active": bool(args[8]),
                    "dry_run": bool(args[9]),
                    "created_at": datetime.now(timezone.utc),
                    "spent_today": 0,
                }
                self.buy_rules[rid] = r_obj
                return InMemoryRecord(r_obj.copy())

            if "update buy_rules" in q:
                rid, uid = str(args[0]), str(args[1])
                rule = self.buy_rules.get(rid)
                if not rule or str(rule["user_id"]) != uid:
                    return None
                if "set active = $3" in q:
                    rule["active"] = bool(args[2])
                elif "set dry_run = $3" in q:
                    rule["dry_run"] = bool(args[2])
                return InMemoryRecord(rule.copy())

            if "delete from buy_rules" in q:
                rid, uid = str(args[0]), str(args[1])
                rule = self.buy_rules.get(rid)
                if not rule or str(rule["user_id"]) != uid:
                    return None
                return InMemoryRecord(self.buy_rules.pop(rid))

            if "sum(stars_spent)" in q and "from orders" in q:
                today = datetime.now(timezone.utc).date()
                rid = str(args[0])
                total = sum(
                    int(o.get("stars_spent", 0))
                    for o in self.orders.values()
                    if str(o.get("rule_id")) == rid
                    and o.get("status") == "success"
                    and o["created_at"].date() == today
                )
                return InMemoryRecord({"total_spent": total})

            if "from orders where idempotency_key = $1" in q:
                oid = self.idempotency_index.get(str(args[0]))
                return InMemoryRecord(self.orders[oid].copy()) if oid and oid in self.orders else None

            if "insert into orders" in q:
                oid = str(uuid.uuid4())
                ikey = str(args[8]) if len(args) > 8 and args[8] else None
                if ikey and ikey in self.idempotency_index:
                    return InMemoryRecord(self.orders[self.idempotency_index[ikey]].copy())
                o_obj = {
                    "id": oid,
                    "user_id": str(args[0]) if args[0] else None,
                    "rule_id": str(args[1]) if args[1] else None,
                    "gift_id": str(args[2]),
                    "qty_requested": int(args[3]),
                    "qty_filled": int(args[4]),
                    "stars_spent": int(args[5]),
                    "status": str(args[6]),
                    "latency_ms": int(args[7] or 0),
                    "idempotency_key": ikey,
                    "error": str(args[9]) if len(args) > 9 and args[9] else None,
                    "created_at": datetime.now(timezone.utc),
                }
                self.orders[oid] = o_obj
                if ikey:
                    self.idempotency_index[ikey] = oid
                return InMemoryRecord(o_obj.copy())
            return None


class InMemoryPubSub:
    def __init__(self, parent: "InMemoryRedis") -> None:
        self._parent = parent
        self._channels: set[str] = set()
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

    async def subscribe(self, *channels: str) -> None:
        for ch in channels:
            self._channels.add(ch)
            self._parent._subscribers.setdefault(ch, set()).add(self._queue)

    async def unsubscribe(self, *channels: str) -> None:
        for ch in (channels or list(self._channels)):
            self._channels.discard(ch)
            if ch in self._parent._subscribers:
                self._parent._subscribers[ch].discard(self._queue)

    async def get_message(self, ignore_subscribe_messages: bool = True, timeout: float = 0.5) -> dict[str, Any] | None:
        try:
            return await asyncio.wait_for(self._queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    async def close(self) -> None:
        await self.unsubscribe()


class InMemoryRedis:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._store: dict[str, tuple[str, float | None]] = {}
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = {}

    async def ping(self) -> bool:
        return True

    async def set(self, key: str, value: Any, ex: int | None = None, nx: bool = False) -> bool | None:
        async with self._lock:
            if key in self._store:
                _, exp = self._store[key]
                if exp is not None and time.monotonic() >= exp:
                    del self._store[key]
            if nx and key in self._store:
                return None
            self._store[key] = (str(value), (time.monotonic() + ex) if ex else None)
            return True

    async def publish(self, channel: str, message: str | dict[str, Any]) -> int:
        payload = json.dumps(message, default=str) if isinstance(message, dict) else str(message)
        queues = list(self._subscribers.get(channel, set()))
        for q in queues:
            await q.put({"type": "message", "channel": channel, "data": payload})
        return len(queues)

    def pubsub(self) -> InMemoryPubSub:
        return InMemoryPubSub(self)


_db_pool: Any = None
_redis_client: Any = None


async def init_db_and_redis() -> tuple[Any, Any]:
    global _db_pool, _redis_client
    settings = get_settings()
    if _db_pool is None:
        if asyncpg is not None and not settings.database_url.startswith("memory://"):
            try:
                _db_pool = await asyncpg.create_pool(dsn=settings.database_url, min_size=1, max_size=15)
                async with _db_pool.acquire() as conn:
                    await conn.execute(SCHEMA_SQL)
            except Exception:
                _db_pool = InMemoryAsyncPGPool()
        else:
            _db_pool = InMemoryAsyncPGPool()

    if _redis_client is None:
        if aioredis is not None and not settings.redis_url.startswith("memory://"):
            try:
                client = aioredis.from_url(settings.redis_url, decode_responses=True)
                await client.ping()
                _redis_client = client
            except Exception:
                _redis_client = InMemoryRedis()
        else:
            _redis_client = InMemoryRedis()

    return _db_pool, _redis_client


async def get_db() -> Any:
    if _db_pool is None:
        await init_db_and_redis()
    return _db_pool


async def get_redis() -> Any:
    if _redis_client is None:
        await init_db_and_redis()
    return _redis_client


# ============================================================================
# 4. PAXTAGRAM BOT API (`https://paxta.online/bot<token>/<method>`) ADAPTERI
# ============================================================================
def is_bot_api_mode(base_url: str, api_key: str) -> bool:
    clean_url = base_url.lower().rstrip("/")
    if "paxta.online" in clean_url or clean_url.endswith("/bot"):
        return True
    if ":" in api_key and not clean_url.startswith("http://mock-external"):
        return True
    return False


def build_bot_method_url(base_url: str, token: str, method: str) -> str:
    base = base_url.rstrip("/")
    clean_token = token.strip()
    if clean_token.startswith("bot"):
        clean_token = clean_token[3:]
    return f"{base}/bot{clean_token}/{method}"


def normalize_gift_object(raw: dict[str, Any]) -> dict[str, Any]:
    gift_id = str(raw.get("gift_id") or raw.get("id") or "")
    star_price = int(raw.get("star_price") if raw.get("star_price") is not None else raw.get("star_count", 0))
    total_raw = raw.get("total_supply") if raw.get("total_supply") is not None else raw.get("total_count")
    rem_raw = raw.get("remaining") if raw.get("remaining") is not None else raw.get("remaining_count")
    total_supply = int(total_raw) if total_raw is not None else 1000
    remaining = int(rem_raw) if rem_raw is not None else total_supply
    sticker = raw.get("sticker") or {}
    emoji = sticker.get("emoji") or raw.get("emoji") or "🎁"
    name = str(raw.get("name") or raw.get("title") or f"PaxtaGift {emoji} #{gift_id}")
    image_url = str(raw.get("image_url") or sticker.get("thumbnail_url") or "")
    return {
        "gift_id": gift_id,
        "name": name,
        "star_price": star_price,
        "total_supply": total_supply,
        "remaining": remaining,
        "image_url": image_url,
    }


async def fetch_external_gifts(client: httpx.AsyncClient, base_url: str, api_key: str = "") -> list[dict[str, Any]]:
    if is_bot_api_mode(base_url, api_key) and api_key:
        resp = await client.get(build_bot_method_url(base_url, api_key, "getAvailableGifts"))
        resp.raise_for_status()
        payload = resp.json()
        if isinstance(payload, dict) and payload.get("ok") is True:
            res = payload.get("result", {})
            raw_list = res.get("gifts", []) if isinstance(res, dict) else res
            return [normalize_gift_object(item) for item in raw_list if isinstance(item, dict)]

    resp = await client.get(f"{base_url.rstrip('/')}/gifts")
    resp.raise_for_status()
    data = resp.json()
    raw_list = data.get("gifts", []) if isinstance(data, dict) else data
    return [normalize_gift_object(item) for item in raw_list if isinstance(item, dict)]


async def execute_external_buy(
    client: httpx.AsyncClient,
    *,
    base_url: str,
    api_key: str,
    gift_id: str,
    qty: int,
    idempotency_key: str,
    recipient_id: str | int | None = None,
) -> tuple[int, dict[str, Any]]:
    if is_bot_api_mode(base_url, api_key) and api_key:
        url = build_bot_method_url(base_url, api_key, "sendGift")
        target_uid: str | int = recipient_id or get_settings().default_recipient_id or 5
        filled = 0
        for i in range(qty):
            resp = await client.post(
                url,
                json={"gift_id": gift_id, "user_id": target_uid},
                headers={"Idempotency-Key": f"{idempotency_key}-{i}"},
            )
            body = resp.json() if resp.content else {}
            if resp.status_code == 200 and body.get("ok") is True:
                filled += 1
                continue
            desc = str(body.get("description") or f"HTTP {resp.status_code}")
            if resp.status_code == 429 or body.get("error_code") == 429:
                return 429, {"status": "rate_limited", "qty_filled": filled, "error": desc}
            return 200, {
                "status": "success" if filled > 0 else "sold_out",
                "qty_filled": filled,
                "error": None if filled > 0 else desc,
            }
        return 200, {"status": "success", "qty_filled": filled, "error": None}

    resp = await client.post(
        f"{base_url.rstrip('/')}/buy",
        json={"gift_id": gift_id, "qty": qty, "idempotency_key": idempotency_key},
        headers={"X-API-Key": api_key, "Idempotency-Key": idempotency_key},
    )
    return resp.status_code, (resp.json() if resp.content else {})


# ============================================================================
# 5. SNIPER WORKER (ORQA FONDA 24/7 ISHLOVCHI ASINXRON DVIGATEL)
# ============================================================================
class SniperWorker:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._stop_event = asyncio.Event()
        self._known_gifts_remaining: dict[str, int] = {}
        self._http_client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        limits = httpx.Limits(max_connections=200, max_keepalive_connections=100, keepalive_expiry=60.0)
        try:
            self._http_client = httpx.AsyncClient(http2=True, limits=limits, timeout=4.0)
        except Exception:
            self._http_client = httpx.AsyncClient(limits=limits, timeout=4.0)

        backoff = 0.25
        poll_sec = max(0.1, self.settings.poll_interval_ms / 1000.0)
        log_json("info", "background_sniper_worker_started", poll_interval_ms=self.settings.poll_interval_ms)

        while not self._stop_event.is_set():
            try:
                await self.poll_once()
                backoff = 0.25
            except Exception:
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2.0, 10.0)
            await asyncio.sleep(poll_sec)

    async def stop(self) -> None:
        self._stop_event.set()
        if self._http_client:
            await self._http_client.aclose()

    async def poll_once(self) -> None:
        db = await get_db()
        redis = await get_redis()
        if not hasattr(db, "users") or not db.users:
            return
        first_user = next(iter(db.users.values()))
        api_key = decrypt_api_key(first_user["api_key_enc"])
        base_url = str(first_user.get("base_url") or self.settings.external_api_base)

        assert self._http_client is not None
        gifts = await fetch_external_gifts(self._http_client, base_url=base_url, api_key=api_key)
        for gift in gifts:
            gid = str(gift["gift_id"])
            rem = int(gift.get("remaining", 0))
            if gid not in self._known_gifts_remaining or self._known_gifts_remaining[gid] != rem:
                self._known_gifts_remaining[gid] = rem
                await db.fetchrow(
                    """
                    INSERT INTO gifts (gift_id, name, star_price, total_supply, remaining, image_url)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    ON CONFLICT (gift_id) DO UPDATE SET remaining = EXCLUDED.remaining, updated_at = now()
                    RETURNING *
                    """,
                    gid,
                    gift["name"],
                    gift["star_price"],
                    gift["total_supply"],
                    rem,
                    gift["image_url"],
                )
                await redis.publish("ws:gifts", {"event": "gift.new", **gift})
                if rem > 0:
                    rules = await db.fetch(
                        """
                        SELECT * FROM buy_rules
                        WHERE active = true
                          AND $1 BETWEEN min_stars AND max_stars
                          AND (gift_ids IS NULL OR $2 = ANY(gift_ids))
                        ORDER BY priority ASC
                        """,
                        int(gift["star_price"]),
                        gid,
                    )
                    for rule in rules:
                        asyncio.create_task(self.try_buy(dict(rule), gift, api_key, base_url))

    async def try_buy(self, rule: dict[str, Any], gift: dict[str, Any], api_key: str, base_url: str) -> None:
        db = await get_db()
        redis = await get_redis()
        rule_id, user_id, gift_id = str(rule["id"]), str(rule["user_id"]), str(gift["gift_id"])
        qty, star_price = int(rule["qty_per_gift"]), int(gift["star_price"])

        if not await redis.set(f"sniped:{rule_id}:{gift_id}", "1", ex=3600, nx=True):
            return

        spent_row = await db.fetchrow(
            "SELECT COALESCE(SUM(stars_spent), 0) AS total_spent FROM orders WHERE rule_id = $1 AND status = 'success'",
            rule_id,
        )
        spent_today = int(spent_row["total_spent"]) if spent_row else 0
        budget = int(rule.get("daily_budget_stars") or 0)
        ikey = f"snipe-{rule_id}-{gift_id}"

        if budget > 0 and (spent_today + qty * star_price) > budget:
            order = await db.fetchrow(
                "INSERT INTO orders (user_id, rule_id, gift_id, qty_requested, qty_filled, stars_spent, status, latency_ms, idempotency_key, error) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *",
                user_id, rule_id, gift_id, qty, 0, 0, "skipped_budget", 0, ikey, "Kunlik limit oshdi",
            )
            await redis.publish("ws:orders", {"event": "order.result", **dict(order)})
            return

        if rule.get("dry_run", True):
            order = await db.fetchrow(
                "INSERT INTO orders (user_id, rule_id, gift_id, qty_requested, qty_filled, stars_spent, status, latency_ms, idempotency_key, error) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *",
                user_id, rule_id, gift_id, qty, 0, 0, "dry_run", 1, ikey, None,
            )
            await redis.publish("ws:orders", {"event": "order.result", **dict(order)})
            return

        t0 = time.perf_counter()
        assert self._http_client is not None
        code, data = await execute_external_buy(
            self._http_client,
            base_url=base_url,
            api_key=api_key,
            gift_id=gift_id,
            qty=qty,
            idempotency_key=ikey,
        )
        latency_ms = max(1, int((time.perf_counter() - t0) * 1000))
        st = str(data.get("status", "success" if code == 200 else "error"))
        filled = int(data.get("qty_filled", qty if st == "success" else 0))
        order = await db.fetchrow(
            "INSERT INTO orders (user_id, rule_id, gift_id, qty_requested, qty_filled, stars_spent, status, latency_ms, idempotency_key, error) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *",
            user_id, rule_id, gift_id, qty, filled, filled * star_price, st, latency_ms, ikey, data.get("error"),
        )
        await redis.publish("ws:orders", {"event": "order.result", **dict(order)})


# ============================================================================
# 6. PYDANTIC MODELLAR VA FASTAPI ENDPOINTLAR
# ============================================================================
class LoginRequest(BaseModel):
    api_key: str = Field(..., min_length=4)
    base_url: str = Field(default="https://paxta.online")
    email: Optional[str] = None


class MarketBuyRequest(BaseModel):
    gift_id: str
    qty: int = Field(..., gt=0)
    idempotency_key: str


class RuleCreateRequest(BaseModel):
    name: str
    min_stars: int = 0
    max_stars: int = 5000
    qty_per_gift: int = 1
    gift_ids: Optional[List[str]] = None
    daily_budget_stars: int = 10000
    priority: int = 10
    active: bool = True
    dry_run: bool = True


app = FastAPI(title="Auto-Buy Sniper All-in-One (PaxtaGram + Web UI)")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_worker_instance = SniperWorker()

SEED_GIFTS = [
    {"gift_id": "paxta_golden_choynak", "name": "Paxta Oltin Choynak 🌸", "star_price": 350, "total_supply": 100, "remaining": 45, "image_url": ""},
    {"gift_id": "paxta_atlas_doppi", "name": "Buxoro Zar Do'ppi ⭐", "star_price": 750, "total_supply": 50, "remaining": 12, "image_url": ""},
    {"gift_id": "paxta_registon_crown", "name": "Registon Emerald Crown 👑", "star_price": 2000, "total_supply": 20, "remaining": 4, "image_url": ""},
]


@app.on_event("startup")
async def startup_event() -> None:
    db, _ = await init_db_and_redis()
    existing = await db.fetch("SELECT * FROM gifts")
    if not existing:
        for g in SEED_GIFTS:
            await db.fetchrow(
                "INSERT INTO gifts (gift_id, name, star_price, total_supply, remaining, image_url) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *",
                g["gift_id"], g["name"], g["star_price"], g["total_supply"], g["remaining"], g["image_url"],
            )
    if get_settings().enable_background_worker:
        asyncio.create_task(_worker_instance.start())


async def get_current_user(
    sniper_token: str | None = Cookie(default=None),
    authorization: str | None = Header(default=None),
    db: Any = Depends(get_db),
) -> dict[str, Any]:
    token = sniper_token
    if not token and authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Avval Login qiling")
    payload = decode_jwt_token(token)
    user = await db.fetchrow("SELECT * FROM users WHERE id = $1", payload["sub"])
    if not user:
        raise HTTPException(status_code=401, detail="Foydalanuvchi topilmadi")
    return dict(user)


@app.post("/auth/login")
async def login_endpoint(body: LoginRequest, response: Response, db: Any = Depends(get_db)) -> dict[str, Any]:
    key_hash = hashlib.sha256(body.api_key.encode("utf-8")).hexdigest()[:10]
    email = body.email or f"bot_{key_hash}@paxta.online"
    ext_id = f"paxta_{key_hash}"
    user = await db.fetchrow(
        "INSERT INTO users (email, api_key_enc, external_user_id, base_url) VALUES ($1,$2,$3,$4) ON CONFLICT (email) DO UPDATE SET api_key_enc = EXCLUDED.api_key_enc, base_url = EXCLUDED.base_url RETURNING *",
        email, encrypt_api_key(body.api_key), ext_id, body.base_url,
    )
    token = create_jwt_token(str(user["id"]), str(user["email"]))
    response.set_cookie(key=COOKIE_NAME, value=token, httponly=True, samesite="lax", path="/")
    return {"status": "ok", "token": token, "user": {"id": str(user["id"]), "email": email, "base_url": body.base_url}}


@app.get("/auth/me")
async def me_endpoint(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    return {"id": str(user["id"]), "email": user["email"], "base_url": user.get("base_url", "https://paxta.online")}


@app.get("/market/gifts")
async def get_gifts_endpoint(user: dict[str, Any] = Depends(get_current_user), db: Any = Depends(get_db)) -> list[dict[str, Any]]:
    rows = await db.fetch("SELECT * FROM gifts")
    return [dict(r) for r in rows]


@app.post("/market/buy")
async def buy_gift_endpoint(
    body: MarketBuyRequest,
    user: dict[str, Any] = Depends(get_current_user),
    db: Any = Depends(get_db),
    redis: Any = Depends(get_redis),
) -> dict[str, Any]:
    t0 = time.perf_counter()
    existing = await db.fetchrow("SELECT * FROM orders WHERE idempotency_key = $1", body.idempotency_key)
    if existing:
        return dict(existing)
    gift = await db.fetchrow("SELECT * FROM gifts WHERE gift_id = $1", body.gift_id)
    if not gift:
        raise HTTPException(status_code=404, detail="Gift topilmadi")
    updated = await db.fetchrow(
        "UPDATE gifts SET remaining = remaining - $2 WHERE gift_id = $1 AND remaining >= $2 RETURNING *",
        body.gift_id, body.qty,
    )
    latency_ms = max(1, int((time.perf_counter() - t0) * 1000))
    if not updated:
        order = await db.fetchrow(
            "INSERT INTO orders (user_id, rule_id, gift_id, qty_requested, qty_filled, stars_spent, status, latency_ms, idempotency_key, error) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *",
            str(user["id"]), None, body.gift_id, body.qty, 0, 0, "sold_out", latency_ms, body.idempotency_key, "Sold out",
        )
    else:
        spent = body.qty * int(gift["star_price"])
        order = await db.fetchrow(
            "INSERT INTO orders (user_id, rule_id, gift_id, qty_requested, qty_filled, stars_spent, status, latency_ms, idempotency_key, error) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *",
            str(user["id"]), None, body.gift_id, body.qty, body.qty, spent, "success", latency_ms, body.idempotency_key, None,
        )
        await redis.publish("ws:gifts", {"event": "gift.stock_update", "gift_id": body.gift_id, "remaining": int(updated["remaining"])})
    await redis.publish("ws:orders", {"event": "order.result", **dict(order)})
    return dict(order)


@app.get("/rules")
async def list_rules_endpoint(user: dict[str, Any] = Depends(get_current_user), db: Any = Depends(get_db)) -> list[dict[str, Any]]:
    rows = await db.fetch("SELECT * FROM buy_rules r WHERE r.user_id = $1", str(user["id"]))
    return [dict(r) for r in rows]


@app.post("/rules")
async def create_rule_endpoint(body: RuleCreateRequest, user: dict[str, Any] = Depends(get_current_user), db: Any = Depends(get_db)) -> dict[str, Any]:
    row = await db.fetchrow(
        "INSERT INTO buy_rules (user_id, name, min_stars, max_stars, qty_per_gift, gift_ids, daily_budget_stars, priority, active, dry_run) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *",
        str(user["id"]), body.name, body.min_stars, body.max_stars, body.qty_per_gift, body.gift_ids, body.daily_budget_stars, body.priority, body.active, body.dry_run,
    )
    return dict(row)


@app.post("/rules/{rule_id}/pause")
async def pause_rule_endpoint(rule_id: str, user: dict[str, Any] = Depends(get_current_user), db: Any = Depends(get_db)) -> dict[str, Any]:
    row = await db.fetchrow("UPDATE buy_rules SET active = $3 WHERE id = $1 AND user_id = $2 RETURNING *", rule_id, str(user["id"]), False)
    return dict(row) if row else {}


@app.post("/rules/{rule_id}/resume")
async def resume_rule_endpoint(rule_id: str, user: dict[str, Any] = Depends(get_current_user), db: Any = Depends(get_db)) -> dict[str, Any]:
    row = await db.fetchrow("UPDATE buy_rules SET active = $3 WHERE id = $1 AND user_id = $2 RETURNING *", rule_id, str(user["id"]), True)
    return dict(row) if row else {}


@app.post("/rules/{rule_id}/toggle-dry-run")
async def toggle_dry_run_endpoint(rule_id: str, dry_run: bool = Query(...), user: dict[str, Any] = Depends(get_current_user), db: Any = Depends(get_db)) -> dict[str, Any]:
    row = await db.fetchrow("UPDATE buy_rules SET dry_run = $3 WHERE id = $1 AND user_id = $2 RETURNING *", rule_id, str(user["id"]), dry_run)
    return dict(row) if row else {}


@app.delete("/rules/{rule_id}")
async def delete_rule_endpoint(rule_id: str, user: dict[str, Any] = Depends(get_current_user), db: Any = Depends(get_db)) -> dict[str, str]:
    await db.fetchrow("DELETE FROM buy_rules WHERE id = $1 AND user_id = $2 RETURNING *", rule_id, str(user["id"]))
    return {"status": "deleted"}


@app.get("/orders")
async def list_orders_endpoint(user: dict[str, Any] = Depends(get_current_user), db: Any = Depends(get_db)) -> list[dict[str, Any]]:
    rows = await db.fetch("SELECT * FROM orders WHERE user_id = $1", str(user["id"]))
    return [dict(r) for r in rows[:50]]


@app.get("/health")
async def health_endpoint() -> dict[str, str]:
    return {"status": "healthy", "mode": "all-in-one"}


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    redis = await get_redis()
    pubsub = redis.pubsub()
    await pubsub.subscribe("ws:orders", "ws:gifts")
    try:
        while True:
            msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=0.5)
            if msg and msg.get("data"):
                await websocket.send_text(str(msg["data"]))
            await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.close()


# ============================================================================
# 7. ICHKI WEB INTERFEYS (SINGLE-PAGE APP — `/` MANZILDA OCHILADI)
# ============================================================================
INDEX_HTML = """<!DOCTYPE html>
<html lang="uz" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Auto-Buy Sniper — PaxtaGram All-in-One</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen font-sans">
  <header class="border-b border-slate-800 bg-slate-900/90 sticky top-0 z-40">
    <div class="max-w-6xl mx-auto px-4 py-3.5 flex items-center justify-between">
      <div class="flex items-center gap-2.5">
        <span class="h-9 w-9 rounded-xl bg-amber-400 text-slate-950 font-black flex items-center justify-center text-lg">⚡</span>
        <span class="font-extrabold text-white text-lg">Auto-Buy Sniper</span>
        <span class="text-xs bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 px-2.5 py-0.5 rounded-full">PaxtaGram All-in-One</span>
      </div>
      <div id="userBadge" class="text-xs text-slate-400"></div>
    </div>
  </header>

  <main class="max-w-6xl mx-auto px-4 py-6 space-y-8">
    <!-- 1. LOGIN PANEL -->
    <section id="loginSection" class="max-w-md mx-auto bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
      <h2 class="text-xl font-bold text-white mb-1">PaxtaGram Bot Token ni ulash</h2>
      <p class="text-xs text-slate-400 mb-4">@PaxtaFather dan olingan token AES-GCM bilan shifrlanadi</p>
      <form id="loginForm" class="space-y-3">
        <div>
          <label class="block text-xs text-slate-300 mb-1">Bot Token (@PaxtaFather) *</label>
          <input id="apiKeyInput" type="password" required placeholder="123456:AbCdEfGhIjKlMnOpQrStUvWxYz0123456_-" class="w-full rounded-xl bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-white" />
        </div>
        <div>
          <label class="block text-xs text-slate-300 mb-1">Server Base URL *</label>
          <input id="baseUrlInput" type="url" required value="https://paxta.online" class="w-full rounded-xl bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-white" />
        </div>
        <button type="submit" class="w-full rounded-xl bg-amber-400 text-slate-950 font-bold py-2.5 text-sm hover:bg-amber-300">Ulash va Kirish</button>
      </form>
    </section>

    <!-- 2. DASHBOARD (MARKET + RULES + LOGS) -->
    <div id="dashboardSection" class="hidden space-y-8">
      <!-- Live Market -->
      <section class="bg-slate-900/80 border border-slate-800 rounded-2xl p-6">
        <div class="flex items-center justify-between mb-4">
          <h2 class="text-lg font-bold text-white">Live Gift Market</h2>
          <button onclick="loadDashboard()" class="text-xs bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-lg">Yangilash</button>
        </div>
        <div id="giftsGrid" class="grid grid-cols-1 sm:grid-cols-3 gap-4"></div>
      </section>

      <!-- Auto-Buy Rules -->
      <section class="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 space-y-4">
        <h2 class="text-lg font-bold text-white">Yangi Auto-Buy Qoidasi Qo'shish</h2>
        <form id="ruleForm" class="grid grid-cols-1 sm:grid-cols-6 gap-3 items-end">
          <div class="sm:col-span-2">
            <label class="block text-xs text-slate-400 mb-1">Qoida nomi</label>
            <input id="rName" required placeholder="Rare Gift Sniper" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-sm" />
          </div>
          <div>
            <label class="block text-xs text-slate-400 mb-1">Min ★</label>
            <input id="rMin" type="number" value="0" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-sm" />
          </div>
          <div>
            <label class="block text-xs text-slate-400 mb-1">Max ★</label>
            <input id="rMax" type="number" value="5000" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-sm" />
          </div>
          <div>
            <label class="block text-xs text-slate-400 mb-1">Qty / Gift</label>
            <input id="rQty" type="number" value="5" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-sm" />
          </div>
          <div>
            <label class="block text-xs text-slate-400 mb-1">Kunlik Limit ★</label>
            <input id="rBudget" type="number" value="25000" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-sm" />
          </div>
          <div class="sm:col-span-4 flex items-center gap-2 pt-2">
            <input id="rDry" type="checkbox" checked class="h-4 w-4 accent-amber-400" />
            <label for="rDry" class="text-xs text-slate-300">Dry-Run (faqat log yozish; haqiqiy xarid uchun belgini olib tashlang)</label>
          </div>
          <div class="sm:col-span-2 text-right">
            <button type="submit" class="w-full rounded-xl bg-amber-400 text-slate-950 font-bold py-2 text-sm hover:bg-amber-300">+ Qoidani Saqlash</button>
          </div>
        </form>

        <div class="overflow-x-auto pt-4">
          <table class="w-full text-left text-sm">
            <thead>
              <tr class="border-b border-slate-800 text-xs text-slate-400 uppercase">
                <th class="py-2">Nomi</th>
                <th class="py-2">Narx (★)</th>
                <th class="py-2">Qty</th>
                <th class="py-2">Kunlik Limit</th>
                <th class="py-2">Rejim</th>
                <th class="py-2 text-right">Amal</th>
              </tr>
            </thead>
            <tbody id="rulesTableBody" class="divide-y divide-slate-800/60"></tbody>
          </table>
        </div>
      </section>

      <!-- Activity Log -->
      <section class="bg-slate-900/80 border border-slate-800 rounded-2xl p-6">
        <h2 class="text-lg font-bold text-white mb-3">Real-Time Activity Log (Buyurtmalar)</h2>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead>
              <tr class="border-b border-slate-800 text-xs text-slate-400 uppercase">
                <th class="py-2">Vaqt</th>
                <th class="py-2">Gift ID</th>
                <th class="py-2">Holat</th>
                <th class="py-2">Qty</th>
                <th class="py-2">Sarf ★</th>
                <th class="py-2 text-right">Latency</th>
              </tr>
            </thead>
            <tbody id="ordersTableBody" class="divide-y divide-slate-800/60"></tbody>
          </table>
        </div>
      </section>
    </div>
  </main>

  <script>
    let authToken = localStorage.getItem("sniper_jwt") || "";

    async function api(path, opts = {}) {
      const headers = Object.assign({"Content-Type": "application/json"}, opts.headers || {});
      if (authToken) headers["Authorization"] = "Bearer " + authToken;
      const res = await fetch(path, Object.assign({}, opts, {headers, credentials: "include"}));
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    }

    document.getElementById("loginForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const api_key = document.getElementById("apiKeyInput").value;
      const base_url = document.getElementById("baseUrlInput").value;
      const data = await api("/auth/login", {method: "POST", body: JSON.stringify({api_key, base_url})});
      authToken = data.token;
      localStorage.setItem("sniper_jwt", authToken);
      await checkAuth();
    });

    document.getElementById("ruleForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      await api("/rules", {
        method: "POST",
        body: JSON.stringify({
          name: document.getElementById("rName").value,
          min_stars: Number(document.getElementById("rMin").value),
          max_stars: Number(document.getElementById("rMax").value),
          qty_per_gift: Number(document.getElementById("rQty").value),
          daily_budget_stars: Number(document.getElementById("rBudget").value),
          dry_run: document.getElementById("rDry").checked,
          priority: 1,
          active: true
        })
      });
      document.getElementById("rName").value = "";
      await loadDashboard();
    });

    async function manualBuy(gift_id) {
      await api("/market/buy", {
        method: "POST",
        body: JSON.stringify({gift_id, qty: 1, idempotency_key: "ui-" + Date.now()})
      });
      await loadDashboard();
    }

    async function deleteRule(id) {
      await api("/rules/" + id, {method: "DELETE"});
      await loadDashboard();
    }

    async function loadDashboard() {
      const [gifts, rules, orders] = await Promise.all([
        api("/market/gifts"),
        api("/rules"),
        api("/orders")
      ]);

      document.getElementById("giftsGrid").innerHTML = gifts.map(g => `
        <div class="rounded-xl border border-slate-800 bg-slate-950 p-4 flex flex-col justify-between">
          <div>
            <div class="flex justify-between items-center mb-2">
              <span class="text-xs font-bold text-amber-400 bg-amber-500/10 px-2.5 py-0.5 rounded-full">★ ${g.star_price}</span>
              <span class="text-xs text-slate-400">${g.remaining} / ${g.total_supply}</span>
            </div>
            <div class="font-bold text-white">${g.name}</div>
            <div class="text-xs text-slate-500 font-mono mb-3">${g.gift_id}</div>
          </div>
          <button onclick="manualBuy('${g.gift_id}')" ${g.remaining <= 0 ? 'disabled' : ''} class="w-full rounded-lg bg-amber-400 text-slate-950 font-bold py-1.5 text-xs hover:bg-amber-300 disabled:opacity-40">
            ${g.remaining <= 0 ? 'Sold Out' : 'Buy 1 Now'}
          </button>
        </div>
      `).join("");

      document.getElementById("rulesTableBody").innerHTML = rules.map(r => `
        <tr>
          <td class="py-2.5 font-semibold text-white">${r.name}</td>
          <td class="py-2.5 text-amber-400">★ ${r.min_stars} – ${r.max_stars}</td>
          <td class="py-2.5">${r.qty_per_gift} dona</td>
          <td class="py-2.5">★ ${r.daily_budget_stars}</td>
          <td class="py-2.5">
            <span class="text-xs px-2 py-0.5 rounded-full ${r.dry_run ? 'bg-amber-500/20 text-amber-300' : 'bg-emerald-500/20 text-emerald-300'}">
              ${r.dry_run ? 'DRY-RUN' : 'LIVE BUY'}
            </span>
          </td>
          <td class="py-2.5 text-right">
            <button onclick="deleteRule('${r.id}')" class="text-xs text-rose-400 hover:underline">O'chirish</button>
          </td>
        </tr>
      `).join("");

      document.getElementById("ordersTableBody").innerHTML = orders.map(o => `
        <tr>
          <td class="py-2 text-xs text-slate-400 font-mono">${new Date(o.created_at).toLocaleTimeString()}</td>
          <td class="py-2 font-mono text-xs text-amber-300">${o.gift_id}</td>
          <td class="py-2"><span class="text-xs font-semibold px-2 py-0.5 rounded-full bg-slate-800">${o.status}</span></td>
          <td class="py-2">${o.qty_filled}/${o.qty_requested}</td>
          <td class="py-2 text-amber-400">★ ${o.stars_spent}</td>
          <td class="py-2 text-right font-mono text-xs">${o.latency_ms || 0} ms</td>
        </tr>
      `).join("");
    }

    async function checkAuth() {
      try {
        const me = await api("/auth/me");
        document.getElementById("userBadge").textContent = me.email + " (" + me.base_url + ")";
        document.getElementById("loginSection").classList.add("hidden");
        document.getElementById("dashboardSection").classList.remove("hidden");
        await loadDashboard();
        const proto = location.protocol === "https:" ? "wss:" : "ws:";
        const ws = new WebSocket(proto + "//" + location.host + "/ws");
        ws.onmessage = () => loadDashboard();
      } catch {
        document.getElementById("loginSection").classList.remove("hidden");
        document.getElementById("dashboardSection").classList.add("hidden");
      }
    }
    checkAuth();
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def serve_spa_ui() -> HTMLResponse:
    return HTMLResponse(INDEX_HTML)


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)