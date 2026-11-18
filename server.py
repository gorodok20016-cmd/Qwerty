#!/usr/bin/env python3
"""Albertgram WSGI API. Run with Gunicorn behind Caddy."""
import base64
from contextlib import closing
import hashlib
import hmac
from http import HTTPStatus
import json
import logging
import os
from pathlib import Path
import re
import secrets
import sqlite3
import struct
import time
from urllib.parse import parse_qs, quote, urlencode, urlsplit

DB_PATH = Path(os.environ.get("ALBERTGRAM_DB", str(Path(__file__).with_name("albertgram-v1.sqlite3"))))
ADMIN_INVITE = os.environ.get("ALBERTGRAM_ADMIN_INVITE", "")
USERNAME = re.compile(r"[a-z0-9_]{3,32}")
CODE = re.compile(r"[0-9]{6}")
MAX_BODY = 64 * 1024
SESSION_TTL = 30 * 86400
SCHEMA = """
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
    password TEXT, secret TEXT, enrollment TEXT, pending_until INTEGER,
    confirmed INTEGER NOT NULL DEFAULT 0, last_code INTEGER NOT NULL DEFAULT -1,
    admin INTEGER NOT NULL DEFAULT 0, verified INTEGER NOT NULL DEFAULT 0,
    banned INTEGER NOT NULL DEFAULT 0, bot INTEGER NOT NULL DEFAULT 0,
    bot_token TEXT UNIQUE, owner INTEGER REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
    expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY, title TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL, direct_key TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS members (
    chat INTEGER REFERENCES chats(id), user_id INTEGER REFERENCES users(id),
    PRIMARY KEY(chat, user_id)
);
CREATE INDEX IF NOT EXISTS members_by_user ON members(user_id, chat);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, chat INTEGER NOT NULL REFERENCES chats(id),
    sender INTEGER NOT NULL REFERENCES users(id), text TEXT NOT NULL,
    ts INTEGER NOT NULL, edited INTEGER NOT NULL DEFAULT 0, markup TEXT
);
CREATE INDEX IF NOT EXISTS messages_by_chat ON messages(chat, id);
CREATE TABLE IF NOT EXISTS updates (
    id INTEGER PRIMARY KEY AUTOINCREMENT, bot INTEGER NOT NULL REFERENCES users(id), payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS updates_by_bot ON updates(bot, id);
CREATE TABLE IF NOT EXISTS revisions (id INTEGER PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS limits (
    scope TEXT NOT NULL, item TEXT NOT NULL, bucket INTEGER NOT NULL, hits INTEGER NOT NULL,
    PRIMARY KEY(scope, item, bucket)
);
INSERT OR IGNORE INTO revisions VALUES (1, 0);
INSERT OR IGNORE INTO users(username, name, confirmed, verified, bot)
VALUES ('papochka', 'Papochka', 1, 1, 1);
"""


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def connect():
    db = sqlite3.connect(DB_PATH, timeout=8)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    old_mask = os.umask(0o077)
    try:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        with closing(connect()) as db:
            db.executescript(SCHEMA)
    finally:
        os.umask(old_mask)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def password_hash(password):
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=1, maxmem=64 * 1024 * 1024)
    return salt.hex() + ":" + key.hex()


def password_ok(password, saved):
    # Use an equivalent KDF when the account does not exist.
    salt, expected = (saved or "0" * 32 + ":" + "0" * 128).split(":")
    key = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=32768, r=8, p=1, maxmem=64 * 1024 * 1024)
    return saved is not None and hmac.compare_digest(key.hex(), expected)


def totp(secret, step):
    raw = base64.b32decode(secret + "=" * (-len(secret) % 8))
    signature = hmac.digest(raw, struct.pack(">Q", step), "sha1")
    offset = signature[-1] & 15
    value = int.from_bytes(signature[offset:offset + 4], "big") & 0x7fffffff
    return f"{value % 1000000:06d}"


def otp_step(user, code):
    step = int(time.time()) // 30
    if not isinstance(code, str) or not CODE.fullmatch(code):
        return None
    for candidate in (step, step - 1, step + 1):
        if candidate > user["last_code"] and hmac.compare_digest(totp(user["secret"], candidate), code):
            return candidate
    return None


def text(body, key, maximum, minimum=1, *, strip=True):
    value = body.get(key, "")
    if isinstance(value, str):
        value = value.strip() if strip else value
        if minimum <= len(value) <= maximum and not re.search(r"[\x00\ud800-\udfff]", value):
            return value
    raise ApiError(400, f"Проверь поле {key} ({minimum}–{maximum} символов).")


def username(value):
    if isinstance(value, str):
        value = value.strip().removeprefix("@").lower()
        if USERNAME.fullmatch(value):
            return value
    raise ApiError(400, "Юзернейм должен содержать 3–32 латинские буквы, цифры или подчёркивания.")


def integer(value, minimum=1):
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,18}", value):
        value = int(value)
    if type(value) is int and minimum <= value < 2**63:
        return value
    raise ApiError(400, "Неверный числовой параметр.")


def public_user(user):
    return {
        "id": user["id"], "username": user["username"], "name": user["name"],
        "verified": bool(user["verified"]), "bot": bool(user["bot"]),
    }


def limit(db, scope, item, maximum, seconds):
    bucket = int(time.time()) // seconds
    with db:
        db.execute("DELETE FROM limits WHERE scope=? AND bucket<?", (scope, bucket - 1))
        count = db.execute("""
            INSERT INTO limits VALUES (?, ?, ?, 1)
            ON CONFLICT(scope,item,bucket) DO UPDATE SET hits=hits+1
            RETURNING hits
        """, (scope, item, bucket)).fetchone()[0]
    if count > maximum:
        raise ApiError(429, "Слишком много попыток. Попробуй немного позже.")


def bump(db):
    db.execute("UPDATE revisions SET value=value+1 WHERE id=1")


def session(db, user_id):
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    db.execute("DELETE FROM sessions WHERE expires<=?", (now,))
    db.execute("INSERT INTO sessions VALUES (?, ?, ?)", (digest(token), user_id, now + SESSION_TTL))
    return {"token": token}


def auth(db, token, bot=False):
    if not token:
        raise ApiError(401, "Войди снова.")
    if bot:
        user = db.execute("SELECT * FROM users WHERE bot=1 AND bot_token=?", (digest(token),)).fetchone()
    else:
        user = db.execute("""
            SELECT users.* FROM sessions JOIN users ON users.id=sessions.user_id
            WHERE sessions.token=? AND sessions.expires>? AND users.confirmed=1 AND users.bot=0
        """, (digest(token), int(time.time()))).fetchone()
    if not user or user["banned"]:
        raise ApiError(401, "Сессия недействительна.")
    return user


def register(db, body, remote):
    limit(db, "register-ip", remote, 12, 600)
    handle = username(body.get("username"))
    password = text(body, "password", 256, 8, strip=False)
    name = text(body, "name", 64, 0) or handle
    admin = handle == "albert"
    if admin:
        supplied = text(body, "invite", 256, 0)
        if not ADMIN_INVITE or not hmac.compare_digest(supplied.encode(), ADMIN_INVITE.encode()):
            raise ApiError(403, "Для @albert нужен ключ администратора.")
    secret = base64.b32encode(secrets.token_bytes(20)).decode()
    ticket = secrets.token_urlsafe(32)
    now = int(time.time())
    hashed = password_hash(password)
    with db:
        db.execute("BEGIN IMMEDIATE")
        existing = db.execute("SELECT confirmed, pending_until FROM users WHERE username=?", (handle,)).fetchone()
        if existing:
            if existing["confirmed"] or (existing["pending_until"] or 0) > now:
                raise ApiError(409, "Юзернейм занят или ожидает подтверждения.")
            db.execute("DELETE FROM users WHERE username=?", (handle,))
        db.execute("""
            INSERT INTO users(username,name,password,secret,enrollment,pending_until,admin)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (handle, name, hashed, secret, digest(ticket), now + 900, admin))
    query = urlencode({"secret": secret, "issuer": "Albertgram"})
    return {"secret": secret, "uri": f"otpauth://totp/Albertgram:{quote(handle)}?{query}", "ticket": ticket}


def confirm(db, body, remote):
    limit(db, "confirm-ip", remote, 40, 300)
    handle = username(body.get("username"))
    ticket = text(body, "ticket", 128)
    limit(db, "confirm-ticket", digest(ticket), 7, 300)
    with db:
        db.execute("BEGIN IMMEDIATE")
        user = db.execute("""
            SELECT * FROM users WHERE username=? AND confirmed=0 AND pending_until>? AND enrollment=?
        """, (handle, int(time.time()), digest(ticket))).fetchone()
        if not user:
            raise ApiError(400, "Регистрация истекла. Начни её заново.")
        step = otp_step(user, body.get("code"))
        if step is None:
            raise ApiError(400, "Неверный код из приложения.")
        db.execute("""
            UPDATE users SET confirmed=1,last_code=?,enrollment=NULL,pending_until=NULL WHERE id=?
        """, (step, user["id"]))
        return session(db, user["id"])


def login(db, body, remote):
    limit(db, "login-ip", remote, 30, 300)
    handle = username(body.get("username"))
    password = text(body, "password", 256, strip=False)
    limit(db, "login-user", handle, 10, 300)
    user = db.execute("""
        SELECT * FROM users WHERE username=? AND confirmed=1 AND bot=0 AND banned=0
    """, (handle,)).fetchone()
    if not password_ok(password, user["password"] if user else None):
        raise ApiError(401, "Неверный логин, пароль или код.")
    step = otp_step(user, body.get("code"))
    if step is None:
        raise ApiError(401, "Неверный или уже использованный код. Дождись следующего.")
    with db:
        changed = db.execute("""
            UPDATE users SET last_code=? WHERE id=? AND last_code<? AND banned=0
        """, (step, user["id"], step)).rowcount
        if not changed:
            raise ApiError(401, "Код уже использован. Дождись следующего.")
        return session(db, user["id"])


def member_chat(db, user_id, chat_id):
    chat = db.execute("""
        SELECT chats.* FROM chats JOIN members ON chats.id=members.chat
        WHERE chats.id=? AND members.user_id=?
    """, (chat_id, user_id)).fetchone()
    if not chat:
        raise ApiError(404, "Чат не найден.")
    return chat


def list_chats(db, user_id):
    rows = db.execute("""
        SELECT c.*, u.name AS peer_name, u.verified AS peer_verified, m.text AS last_text
        FROM members AS mine JOIN chats AS c ON c.id=mine.chat
        LEFT JOIN members AS other ON c.kind='direct' AND other.chat=c.id AND other.user_id<>mine.user_id
        LEFT JOIN users AS u ON u.id=other.user_id
        LEFT JOIN messages AS m ON m.id=(SELECT id FROM messages WHERE chat=c.id ORDER BY id DESC LIMIT 1)
        WHERE mine.user_id=? ORDER BY COALESCE(m.id, 0) DESC, c.id DESC
    """, (user_id,))
    return {"chats": [
        {"id": row["id"], "type": row["kind"], "title": row["peer_name"] or row["title"],
         "verified": bool(row["peer_verified"]), "last": row["last_text"] or ""}
        for row in rows
    ]}


def open_direct(db, user_id, handle):
    peer = db.execute("""
        SELECT id FROM users WHERE username=? AND confirmed=1 AND banned=0
    """, (handle,)).fetchone()
    if not peer:
        raise ApiError(404, "Пользователь не найден.")
    if peer["id"] == user_id:
        raise ApiError(400, "Выбери другого пользователя.")
    key = ":".join(str(item) for item in sorted((user_id, peer["id"])))
    with db:
        created = db.execute("INSERT OR IGNORE INTO chats(kind,direct_key) VALUES ('direct',?)", (key,)).rowcount
        chat_id = db.execute("SELECT id FROM chats WHERE direct_key=?", (key,)).fetchone()[0]
        if created:
            db.executemany("INSERT INTO members VALUES (?,?)", [(chat_id, user_id), (chat_id, peer["id"])])
            bump(db)
    return {"chat": chat_id}


def create_group(db, user_id, body):
    title = text(body, "title", 80)
    members = body.get("members", [])
    if not isinstance(members, list) or len(members) > 50:
        raise ApiError(400, "В группе может быть до 50 приглашённых участников.")
    handles = {username(item) for item in members}
    with db:
        db.execute("BEGIN IMMEDIATE")
        ids = {user_id}
        for handle in handles:
            row = db.execute("SELECT id FROM users WHERE username=? AND confirmed=1 AND banned=0", (handle,)).fetchone()
            if not row:
                raise ApiError(404, f"Участник @{handle} не найден.")
            ids.add(row["id"])
        chat_id = db.execute("INSERT INTO chats(title,kind) VALUES (?,'group')", (title,)).lastrowid
        db.executemany("INSERT INTO members VALUES (?,?)", [(chat_id, item) for item in ids])
        bump(db)
    return {"chat": chat_id}


def serialize_message(db, row):
    sender = db.execute("SELECT * FROM users WHERE id=?", (row["sender"],)).fetchone()
    return {
        "id": row["id"], "text": row["text"], "ts": row["ts"], "edited": bool(row["edited"]),
        "from": public_user(sender), "markup": json.loads(row["markup"]) if row["markup"] else None,
    }


def history(db, user_id, chat_id):
    member_chat(db, user_id, chat_id)
    rows = db.execute("SELECT * FROM messages WHERE chat=? ORDER BY id DESC LIMIT 250", (chat_id,)).fetchall()
    return {"msgs": [serialize_message(db, row) for row in reversed(rows)]}


def keyboard(body):
    markup = body.get("reply_markup")
    if markup is None:
        return None
    if not isinstance(markup, dict):
        raise ApiError(400, "Неверная клавиатура бота.")
    rows = markup.get("inline_keyboard")
    if not isinstance(rows, list) or len(rows) > 8:
        raise ApiError(400, "Клавиатура может содержать до 8 строк.")
    clean = []
    for row in rows:
        if not isinstance(row, list) or not 1 <= len(row) <= 4:
            raise ApiError(400, "В строке должно быть от 1 до 4 кнопок.")
        buttons = []
        for entry in row:
            if not isinstance(entry, dict):
                raise ApiError(400, "Неверная кнопка бота.")
            button = {"text": text(entry, "text", 64)}
            if "url" in entry:
                link = text(entry, "url", 2048)
                try:
                    parsed = urlsplit(link)
                    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None:
                        raise ValueError()
                except ValueError as error:
                    raise ApiError(400, "Кнопка должна вести на HTTP(S)-адрес.") from error
                button["url"] = link
            else:
                button["callback_data"] = text(entry, "callback_data", 64, strip=False)
            buttons.append(button)
        clean.append(buttons)
    return json.dumps({"inline_keyboard": clean}, ensure_ascii=False)


def add_message(db, chat_id, sender, content, markup=None):
    message_id = db.execute("""
        INSERT INTO messages(chat,sender,text,ts,markup) VALUES (?, ?, ?, ?, ?)
    """, (chat_id, sender, content, int(time.time()), markup)).lastrowid
    return db.execute("SELECT * FROM messages WHERE id=?", (message_id,)).fetchone()


def enqueue(db, bot, event):
    db.execute("INSERT INTO updates(bot,payload) VALUES (?,?)", (bot, json.dumps(event, ensure_ascii=False)))
    db.execute("""
        DELETE FROM updates WHERE bot=? AND id<(SELECT id FROM updates WHERE bot=? ORDER BY id DESC LIMIT 1 OFFSET 999)
    """, (bot, bot))


def message_send(db, actor, chat_id, content, markup=None):
    with db:
        db.execute("BEGIN IMMEDIATE")
        chat = member_chat(db, actor["id"], chat_id)
        row = add_message(db, chat_id, actor["id"], content, markup)
        message = serialize_message(db, row)
        if not actor["bot"]:
            bots = db.execute("""
                SELECT users.id, users.username FROM members JOIN users ON users.id=members.user_id
                WHERE members.chat=? AND users.bot=1 AND users.banned=0
            """, (chat_id,)).fetchall()
            for bot in bots:
                if bot["username"] == "papochka":
                    if chat["kind"] == "direct":
                        add_message(db, chat_id, bot["id"], "Создать бота можно через ⚙ Настройки → Создать бота. Там появится токен для Bot API.")
                else:
                    enqueue(db, bot["id"], {"message": {**message, "chat": {"id": chat_id, "type": chat["kind"]}}})
        bump(db)
    return message


def change_message(db, actor, body, remove):
    message_id = integer(body.get("id"))
    with db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM messages WHERE id=? AND sender=?", (message_id, actor["id"])).fetchone()
        if not row:
            raise ApiError(404, "Сообщение не найдено.")
        member_chat(db, actor["id"], row["chat"])
        if remove:
            db.execute("DELETE FROM messages WHERE id=?", (message_id,))
        else:
            db.execute("UPDATE messages SET text=?, edited=1 WHERE id=?", (text(body, "text", 4000), message_id))
        bump(db)
    return {"ok": True}


def bot_callback(db, actor, body):
    message_id = integer(body.get("msg"))
    data = text(body, "data", 64, strip=False)
    with db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("""
            SELECT m.* FROM messages m JOIN users u ON u.id=m.sender
            WHERE m.id=? AND u.bot=1 AND u.banned=0
        """, (message_id,)).fetchone()
        if not row or not row["markup"]:
            raise ApiError(404, "Кнопка не найдена.")
        chat = member_chat(db, actor["id"], row["chat"])
        markup = json.loads(row["markup"])
        if not any(button.get("callback_data") == data for line in markup["inline_keyboard"] for button in line):
            raise ApiError(400, "Кнопка не найдена.")
        enqueue(db, row["sender"], {"callback_query": {
            "id": secrets.token_urlsafe(16), "from": public_user(actor), "data": data,
            "message": {**serialize_message(db, row), "chat": {"id": row["chat"], "type": chat["kind"]}},
        }})
    return {"ok": True}


def create_bot(db, actor, body):
    handle = username(body.get("username"))
    name = text(body, "name", 64)
    if handle in {"albert", "papochka"}:
        raise ApiError(409, "Юзернейм зарезервирован.")
    token = secrets.token_urlsafe(32)
    with db:
        db.execute("BEGIN IMMEDIATE")
        count = db.execute("SELECT COUNT(*) FROM users WHERE owner=?", (actor["id"],)).fetchone()[0]
        if count >= 10:
            raise ApiError(400, "На одном аккаунте можно создать до 10 ботов.")
        created = db.execute("""
            INSERT OR IGNORE INTO users(username,name,confirmed,bot,bot_token,owner)
            VALUES (?,?,1,1,?,?)
        """, (handle, name, digest(token), actor["id"])).rowcount
        if not created:
            raise ApiError(409, "Юзернейм занят.")
    return {"token": token, "username": handle}


def admin_action(db, actor, path, body):
    if not actor["admin"]:
        raise ApiError(403, "Нужны права администратора.")
    if path == "/api/admin/stats":
        return dict(db.execute("""
            SELECT (SELECT COUNT(*) FROM users WHERE confirmed=1 AND bot=0) AS users,
                   (SELECT COUNT(*) FROM users WHERE bot=1) AS bots,
                   (SELECT COUNT(*) FROM chats) AS chats,
                   (SELECT COUNT(*) FROM messages) AS msgs
        """).fetchone())
    if path == "/api/admin/users":
        rows = db.execute("SELECT * FROM users WHERE confirmed=1 ORDER BY id")
        return {"users": [{**public_user(row), "banned": bool(row["banned"])} for row in rows]}
    field = body.get("field")
    value = body.get("value")
    if field not in ("banned", "verified") or type(value) is not bool:
        raise ApiError(400, "Неверное действие.")
    user_id = integer(body.get("id"))
    with db:
        db.execute("BEGIN IMMEDIATE")
        target = db.execute("SELECT * FROM users WHERE id=? AND confirmed=1", (user_id,)).fetchone()
        if not target:
            raise ApiError(404, "Пользователь не найден.")
        if field == "banned" and (target["admin"] or target["username"] == "papochka"):
            raise ApiError(400, "Этот аккаунт нельзя заблокировать.")
        sql = "UPDATE users SET banned=? WHERE id=?" if field == "banned" else "UPDATE users SET verified=? WHERE id=?"
        db.execute(sql, (value, user_id))
        if field == "banned" and value:
            db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        bump(db)
    return {"ok": True}


def bot_api(db, token, path, body):
    bot = auth(db, token, bot=True)
    limit(db, "bot", str(bot["id"]), 180, 60)
    if path.endswith("/getUpdates"):
        offset = integer(body.get("offset", 0), minimum=0)
        with db:
            if offset:
                db.execute("DELETE FROM updates WHERE bot=? AND id<?", (bot["id"], offset))
            rows = db.execute("""
                SELECT * FROM updates WHERE bot=? AND id>=? ORDER BY id LIMIT 100
            """, (bot["id"], offset)).fetchall()
        result = [{"update_id": row["id"], **json.loads(row["payload"])} for row in rows]
    elif path.endswith("/sendMessage"):
        result = message_send(db, bot, integer(body.get("chat_id")), text(body, "text", 4000), keyboard(body))
    else:
        result = public_user(bot)
    return {"ok": True, "result": result}


GET = {
    "/api/health", "/api/me", "/api/chats", "/api/wait", "/api/msgs", "/api/search",
    "/api/admin/stats", "/api/admin/users",
}
POST = {
    "/api/register", "/api/confirm", "/api/login", "/api/logout", "/api/chat/open",
    "/api/group", "/api/send", "/api/edit", "/api/delete", "/api/cb",
    "/api/admin/set", "/api/bots/create", "/api/bot/getMe", "/api/bot/getUpdates", "/api/bot/sendMessage",
}


def route(db, path, query, body, token, remote):
    if path == "/api/health":
        db.execute("SELECT value FROM revisions WHERE id=1").fetchone()
        return {"ok": True}
    if path == "/api/register":
        return register(db, body, remote)
    if path == "/api/confirm":
        return confirm(db, body, remote)
    if path == "/api/login":
        return login(db, body, remote)
    if path.startswith("/api/bot/"):
        return bot_api(db, token, path, body)

    actor = auth(db, token)
    actor_id = actor["id"]
    if path in POST:
        limit(db, "write", str(actor_id), 120, 60)
    if path == "/api/logout":
        with db:
            db.execute("DELETE FROM sessions WHERE token=?", (digest(token),))
        return {"ok": True}
    if path == "/api/me":
        return {**public_user(actor), "admin": bool(actor["admin"])}
    if path == "/api/chats":
        return list_chats(db, actor_id)
    if path == "/api/wait":
        return {"v": db.execute("SELECT value FROM revisions WHERE id=1").fetchone()[0]}
    if path == "/api/msgs":
        return history(db, actor_id, integer(query.get("chat", [None])[0]))
    if path == "/api/search":
        term = query.get("q", [""])[0].strip().removeprefix("@").lower()
        if not term or not re.fullmatch(r"[a-z0-9_]{1,32}", term):
            return {"users": []}
        term = term.replace("_", "\\_")
        rows = db.execute("""
            SELECT * FROM users WHERE confirmed=1 AND banned=0 AND id<>?
            AND username LIKE ? ESCAPE '\\' ORDER BY username LIMIT 30
        """, (actor_id, term + "%"))
        return {"users": [public_user(row) for row in rows]}
    if path == "/api/chat/open":
        return open_direct(db, actor_id, username(body.get("username")))
    if path == "/api/group":
        return create_group(db, actor_id, body)
    if path == "/api/send":
        return message_send(db, actor, integer(body.get("chat")), text(body, "text", 4000))
    if path in {"/api/edit", "/api/delete"}:
        return change_message(db, actor, body, remove=path.endswith("/delete"))
    if path == "/api/cb":
        return bot_callback(db, actor, body)
    if path == "/api/bots/create":
        return create_bot(db, actor, body)
    return admin_action(db, actor, path, body)


def parse_request(environ):
    path = environ.get("PATH_INFO", "")
    expected = "GET" if path in GET else "POST" if path in POST else None
    if expected is None:
        raise ApiError(404, "Маршрут не найден.")
    if environ.get("REQUEST_METHOD") != expected:
        raise ApiError(405, "Метод не поддерживается.")
    body = {}
    if expected == "POST":
        if environ.get("CONTENT_TYPE", "").split(";", 1)[0].lower() != "application/json":
            raise ApiError(415, "Нужен Content-Type: application/json.")
        size = integer(environ.get("CONTENT_LENGTH") or "0", minimum=0)
        if size > MAX_BODY:
            raise ApiError(413, "Запрос слишком большой.")
        try:
            body = json.loads(environ["wsgi.input"].read(size))
        except (ValueError, UnicodeError, RecursionError) as error:
            raise ApiError(400, "Неверный JSON.") from error
        if not isinstance(body, dict):
            raise ApiError(400, "Ожидался JSON-объект.")
    try:
        query = parse_qs(environ.get("QUERY_STRING", ""), max_num_fields=25)
    except ValueError as error:
        raise ApiError(400, "Слишком много параметров.") from error
    auth_header = environ.get("HTTP_AUTHORIZATION", "")
    bearer = auth_header[7:] if auth_header.startswith("Bearer ") and len(auth_header) <= 140 else ""
    remote = environ.get("REMOTE_ADDR", "unknown")
    if remote in {"127.0.0.1", "::1"}:
        # Gunicorn listens on loopback and Caddy supplies the trusted client IP.
        remote = environ.get("HTTP_X_FORWARDED_FOR", remote).rsplit(",", 1)[-1].strip()[:64]
    return path, query, body, bearer, remote


def application(environ, start_response):
    status = 200
    try:
        args = parse_request(environ)
        with closing(connect()) as db:
            result = route(db, *args)
    except ApiError as error:
        status, result = error.status, {"error": str(error)}
    except Exception:
        logging.exception("Unhandled Albertgram API error")
        status, result = 500, {"error": "Внутренняя ошибка сервера."}
    payload = json.dumps(result, ensure_ascii=False).encode()
    start_response(f"{status} {HTTPStatus(status).phrase}", [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(payload))), ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
    ])
    return [payload]


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--init-db", action="store_true", required=True)
    parser.parse_args()
    init_db()
    print("База готова:", DB_PATH)
