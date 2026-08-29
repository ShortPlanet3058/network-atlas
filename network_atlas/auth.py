"""Accounts, sessions and guess-rate limiting for the web viewer.

Only the HTTP viewer is protected. The command line opens the database directly
and never speaks to the server, so `network-atlas scan`, `passive`, `snmp` and
the rest are unaffected by anything here.

Why this exists: the viewer publishes the findings list, which is a ranked
inventory of exploitable services on the network with remediation notes attached.
That is the most useful document an attacker on the same LAN could find, so the
moment the viewer is reachable from another machine it needs a credential.

There is one account, `admin`. It is created the first time the server starts,
with a random password printed to the terminal — so a fresh container shows its
credentials in `docker logs` and nothing ships with a default password. There is
no signup page and no password reset over HTTP; both are ways in. Recovery is
`network-atlas account --reset-password`, which needs access to the machine.

Sessions are held in memory rather than signed into the cookie. A server-side
record can be revoked; a signed cookie cannot be, short of rotating the key and
logging everyone out. It also means a restart logs everyone out, which for a tool
that runs on one machine is a feature.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
from dataclasses import dataclass

# scrypt parameters. Deliberately costly: the whole point is that guessing is
# slow. These take on the order of 20-100ms, which is unnoticeable on a login and
# ruinous for an attacker working through a wordlist.
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_LENGTH = 32
_SALT_BYTES = 16

SESSION_COOKIE = "atlas_session"
SESSION_TTL_SECONDS = 12 * 60 * 60

# Guessing controls, applied per client address. The lockout is deliberately
# short: long enough to make a wordlist impractical, short enough that locking
# yourself out of your own network map is an inconvenience, not a crisis.
MAX_FAILURES = 8
FAILURE_WINDOW_SECONDS = 300
LOCKOUT_SECONDS = 300

MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 1024
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,31}$")

class AuthError(ValueError):
    """A credential or account request that cannot be honoured."""


@dataclass(frozen=True)
class Session:
    token: str
    user_id: int
    username: str


DEFAULT_USERNAME = "admin"


def generate_password() -> str:
    """The password printed at first startup.

    Random rather than memorable on purpose: a memorable generated password would
    end up reused, and this one is meant to be copied into a password manager or
    replaced from the viewer.
    """
    return secrets.token_urlsafe(12)


def normalize_username(username: str) -> str:
    """Validate a username and return its canonical form.

    Stored and compared in lower case, so the login is not case-sensitive in a
    way nobody expects.
    """
    candidate = (username or "").strip()
    if not USERNAME_PATTERN.match(candidate):
        raise AuthError(
            "A username must be 2 to 32 characters, start with a letter or digit, "
            "and contain only letters, digits, dots, underscores or hyphens."
        )
    return candidate.lower()


def check_password_strength(password: str) -> None:
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise AuthError(
            f"The password must be at least {MIN_PASSWORD_LENGTH} characters."
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        # scrypt on an unbounded input is a denial-of-service vector.
        raise AuthError("That password is unreasonably long.")


def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Derive a password hash. Returns (salt, hash)."""
    salt = salt or secrets.token_bytes(_SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_KEY_LENGTH,
    )
    return salt, derived


def verify_password(password: str, salt: bytes, expected: bytes) -> bool:
    """Whether a candidate matches a stored hash.

    Always derives the full hash before comparing, so the time taken does not
    reveal how much of the password was right.
    """
    if not password or not salt or not expected:
        return False
    _, derived = hash_password(password, salt)
    return hmac.compare_digest(derived, expected)


class SessionStore:
    """Live sessions and login-attempt throttling."""

    def __init__(
        self,
        *,
        session_ttl: int = SESSION_TTL_SECONDS,
        max_failures: int = MAX_FAILURES,
        lockout_seconds: int = LOCKOUT_SECONDS,
    ) -> None:
        self._session_ttl = session_ttl
        self._max_failures = max_failures
        self._lockout_seconds = lockout_seconds
        # ThreadingHTTPServer serves requests concurrently, so every mutation of
        # these tables has to be guarded.
        self._lock = threading.Lock()
        self._sessions: dict[str, tuple[Session, float]] = {}
        self._failures: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}

    def open(self, user_id: int, username: str) -> Session:
        token = secrets.token_urlsafe(32)
        session = Session(token=token, user_id=user_id, username=username)
        with self._lock:
            self._prune_locked()
            self._sessions[token] = (session, time.monotonic() + self._session_ttl)
        return session

    def get(self, token: str | None) -> Session | None:
        """Return a live session, extending its lifetime.

        The extension makes the timeout a sliding window: someone watching the map
        all afternoon is not logged out mid-scan, while an abandoned session still
        expires.
        """
        if not token:
            return None
        now = time.monotonic()
        with self._lock:
            entry = self._sessions.get(token)
            if entry is None:
                return None
            session, expiry = entry
            if expiry < now:
                del self._sessions[token]
                return None
            self._sessions[token] = (session, now + self._session_ttl)
            return session

    def close(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(token, None)

    def close_user(self, user_id: int) -> int:
        """Revoke every session belonging to the account.

        Called when the password changes: otherwise anyone already signed in with
        the old one keeps working until their cookie happens to expire.
        """
        with self._lock:
            doomed = [
                token for token, (session, _) in self._sessions.items()
                if session.user_id == user_id
            ]
            for token in doomed:
                del self._sessions[token]
            return len(doomed)

    def count(self) -> int:
        with self._lock:
            self._prune_locked()
            return len(self._sessions)

    # -- throttling -----------------------------------------------------------
    def lockout_remaining(self, client: str) -> int:
        """Seconds before this client may try again. Zero when it may try now."""
        with self._lock:
            until = self._locked_until.get(client)
            if until is None:
                return 0
            remaining = until - time.monotonic()
            if remaining <= 0:
                del self._locked_until[client]
                return 0
            return int(remaining) + 1

    def record_failure(self, client: str) -> int:
        """Note a wrong password. Returns the seconds of lockout now in force."""
        now = time.monotonic()
        with self._lock:
            attempts = [
                stamp for stamp in self._failures.get(client, [])
                if stamp > now - FAILURE_WINDOW_SECONDS
            ]
            attempts.append(now)
            self._failures[client] = attempts
            if len(attempts) >= self._max_failures:
                self._locked_until[client] = now + self._lockout_seconds
                self._failures[client] = []
                return self._lockout_seconds
            return 0

    def record_success(self, client: str) -> None:
        with self._lock:
            self._failures.pop(client, None)
            self._locked_until.pop(client, None)

    def _prune_locked(self) -> None:
        now = time.monotonic()
        for token, (_, expiry) in list(self._sessions.items()):
            if expiry < now:
                del self._sessions[token]
