"""Home Control Hub — procesbewaker van de alles-in-één image; is zelf PID 1 van de container (geen dumb-init).

Eén container draait alles: PostgreSQL 16 (alleen unix-socket, geen netwerk, geen wachtwoord), migraties, de API
met statuspagina en de worker. Eén datamap (/appdata) en één poort (30420): zo installeert de app als gewone
TrueNAS Custom App zonder YAML.

Regels (gebaseerd op het werkende MSO-voorbeeld, contract 1.2 §2.2/§10, ADR-0010):
- Start als root alleen om /appdata (en alleen de eigen submappen) aan 568:568 te geven. Daarna laat de bewaker
  alle capabilities uit de bounding set vallen, wordt volledig 568 (``setgroups([])``, ``setgid``, ``setuid``; geen
  ambient capabilities) en zet ``PR_SET_NO_NEW_PRIVS`` vóór de eerste ``execve`` van een dienstproces: het standaard
  Custom App-formulier zet geen no-new-privileges en geen cap_drop. Dat geldt ook voor PID 1: de bewaker ís PID 1,
  ruimt verweesde processen (zombies) zelf op en draait na de wissel als 568 zonder capabilities. Start de container
  als 568 ("Custom User"), dan is er geen eigenaarschapsstap en wordt alleen no-new-privileges gezet.
- First-start-init: ontbrekende geheimen in /appdata/secrets (0600, nooit overschrijven).
- Duidelijke Nederlandse fout (en even wachten) als /appdata ontbreekt of niet schrijfbaar is, i.p.v. een crashloop.
- Oude postmaster.pid na een harde stop wordt opgeruimd.
- Vóór openstaande migraties een pg_dump naar /appdata/backups (de nieuwste 3 blijven). Mislukt die back-up, dan
  wordt NIET gemigreerd (fail-closed, gate-matrix) en stopt de app met een melding. Mislukt een migratie, dan blijft
  de vorige database ongewijzigd en stopt de app ook met een melding.
- Crashende processen worden met backoff herstart; SIGTERM stopt worker → api → database netjes.
"""

from __future__ import annotations

import contextlib
import ctypes
import grp
import os
import pwd
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

UID = int(os.environ.get("HCH_UID", "568"))
GID = int(os.environ.get("HCH_GID", "568"))
DATA = Path(os.environ.get("HCH_DATA_DIR", "/appdata"))
PGDATA = DATA / "postgres"
SOCKET_DIR = Path("/tmp/hch-pg")
PORT = os.environ.get("HCH_PORT", "30420")
DB_URL = f"postgresql+psycopg://hch@/hch?host={SOCKET_DIR}"
MANAGED = ("postgres", "secrets", "backups", "logs")
STOP = threading.Event()
PR_SET_NO_NEW_PRIVS = 38
PR_CAPBSET_DROP = 24


def log(msg: str) -> None:
    print(f"[home-control-hub] {msg}", flush=True)


def fail(msg: str, code: int = 78) -> None:
    log("FOUT: " + msg)
    time.sleep(30)  # houd de melding zichtbaar in de TrueNAS-app-log i.p.v. een snelle crashloop
    sys.exit(code)


def demote() -> None:
    """Volledig naar 568:568 zonder capabilities en met no-new-privileges (ook in kindprocessen vóór hun execve)."""
    libc = ctypes.CDLL(None, use_errno=True)
    if os.getuid() == 0 or os.geteuid() == 0:
        for cap in range(64):  # bounding set leeg (CAP_SETPCAP zit in de Docker-standaardset)
            if libc.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0:
                break  # einde van de bekende capabilities
        os.setgroups([])
        os.setgid(GID)
        os.setuid(UID)  # wist permitted/effective capabilities (geen keepcaps, geen ambient)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS mislukt")
    if 0 in (os.getuid(), os.geteuid(), os.getgid(), os.getegid()):
        raise PermissionError("rechten konden niet worden verlaagd")


def reap_orphans(known: set[int]) -> int:
    """Als PID 1: verweesde kindprocessen (zombies met PPID 1) opruimen, zonder de exitstatus van eigen kinderen
    (``known``, die ``Child.alive()`` zelf ophaalt) weg te nemen. Geeft het aantal opgeruimde processen."""
    if os.getpid() != 1:
        return 0
    reaped = 0
    for entry in os.listdir("/proc"):
        if not entry.isdigit() or int(entry) in known:
            continue
        try:
            with open(f"/proc/{entry}/stat", encoding="utf-8", errors="replace") as fh:
                fields = fh.read().rsplit(")", 1)[1].split()
        except (OSError, IndexError):
            continue
        if len(fields) > 1 and fields[0] == "Z" and fields[1] == "1":
            with contextlib.suppress(ChildProcessError, OSError):
                os.waitpid(int(entry), os.WNOHANG)
                reaped += 1
    return reaped


def _chown_tree(path: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(path):
        for name in [dirpath, *[os.path.join(dirpath, n) for n in dirnames + filenames]]:
            try:
                os.lchown(name, UID, GID)
            except OSError:
                pass


def prepare_dirs() -> None:
    if not DATA.exists():
        fail(f"{DATA} bestaat niet. Koppel in de app-instellingen een dataset (Host Path) aan {DATA}.")
    root = os.getuid() == 0
    if root:
        st = DATA.stat()
        if (st.st_uid, st.st_gid) != (UID, GID):
            log(f"eigenaar van {DATA} wordt {UID}:{GID}")
            os.chown(DATA, UID, GID)
        for sub in MANAGED:
            p = DATA / sub
            if p.exists() and (p.stat().st_uid, p.stat().st_gid) != (UID, GID):
                log(f"eigenaar van {p} wordt {UID}:{GID}")
                _chown_tree(p)
    for sub in (PGDATA, DATA / "secrets", DATA / "backups"):
        try:
            sub.mkdir(parents=True, exist_ok=True)
            if root:
                os.chown(sub, UID, GID)
        except PermissionError:
            fail(
                f"geen schrijfrechten op {sub}. Laat de app als root starten (dan regelt hij de rechten zelf) of "
                f"geef gebruiker {UID} (apps) schrijfrechten op de dataset."
            )
    try:
        os.chmod(PGDATA, 0o700)
        os.chmod(DATA / "secrets", 0o700)
    except PermissionError:
        fail(f"{PGDATA} is niet van gebruiker {UID}; start de app als root of maak {UID} eigenaar van de dataset.")
    SOCKET_DIR.mkdir(parents=True, exist_ok=True)
    if root:
        os.chown(SOCKET_DIR, UID, GID)
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            f"open('{DATA}/.hch-schrijftest','w').close();import os;os.remove('{DATA}/.hch-schrijftest')",
        ],
        preexec_fn=demote,
        capture_output=True,
        check=False,
    )
    if probe.returncode != 0:
        fail(f"gebruiker {UID} kan niet schrijven in {DATA}. Pas de rechten van de dataset aan (gebruiker apps).")


def env_for(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ)
    env.update({"HOME": "/tmp", "HCH_DATA_DIR": str(DATA), "HCH_DATABASE_URL": DB_URL, "PYTHONUNBUFFERED": "1"})
    try:
        env["USER"] = pwd.getpwuid(UID).pw_name
    except KeyError:
        pass
    env.update(extra or {})
    return env


def run_once(name: str, cmd: list[str]) -> int:
    log(f"{name} …")
    return subprocess.run(cmd, env=env_for(), preexec_fn=demote, check=False).returncode


class Child:
    def __init__(self, name: str, cmd: list[str], stop_signal: int = signal.SIGTERM) -> None:
        self.name, self.cmd, self.stop_signal = name, cmd, stop_signal
        self.proc: subprocess.Popen[bytes] | None = None

    def start(self) -> None:
        log(f"start {self.name}")
        self.proc = subprocess.Popen(self.cmd, env=env_for(), preexec_fn=demote)

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self, timeout: float = 25) -> None:
        if not self.alive() or self.proc is None:
            return
        self.proc.send_signal(self.stop_signal)
        try:
            self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            log(f"{self.name} reageert niet; geforceerd stoppen")
            self.proc.kill()
            self.proc.wait(5)


def init_database() -> None:
    if (PGDATA / "PG_VERSION").exists():
        major = (PGDATA / "PG_VERSION").read_text().strip()
        if major != "16":
            fail(f"de database in {PGDATA} is PostgreSQL {major}; deze image gebruikt 16. Zie de releasenotes.")
        pid = PGDATA / "postmaster.pid"
        if pid.exists():
            log("oude postmaster.pid van een onderbroken stop verwijderd")
            pid.unlink()
        return
    log("eerste start: database aanmaken")
    rc = run_once(
        "initdb",
        [
            "initdb",
            "-D",
            str(PGDATA),
            "-U",
            "hch",
            "--auth-local=trust",
            "--auth-host=reject",
            "--encoding=UTF8",
            "--locale=C.UTF-8",
            "--no-instructions",
        ],
    )
    if rc != 0:
        fail("initdb mislukt (zie de log hierboven)")


def postgres_child() -> Child:
    return Child(
        "database",
        [
            "postgres",
            "-D",
            str(PGDATA),
            "-c",
            "listen_addresses=",
            "-c",
            f"unix_socket_directories={SOCKET_DIR}",
            "-c",
            "max_connections=30",
            "-c",
            "shared_buffers=32MB",
            "-c",
            "jit=off",
            "-c",
            "logging_collector=off",
            "-c",
            "log_min_messages=warning",
        ],
        stop_signal=signal.SIGINT,  # 'fast shutdown'
    )


def wait_for_db(pg: Child, timeout: float = 90) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not pg.alive():
            fail("de database stopte tijdens het opstarten (zie de log hierboven)")
        rc = subprocess.run(
            ["pg_isready", "-h", str(SOCKET_DIR), "-U", "hch", "-d", "postgres", "-q"],
            env=env_for(),
            preexec_fn=demote,
            check=False,
        ).returncode
        if rc == 0:
            break
        time.sleep(1)
    else:
        fail("de database was niet binnen 90 s klaar")
    exists = subprocess.run(
        [
            "psql",
            "-h",
            str(SOCKET_DIR),
            "-U",
            "hch",
            "-d",
            "postgres",
            "-tAc",
            "SELECT 1 FROM pg_database WHERE datname='hch'",
        ],
        env=env_for(),
        preexec_fn=demote,
        capture_output=True,
        text=True,
        check=False,
    )
    if (
        exists.stdout.strip() != "1"
        and run_once(
            "database 'hch' aanmaken",
            ["psql", "-h", str(SOCKET_DIR), "-U", "hch", "-d", "postgres", "-qc", "CREATE DATABASE hch"],
        )
        != 0
    ):
        fail("database 'hch' aanmaken mislukt")


def shutdown(signum: int, _frame: object) -> None:
    log(f"signaal {signum}: netjes stoppen")
    STOP.set()


def main() -> None:
    # als PID 1 negeert de kernel signalen zonder handler: daarom meteen (ook tijdens init) afhandelen
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    log(f"Home Control Hub (alles-in-één) · versie {os.environ.get('HCH_VERSION', '?')} · data {DATA} · poort {PORT}")
    prepare_dirs()
    try:
        demote()  # vanaf hier draait niets meer als root: geen capabilities, no-new-privileges
    except OSError as exc:
        fail(f"rechten verlagen mislukt ({exc}); de app weigert als root of zonder no-new-privileges te draaien")
    log(f"draait als {os.getuid()}:{os.getgid()} zonder capabilities, no-new-privileges aan (PID {os.getpid()})")
    py = sys.executable
    if run_once("geheimen controleren (first-start-init)", [py, "-m", "integrations", "init"]) != 0:
        fail("geheimen aanmaken in /appdata/secrets mislukt")
    init_database()
    pg = postgres_child()
    pg.start()
    wait_for_db(pg)
    if (
        run_once(
            "migraties (met back-up vóór upgrade)",
            [py, "-m", "integrations", "migrate", "--backup-dir", str(DATA / "backups")],
        )
        != 0
    ):
        pg.stop()
        fail(
            "back-up vóór de migratie of de migratie zelf mislukt (zie de log hierboven); de database is ongewijzigd. "
            "Controleer de vrije ruimte op de dataset of zet de vorige image-tag terug."
        )

    children = [
        Child("api", [py, "-m", "integrations", "api", "--host", "0.0.0.0", "--port", PORT]),  # noqa: S104
        Child("worker", [py, "-m", "integrations", "worker"]),
    ]
    for c in children:
        c.start()

    backoff: dict[str, float] = {}
    while not STOP.is_set():
        reap_orphans({c.proc.pid for c in [pg, *children] if c.proc is not None})
        if not pg.alive():
            log("database gestopt; opnieuw starten")
            for c in children:
                c.stop()
            init_database()
            pg.start()
            wait_for_db(pg)
            for c in children:
                c.start()
        for c in children:
            if not c.alive() and not STOP.is_set():
                wait = min(60.0, backoff.get(c.name, 1.0))
                log(f"{c.name} gestopt (code {c.proc.returncode if c.proc else '?'}); herstart over {wait:.0f} s")
                STOP.wait(wait)
                backoff[c.name] = wait * 2
                if not STOP.is_set():
                    c.start()
            elif c.alive():
                backoff[c.name] = max(1.0, backoff.get(c.name, 1.0) * 0.9)
        STOP.wait(2)

    for c in reversed(children):  # worker → api
        c.stop()
    pg.stop(60)
    log("gestopt")


if __name__ == "__main__":
    try:
        pwd.getpwuid(UID)
        grp.getgrgid(GID)
    except KeyError:
        fail(f"gebruiker {UID}:{GID} bestaat niet in de image")
    if shutil.which("postgres") is None:
        fail("postgres ontbreekt in de image")
    main()
