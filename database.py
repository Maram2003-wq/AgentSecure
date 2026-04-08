"""
AgentSec — database.py
SQLite-based persistence for scan results, history and trends.
"""

import sqlite3, json, os, logging
from datetime import datetime, timedelta
import pandas as pd

log = logging.getLogger('agentsec.db')

DB_PATH = os.environ.get('AGENTSEC_DB', os.path.expanduser('~/agentsec/agentsec.db'))
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def _conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_database():
    with _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id         TEXT UNIQUE,
                target          TEXT,
                email           TEXT,
                completed_at    TEXT,
                security_score  REAL DEFAULT 0,
                risk_level      TEXT DEFAULT 'INCONNU',
                total_findings  INTEGER DEFAULT 0,
                critical        INTEGER DEFAULT 0,
                high            INTEGER DEFAULT 0,
                medium          INTEGER DEFAULT 0,
                low             INTEGER DEFAULT 0,
                info            INTEGER DEFAULT 0,
                weak_credentials INTEGER DEFAULT 0,
                pdf_path        TEXT,
                raw_json        TEXT
            )
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_target
            ON scans(target)
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_completed
            ON scans(completed_at)
        """)
        c.commit()
    log.info(f"[DB] Initialisée → {DB_PATH}")


def save_scan_results(data: dict):
    """Persiste un résultat de scan dans la DB."""
    if not isinstance(data, dict):
        return

    scan_id = data.get('scanId') or data.get('scan_id') or ''
    target  = data.get('target', '')
    email   = data.get('emailTo') or data.get('email', '')

    ai      = data.get('aiAnalysis') or {}
    stats   = ai.get('stats') or {}

    score   = ai.get('score_securite', 0)
    risk    = ai.get('risque_global', 'INCONNU')
    total   = stats.get('total_findings', 0)
    crit    = stats.get('critical', 0)
    high    = stats.get('high', 0)
    medium  = stats.get('medium', 0)
    low     = stats.get('low', 0)
    info    = stats.get('info', 0)

    # Compter les credentials faibles Hydra
    hydra_creds = len([h for h in (data.get('scans', {}).get('hydra') or [])
                       if h.get('type') == 'credential'])

    pdf_path    = (data.get('pdfInfo') or {}).get('pdfPath', '') or data.get('report_path', '')
    completed   = data.get('completedAt', datetime.utcnow().isoformat() + 'Z')
    raw         = json.dumps(data, ensure_ascii=False)

    try:
        with _conn() as c:
            c.execute("""
                INSERT INTO scans
                    (scan_id, target, email, completed_at, security_score,
                     risk_level, total_findings, critical, high, medium,
                     low, info, weak_credentials, pdf_path, raw_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    security_score  = excluded.security_score,
                    risk_level      = excluded.risk_level,
                    total_findings  = excluded.total_findings,
                    critical        = excluded.critical,
                    high            = excluded.high,
                    medium          = excluded.medium,
                    low             = excluded.low,
                    info            = excluded.info,
                    weak_credentials= excluded.weak_credentials,
                    pdf_path        = excluded.pdf_path,
                    raw_json        = excluded.raw_json,
                    completed_at    = excluded.completed_at
            """, (scan_id, target, email, completed, score,
                  risk, total, crit, high, medium,
                  low, info, hydra_creds, pdf_path, raw))
            c.commit()
        log.info(f"[DB] Scan sauvegardé — scan_id={scan_id} target={target}")
    except Exception as e:
        log.error(f"[DB] save_scan_results: {e}")


def get_scan_history(limit: int = 50) -> pd.DataFrame:
    """Retourne l'historique des scans sous forme de DataFrame."""
    try:
        with _conn() as c:
            rows = c.execute("""
                SELECT scan_id, target, email, completed_at,
                       security_score, risk_level, total_findings,
                       critical, high, medium, low, info,
                       weak_credentials, pdf_path
                FROM scans
                ORDER BY completed_at DESC
                LIMIT ?
            """, (limit,)).fetchall()
        if not rows:
            return pd.DataFrame()
        return pd.DataFrame([dict(r) for r in rows])
    except Exception as e:
        log.error(f"[DB] get_scan_history: {e}")
        return pd.DataFrame()


def get_trends(days: int = 30) -> pd.DataFrame:
    """Retourne les statistiques agrégées par jour sur N jours."""
    try:
        since = (datetime.utcnow() - timedelta(days=days)).isoformat()
        with _conn() as c:
            rows = c.execute("""
                SELECT
                    substr(completed_at, 1, 10)   AS date,
                    COUNT(*)                       AS scan_count,
                    AVG(security_score)            AS avg_score,
                    AVG(critical)                  AS avg_critical,
                    AVG(high)                      AS avg_high,
                    AVG(medium)                    AS avg_medium,
                    AVG(low)                       AS avg_low
                FROM scans
                WHERE completed_at >= ?
                GROUP BY substr(completed_at, 1, 10)
                ORDER BY date ASC
            """, (since,)).fetchall()
        if not rows:
            return pd.DataFrame()
        return pd.DataFrame([dict(r) for r in rows])
    except Exception as e:
        log.error(f"[DB] get_trends: {e}")
        return pd.DataFrame()


def get_top_vulnerable_targets(limit: int = 5) -> pd.DataFrame:
    """Retourne les cibles les plus vulnérables."""
    try:
        with _conn() as c:
            rows = c.execute("""
                SELECT target,
                       COUNT(*)        AS scan_count,
                       MIN(security_score) AS min_score,
                       MAX(critical)   AS max_critical,
                       MAX(high)       AS max_high
                FROM scans
                GROUP BY target
                ORDER BY max_critical DESC, min_score ASC
                LIMIT ?
            """, (limit,)).fetchall()
        if not rows:
            return pd.DataFrame()
        return pd.DataFrame([dict(r) for r in rows])
    except Exception as e:
        log.error(f"[DB] get_top_vulnerable_targets: {e}")
        return pd.DataFrame()


def get_scan_by_id(scan_id: str) -> dict | None:
    """Retourne le JSON brut d'un scan spécifique."""
    try:
        with _conn() as c:
            row = c.execute(
                "SELECT raw_json FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        if row and row['raw_json']:
            return json.loads(row['raw_json'])
    except Exception as e:
        log.error(f"[DB] get_scan_by_id: {e}")
    return None
