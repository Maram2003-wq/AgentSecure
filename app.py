#!/usr/bin/env python3
"""
AgentSec — Backend Flask v4.2
Fixes:
  - /api/scan-progress → reçoit les étapes réelles depuis n8n
  - /api/scan-log      → reçoit les logs réels depuis n8n
  - /api/results/<id>/progress → retourne les étapes au frontend
  - stats toujours recalculées depuis findings_valides réels
  - pdfInfo toujours inclus dans le payload final
"""

from flask import Flask, request, jsonify, render_template, send_file, abort
import requests, json, os, glob, time, threading, logging, io, math
from datetime import datetime, timezone

# ─── Import DB ────────────────────────────────────────────────────────────────
try:
    from database import (init_database, save_scan_results,
                          get_scan_history, get_trends,
                          get_top_vulnerable_targets)
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False
    import pandas as pd
    def init_database(): pass
    def save_scan_results(data): pass
    def get_scan_history(limit=50):       return pd.DataFrame()
    def get_trends(days=30):              return pd.DataFrame()
    def get_top_vulnerable_targets(n=5):  return pd.DataFrame()

# ─── App ──────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'agentsec-secret-2024')

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s',
                    datefmt='%H:%M:%S')
log = logging.getLogger('agentsec')

# ─── Config ───────────────────────────────────────────────────────────────────
N8N_WEBHOOK_URL = os.environ.get('N8N_WEBHOOK_URL',
    'http://localhost:5678/webhook/vulnerability-scan')
N8N_BASE_URL  = os.environ.get('N8N_BASE_URL',  'http://localhost:5678')
RESULTS_DIR   = os.environ.get('RESULTS_DIR',   '/tmp/vulnscan/results')
SCAN_TIMEOUT  = int(os.environ.get('SCAN_TIMEOUT', 600))
FLASK_PORT    = int(os.environ.get('FLASK_PORT', 3000))

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs('/tmp/vulnscan', exist_ok=True)

# ─── État global ──────────────────────────────────────────────────────────────
_lock          = threading.Lock()
_scan_cache    = {}   # scan_id → payload enrichi final
_scan_meta     = {}   # scan_id → {target, email, ports, started_at_iso, started_at_ts, status}
_scan_progress = {}   # scan_id → list of completed step names
_scan_logs     = {}   # scan_id → list of log strings
_watched       = set()


# ══════════════════════════════════════════════════════════════════════════════
#  UTILITAIRES
# ══════════════════════════════════════════════════════════════════════════════

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

def _now_ts() -> float:
    return time.time()

def _safe(v):
    if hasattr(v, 'isoformat'): return v.isoformat()
    if isinstance(v, float) and math.isnan(v): return None
    return v

def ok(data, code=200):  return jsonify(data), code
def err(msg, code=400):  return jsonify({'success': False, 'error': msg}), code


# ══════════════════════════════════════════════════════════════════════════════
#  STATS — toujours recalculées depuis les vrais findings
# ══════════════════════════════════════════════════════════════════════════════

def _recount_stats(findings: list, scans: dict) -> dict:
    """Compte les vrais findings depuis findings_valides + nikto + hydra."""
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in findings:
        if f.get('faux_positif'):
            continue
        sev = (f.get('severite') or 'info').lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts['info'] += 1

    nikto_count  = len(scans.get('nikto') or [])
    hydra_creds  = len([h for h in (scans.get('hydra') or [])
                        if h.get('type') == 'credential'])

    return {
        'critical':       counts['critical'],
        'high':           counts['high'],
        'medium':         counts['medium'],
        'low':            counts['low'],
        'info':           counts['info'],
        'total_findings': len([f for f in findings if not f.get('faux_positif')])
                          + nikto_count + hydra_creds,
    }


def _compute_score(stats: dict) -> int:
    s = 100
    s -= stats.get('critical', 0) * 45
    s -= stats.get('high',     0) * 22
    s -= stats.get('medium',   0) * 8
    s -= stats.get('low',      0) * 3
    return max(0, min(100, s))


def _normalize_risk(risk: str, score: int) -> str:
    table = {
        'critique': 'CRITIQUE', 'critical': 'CRITIQUE',
        'élevé':    'ÉLEVÉ',    'high':     'ÉLEVÉ',
        'moyen':    'MOYEN',    'medium':   'MOYEN',
        'faible':   'FAIBLE',   'low':      'FAIBLE',
    }
    r = table.get((risk or '').lower().strip())
    if r:
        return r
    if score <= 40: return 'CRITIQUE'
    if score <= 65: return 'ÉLEVÉ'
    if score <= 85: return 'MOYEN'
    return 'FAIBLE'


# ══════════════════════════════════════════════════════════════════════════════
#  ENRICHISSEMENT IA
# ══════════════════════════════════════════════════════════════════════════════

def _enrich_ai(ai: dict, scans: dict, services: list) -> dict:
    ai       = dict(ai)
    findings = ai.get('findings_valides') or []

    # ── Stats TOUJOURS recalculées depuis les vrais findings ──────────────────
    ai['stats'] = _recount_stats(findings, scans)

    # ── Score & risque recalculés ─────────────────────────────────────────────
    ai['score_securite'] = _compute_score(ai['stats'])
    ai['risque_global']  = _normalize_risk(
        ai.get('risque_global', ''), ai['score_securite'])

    # ── urgence + effort sur chaque finding ───────────────────────────────────
    urgence_map = {
        'CRITICAL': 'Immédiate', 'HIGH': 'Sous 24h',
        'MEDIUM': 'Cette semaine', 'LOW': 'Ce mois', 'INFO': 'À planifier',
    }
    effort_map = {
        'CRITICAL': 'Élevé', 'HIGH': 'Moyen',
        'MEDIUM': 'Moyen', 'LOW': 'Faible', 'INFO': 'Faible',
    }
    for f in findings:
        sev = (f.get('severite') or 'INFO').upper()
        f['urgence']    = f.get('urgence')    or urgence_map.get(sev, 'À planifier')
        f['effort']     = f.get('effort')     or effort_map.get(sev,  'Faible')
        f['cvss_score'] = f.get('cvss_score') or 0
        f.setdefault('cves', [])

    # ── Vecteurs d'attaque ────────────────────────────────────────────────────
    if not ai.get('vecteurs_attaque'):
        v = []
        for f in findings:
            if (f.get('severite') or '').upper() in ('CRITICAL', 'HIGH'):
                v.append(f"[{f['severite']}] {f.get('titre','?')} (source: {f.get('source','?')})")
        creds = [h for h in (scans.get('hydra') or []) if h.get('type') == 'credential']
        if creds:
            v.append(f"[Auth] {len(creds)} credential(s) faible(s) trouvé(s) par Hydra")
        nikto = scans.get('nikto') or []
        if nikto:
            v.append(f"[Web] {len(nikto)} finding(s) détectés par Nikto")
        for s in (scans.get('ssl') or []):
            if s.get('severity') in ('CRITICAL', 'HIGH'):
                v.append(f"[SSL/TLS] {s.get('issue','?')}")
        if services:
            ports = [f"{s.get('port')}/{s.get('service','?')}" for s in services[:6]]
            v.append(f"[Réseau] Ports exposés : {', '.join(ports)}")
        ai['vecteurs_attaque'] = v or ['Aucun vecteur critique identifié']

    # ── Recommandations globales ──────────────────────────────────────────────
    if not ai.get('recommandations_globales'):
        recos, seen = [], set()
        for f in findings:
            r = (f.get('remediation') or '').strip()
            if r and r not in seen and len(r) > 10:
                recos.append(r); seen.add(r)
            if len(recos) >= 8: break
        defaults = [
            "Maintenir tous les services à jour (correctifs CVEs)",
            "Activer l'authentification multi-facteurs sur tous les accès",
            "Déployer un WAF devant les services web exposés",
            "Effectuer des audits de sécurité trimestriels",
            "Mettre en place une journalisation centralisée (SIEM)",
        ]
        for d in defaults:
            if len(recos) < 5: recos.append(d)
        ai['recommandations_globales'] = recos[:8]

    # ── Plan d'action ─────────────────────────────────────────────────────────
    if not ai.get('plan_action'):
        imm, court, moyen = [], [], []
        for f in findings:
            sev  = (f.get('severite') or '').upper()
            item = f"{f.get('titre','?')} — {(f.get('remediation') or 'Corriger')[:100]}"
            if sev == 'CRITICAL' and len(imm)   < 5: imm.append(item)
            elif sev == 'HIGH'   and len(court)  < 5: court.append(item)
            elif                     len(moyen)  < 5: moyen.append(item)
        ai['plan_action'] = {
            'immediat':    imm   or ['Vérifier les configurations critiques immédiatement'],
            'court_terme': court or ["Patcher les CVEs HIGH, renforcer l'authentification"],
            'moyen_terme': moyen or ['Mettre en place une politique de sécurité globale'],
        }

    return ai


def _enrich_payload(payload: dict) -> dict:
    payload = dict(payload)
    scans   = payload.get('scans') or {}
    payload['aiAnalysis'] = _enrich_ai(
        payload.get('aiAnalysis') or {},
        scans,
        payload.get('services') or [],
    )
    payload.setdefault('completedAt', _now_iso())
    payload.setdefault('status', 'completed')

    # pdfInfo toujours présent
    if 'pdfInfo' not in payload:
        payload['pdfInfo'] = {
            'pdfPath':  payload.get('report_path', ''),
            'filename': '',
        }

    return payload


# ══════════════════════════════════════════════════════════════════════════════
#  CACHE
# ══════════════════════════════════════════════════════════════════════════════

def _save_cache(scan_id: str, data: dict):
    with _lock:
        _scan_cache[scan_id] = data
        if scan_id in _scan_meta:
            _scan_meta[scan_id]['status'] = 'done'
    try:
        save_scan_results(data)
    except Exception as e:
        log.warning(f"[DB] {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  FILE WATCHER
# ══════════════════════════════════════════════════════════════════════════════

def _file_watcher():
    log.info(f"[WATCHER] Démarré — {RESULTS_DIR}  +  /tmp/vulnscan  (cycle 5s)")
    while True:
        try:
            dirs = list({RESULTS_DIR, '/tmp/vulnscan'})
            for d in dirs:
                for fpath in glob.glob(os.path.join(d, '*.json')):
                    if fpath in _watched:
                        continue
                    try:
                        file_mtime = os.path.getmtime(fpath)
                        if _now_ts() - file_mtime > 900:
                            _watched.add(fpath); continue

                        with open(fpath, 'r', encoding='utf-8') as f:
                            data = json.load(f)

                        if not isinstance(data, dict):
                            _watched.add(fpath); continue
                        if not (data.get('target') or data.get('aiAnalysis')):
                            _watched.add(fpath); continue

                        file_scan_id = data.get('scanId', '')
                        file_target  = data.get('target', '')
                        matched_id   = None

                        with _lock:
                            metas = dict(_scan_meta)
                            done  = set(_scan_cache.keys())

                        for sid, m in metas.items():
                            if sid in done: continue
                            start_ts = m.get('started_at_ts', 0.0)
                            if file_mtime <= start_ts:
                                continue
                            if file_scan_id and file_scan_id == sid:
                                matched_id = sid; break
                            if file_target and file_target == m.get('target', ''):
                                matched_id = sid; break

                        if matched_id:
                            data['scanId'] = matched_id
                            enriched = _enrich_payload(data)
                            _save_cache(matched_id, enriched)
                            log.info(f"[WATCHER] ✅ scanId={matched_id} ← {os.path.basename(fpath)}")

                        _watched.add(fpath)

                    except json.JSONDecodeError:
                        log.debug(f"[WATCHER] JSON incomplet (retry) : {os.path.basename(fpath)}")
                    except Exception as e:
                        log.debug(f"[WATCHER] {fpath}: {e}")
                        _watched.add(fpath)

        except Exception as e:
            log.warning(f"[WATCHER] boucle: {e}")

        time.sleep(5)


# ══════════════════════════════════════════════════════════════════════════════
#  N8N SENDER
# ══════════════════════════════════════════════════════════════════════════════

def _send_to_n8n(payload: dict):
    scan_id = payload.get('scanId')
    try:
        log.info(f"[N8N] → {N8N_WEBHOOK_URL}  scanId={scan_id}")
        with _lock:
            if scan_id in _scan_meta:
                _scan_meta[scan_id]['status'] = 'running'

        resp = requests.post(N8N_WEBHOOK_URL, json=payload, timeout=SCAN_TIMEOUT)
        log.info(f"[N8N] ← HTTP {resp.status_code}")

        if resp.status_code == 200:
            try:
                result = resp.json()
                if isinstance(result, dict) and result.get('scanId') == scan_id:
                    _save_cache(scan_id, _enrich_payload(result))
                    log.info(f"[N8N] Résultat reçu directement (sync)")
            except Exception:
                pass

    except requests.exceptions.Timeout:
        log.error(f"[N8N] Timeout {SCAN_TIMEOUT}s — scanId={scan_id}")
        with _lock:
            if scan_id in _scan_meta:
                _scan_meta[scan_id]['status'] = 'timeout'
    except Exception as e:
        log.error(f"[N8N] Erreur: {e}")
        with _lock:
            if scan_id in _scan_meta:
                _scan_meta[scan_id]['status'] = 'error'


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — PAGE
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('index.html')


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — INFRA
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/check-n8n')
def check_n8n():
    try:
        r = requests.get(f'{N8N_BASE_URL}/healthz', timeout=4)
        return ok({'ok': r.status_code == 200})
    except Exception:
        return ok({'ok': False})


@app.route('/api/status')
def api_status():
    with _lock:
        n_cache  = len(_scan_cache)
        n_active = sum(1 for m in _scan_meta.values() if m.get('status') == 'running')
    return ok({'api': 'ok', 'db': DB_AVAILABLE,
               'cache': n_cache, 'active_scans': n_active, 'ts': _now_iso()})


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — SCAN
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/scan', methods=['POST'])
def trigger_scan():
    data   = request.get_json(silent=True) or {}
    target = data.get('target', '').strip()
    email  = data.get('email',  '').strip()
    ports  = data.get('ports',  '22,80,443,8080').strip()

    if not target: return err('Le champ "target" est requis.')
    if not email:  return err('Le champ "email" est requis.')

    scan_id  = f"scan_{int(time.time())}"
    start_ts = _now_ts()

    payload = {
        'scan_id':   scan_id,
        'scanId':    scan_id,
        'target':    target,
        'network':   target,
        'email':     email,
        'emailTo':   email,
        'ports':     ports,
        'portRange': ports,
    }

    with _lock:
        _scan_meta[scan_id] = {
            'target':        target,
            'email':         email,
            'ports':         ports,
            'started_at':    _now_iso(),
            'started_at_ts': start_ts,
            'status':        'pending',
        }
        _scan_progress[scan_id] = []
        _scan_logs[scan_id]     = []

    threading.Thread(target=_send_to_n8n, args=(payload,), daemon=True).start()
    log.info(f"[SCAN] Démarré — scanId={scan_id}  target={target}")
    return ok({'success': True, 'scan_id': scan_id})


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — PROGRESS & LOGS (appelées par n8n à chaque étape)
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/scan-progress', methods=['POST'])
def scan_progress_update():
    """
    n8n appelle cette route après chaque outil (nmap, nikto, ssl, hydra, ai, report).
    Body: { "scan_id": "...", "step": "nmap", "status": "done" }
    """
    data    = request.get_json(silent=True) or {}
    scan_id = data.get('scan_id') or data.get('scanId', '')
    step    = data.get('step', '').lower().strip()

    if scan_id and step:
        with _lock:
            if scan_id not in _scan_progress:
                _scan_progress[scan_id] = []
            if step not in _scan_progress[scan_id]:
                _scan_progress[scan_id].append(step)
        log.info(f"[PROGRESS] scanId={scan_id}  step={step}")

    return ok({'ok': True})


@app.route('/api/scan-log', methods=['POST'])
def scan_log_update():
    """
    n8n appelle cette route pour envoyer des logs temps réel.
    Body: { "scan_id": "...", "message": "Nmap: 3 ports ouverts détectés", "type": "info" }
    """
    data    = request.get_json(silent=True) or {}
    scan_id = data.get('scan_id') or data.get('scanId', '')
    message = data.get('message', '').strip()
    log_type = data.get('type', 'info')

    if scan_id and message:
        with _lock:
            if scan_id not in _scan_logs:
                _scan_logs[scan_id] = []
            _scan_logs[scan_id].append({
                'message': message,
                'type':    log_type,
                'ts':      _now_iso(),
            })
            # Garder max 100 lignes
            _scan_logs[scan_id] = _scan_logs[scan_id][-100:]

    return ok({'ok': True})


@app.route('/api/results/<scan_id>/progress')
def get_scan_progress(scan_id):
    """Retourne les étapes complétées + logs pour ce scan."""
    with _lock:
        steps = list(_scan_progress.get(scan_id, []))
        logs  = list(_scan_logs.get(scan_id, []))
        done  = scan_id in _scan_cache
    return ok({'steps': steps, 'logs': logs, 'completed': done})


@app.route('/api/scan/<scan_id>/status')
def scan_status(scan_id):
    with _lock:
        done = scan_id in _scan_cache
        meta = {k: v for k, v in _scan_meta.get(scan_id, {}).items()
                if k != 'started_at_ts'}
    status = 'done' if done else meta.get('status', 'unknown')
    return ok({'scan_id': scan_id, 'status': status, **meta})


@app.route('/api/results/<scan_id>')
def get_results(scan_id):
    with _lock:
        data = _scan_cache.get(scan_id)
    if data:
        return ok(data)
    return jsonify({'pending': True}), 204


@app.route('/api/scans')
def list_scans():
    status_filter = request.args.get('status')
    with _lock:
        metas    = dict(_scan_meta)
        done_ids = set(_scan_cache.keys())
    result = []
    for sid, meta in metas.items():
        status = 'done' if sid in done_ids else meta.get('status', 'pending')
        if status_filter and status != status_filter:
            continue
        m = {k: v for k, v in meta.items() if k != 'started_at_ts'}
        result.append({'scan_id': sid, 'status': status, **m})
    result.sort(key=lambda x: x.get('started_at', ''), reverse=True)
    return ok({'scans': result, 'total': len(result)})


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — WEBHOOK n8n → Flask
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/webhook-result', methods=['POST'])
def webhook_result():
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return err('JSON invalide.', 400)

    scan_id = data.get('scanId') or data.get('scan_id', '')

    with _lock:
        known    = scan_id in _scan_meta
        in_cache = scan_id in _scan_cache

    if not known:
        file_target = data.get('target', '')
        with _lock:
            for sid, m in _scan_meta.items():
                if m.get('target') == file_target and sid not in _scan_cache:
                    scan_id = sid
                    known   = True
                    log.info(f"[WEBHOOK] scanId résolu par target → {scan_id}")
                    break

    if not known:
        scan_id = scan_id or f"scan_{int(time.time())}"
        log.warning(f"[WEBHOOK] scanId inconnu — orphelin {scan_id}")

    data['scanId'] = scan_id
    enriched = _enrich_payload(data)

    # Marquer toutes les étapes comme terminées
    with _lock:
        _scan_progress[scan_id] = ['nmap', 'nikto', 'ssl', 'hydra', 'ai', 'report']

    # Sauvegarde disque
    try:
        fname = f"result_{scan_id}_{int(time.time())}.json"
        out   = os.path.join(RESULTS_DIR, fname)
        with open(out, 'w', encoding='utf-8') as f:
            json.dump(enriched, f, ensure_ascii=False, indent=2)
        _watched.add(out)
        log.info(f"[WEBHOOK] 💾 Sauvegardé → {fname}")
    except Exception as e:
        log.warning(f"[WEBHOOK] Sauvegarde disque: {e}")

    _save_cache(scan_id, enriched)
    log.info(
        f"[WEBHOOK] ✅ Résultat reçu — "
        f"scanId={scan_id}  target={data.get('target')}  "
        f"score={enriched.get('aiAnalysis',{}).get('score_securite','?')}/100  "
        f"findings={enriched.get('aiAnalysis',{}).get('stats',{}).get('total_findings','?')}"
    )
    return ok({'received': True, 'scan_id': scan_id})


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — HISTORIQUE & STATS
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/history')
def history():
    limit = min(int(request.args.get('limit', 50)), 500)
    try:
        df = get_scan_history(limit=limit)
        if df.empty:
            with _lock:
                cached = list(_scan_cache.values())
            records = []
            for d in cached:
                ai    = d.get('aiAnalysis') or {}
                stats = ai.get('stats')     or {}
                hydra = d.get('scans', {}).get('hydra') or []
                records.append({
                    'target':           d.get('target', '—'),
                    'completed_at':     d.get('completedAt', ''),
                    'security_score':   ai.get('score_securite', 0),
                    'risk_level':       ai.get('risque_global', 'INCONNU'),
                    'total_findings':   stats.get('total_findings', 0),
                    'critical':         stats.get('critical', 0),
                    'high':             stats.get('high', 0),
                    'weak_credentials': len([h for h in hydra if h.get('type') == 'credential']),
                })
            records.sort(key=lambda x: x.get('completed_at', ''), reverse=True)
            return ok({'history': records, 'total': len(records)})

        records = df.to_dict(orient='records')
        for rec in records:
            rec.update({k: _safe(v) for k, v in rec.items()})
        return ok({'history': records, 'total': len(records)})
    except Exception as e:
        log.exception("[/api/history]")
        return ok({'history': [], 'total': 0, 'error': str(e)})


@app.route('/api/trends')
def trends():
    days = int(request.args.get('days', 30))
    try:
        df = get_trends(days=days)
        if df.empty:
            with _lock:
                cached = list(_scan_cache.values())
            by_date = {}
            for d in cached:
                date_str = (d.get('completedAt') or '')[:10]
                if not date_str: continue
                ai    = d.get('aiAnalysis') or {}
                stats = ai.get('stats')     or {}
                if date_str not in by_date:
                    by_date[date_str] = {'scores': [], 'critical': [], 'high': [], 'medium': []}
                by_date[date_str]['scores'].append(ai.get('score_securite', 0))
                by_date[date_str]['critical'].append(stats.get('critical', 0))
                by_date[date_str]['high'].append(stats.get('high', 0))
                by_date[date_str]['medium'].append(stats.get('medium', 0))

            def avg(lst): return round(sum(lst) / len(lst), 1) if lst else 0
            records = [
                {'date': dt, 'avg_score': avg(v['scores']),
                 'avg_critical': avg(v['critical']), 'avg_high': avg(v['high']),
                 'avg_medium': avg(v['medium'])}
                for dt, v in sorted(by_date.items())
            ]
            return ok({'trends': records, 'days': days})

        records = df.to_dict(orient='records')
        for rec in records:
            rec.update({k: (str(v) if hasattr(v, 'isoformat') else
                            (0 if isinstance(v, float) and math.isnan(v) else v))
                        for k, v in rec.items()})
        return ok({'trends': records, 'days': days})
    except Exception as e:
        log.exception("[/api/trends]")
        return ok({'trends': [], 'days': days, 'error': str(e)})


@app.route('/api/stats')
def stats():
    try:
        df = get_scan_history(limit=500)
        db_total = db_avg = db_crit = 0
        if not df.empty:
            db_total = len(df)
            db_avg   = float(df['security_score'].mean()) if 'security_score' in df else 0
            db_crit  = int(df['critical'].sum())          if 'critical' in df else 0

        with _lock:
            cached = list(_scan_cache.values())
        mem_scores = [c.get('aiAnalysis', {}).get('score_securite', 0) for c in cached]
        mem_crit   = sum(c.get('aiAnalysis', {}).get('stats', {}).get('critical', 0) for c in cached)

        total = db_total or len(cached)
        avg   = db_avg if db_total else (sum(mem_scores) / len(mem_scores) if mem_scores else 0)
        crit  = db_crit if db_total else mem_crit

        return ok({'total_scans': total, 'avg_score': round(avg, 1),
                   'total_critical': crit, 'db_available': DB_AVAILABLE})
    except Exception as e:
        log.exception("[/api/stats]")
        return err(str(e), 500)


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — EXPORT
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/download-pdf')
def download_pdf():
    path = request.args.get('path', '').strip()
    if not path: abort(400)
    real_path = os.path.realpath(path)
    safe_dirs = [os.path.realpath(RESULTS_DIR), os.path.realpath('/tmp/vulnscan')]
    if not any(real_path.startswith(d) for d in safe_dirs):
        log.warning(f"[SECURITY] Path traversal refusé : {path}")
        abort(403)
    if not os.path.isfile(real_path): abort(404)
    return send_file(real_path, as_attachment=True,
                     download_name=os.path.basename(real_path))


@app.route('/api/results/<scan_id>/export')
def export_json(scan_id):
    with _lock:
        data = _scan_cache.get(scan_id)
    if not data: return err('Résultat introuvable.', 404)
    blob = json.dumps(data, indent=2, ensure_ascii=False).encode('utf-8')
    return send_file(io.BytesIO(blob), mimetype='application/json',
                     as_attachment=True, download_name=f"agentsec_{scan_id}.json")


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — ADMIN
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    with _lock:
        n = len(_scan_cache)
        _scan_cache.clear(); _scan_meta.clear()
        _scan_progress.clear(); _scan_logs.clear()
        _watched.clear()
    log.info(f"[CACHE] Vidé — {n} entrées supprimées")
    return ok({'cleared': True, 'removed': n})


@app.errorhandler(400)
def e400(e): return err(str(e), 400)
@app.errorhandler(403)
def e403(e): return err('Accès refusé.', 403)
@app.errorhandler(404)
def e404(e): return err('Introuvable.', 404)
@app.errorhandler(500)
def e500(e):
    log.exception("[500]")
    return err('Erreur interne.', 500)


# ══════════════════════════════════════════════════════════════════════════════
#  LANCEMENT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    init_database()
    threading.Thread(target=_file_watcher, daemon=True).start()

    print(f"""
{'='*60}
  🛡  AGENTSEC — Backend v4.2
{'='*60}
  📱 Interface    : http://localhost:{FLASK_PORT}
  📊 Stats        : http://localhost:{FLASK_PORT}/api/stats
  📋 Historique   : http://localhost:{FLASK_PORT}/api/history
  🔗 n8n webhook  : {N8N_WEBHOOK_URL}
  📥 Résultats    : {RESULTS_DIR}
  🗄  Base DB      : {'activée' if DB_AVAILABLE else 'désactivée (mode mémoire)'}
{'='*60}
  Nouveaux endpoints v4.2 :
    POST /api/scan-progress  → n8n notifie Flask par étape
    POST /api/scan-log       → n8n envoie logs temps réel
    GET  /api/results/<id>/progress → frontend poll les étapes
{'='*60}
""")
    app.run(host='0.0.0.0', port=FLASK_PORT, debug=True)
