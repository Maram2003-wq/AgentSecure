#!/usr/bin/env python3
"""
AgentSec — Backend Flask complet v4.0
Conçu pour fonctionner avec :
  - index_3_.html (frontend)
  - Vulnerability Scanner n8n workflow (Ubuntu Edition)
"""

from flask import Flask, request, jsonify, render_template, send_file, abort
import requests, json, os, glob, time, threading, logging, io
from datetime import datetime, timedelta
from functools import wraps

# ─── Import DB (fallback si database.py manque) ───────────────────────────────
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
    def get_scan_history(limit=50):  return pd.DataFrame()
    def get_trends(days=30):         return pd.DataFrame()
    def get_top_vulnerable_targets(limit=5): return pd.DataFrame()

# ─── App ──────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'agentsec-secret-2024')

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s',
                    datefmt='%H:%M:%S')
log = logging.getLogger('agentsec')

# ─── Configuration ────────────────────────────────────────────────────────────
N8N_WEBHOOK_URL = os.environ.get('N8N_WEBHOOK_URL',
    'http://localhost:5678/webhook/vulnerability-scan')
N8N_BASE_URL    = os.environ.get('N8N_BASE_URL', 'http://localhost:5678')
RESULTS_DIR     = os.environ.get('RESULTS_DIR', '/tmp/vulnscan/results')
RESULT_MAX_AGE  = int(os.environ.get('RESULT_MAX_AGE', 600))
SCAN_TIMEOUT    = int(os.environ.get('SCAN_TIMEOUT', 600))
FLASK_PORT      = int(os.environ.get('FLASK_PORT', 3000))

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs('/tmp/vulnscan', exist_ok=True)

# ─── State ────────────────────────────────────────────────────────────────────
_lock        = threading.Lock()
_scan_cache  = {}   # scan_id → enriched payload
_scan_meta   = {}   # scan_id → {target, email, ports, started_at, status}
_watched     = set()


# ══════════════════════════════════════════════════════════════════════════════
#  AI ENRICHMENT — compute missing fields the Groq n8n prompt doesn't return
# ══════════════════════════════════════════════════════════════════════════════

def _compute_score(stats: dict) -> int:
    """Calcule le score de sécurité (0–100) à partir des stats."""
    score = 100
    score -= stats.get('critical', 0) * 20
    score -= stats.get('high',     0) * 10
    score -= stats.get('medium',   0) * 5
    score -= stats.get('low',      0) * 2
    return max(0, min(100, score))


def _risk_to_label(risk: str) -> str:
    mapping = {
        'critique': 'CRITIQUE', 'critical': 'CRITIQUE',
        'élevé': 'ÉLEVÉ',       'high': 'ÉLEVÉ',
        'moyen': 'MOYEN',       'medium': 'MOYEN',
        'faible': 'FAIBLE',     'low': 'FAIBLE',
    }
    return mapping.get((risk or 'inconnu').lower(), 'INCONNU')


def _urgence_effort(severity: str) -> tuple:
    """Retourne (urgence, effort) selon la sévérité."""
    table = {
        'CRITICAL': ('Immédiate', 'Élevé'),
        'HIGH':     ('Sous 24h',  'Moyen'),
        'MEDIUM':   ('Cette semaine', 'Moyen'),
        'LOW':      ('Ce mois',   'Faible'),
    }
    return table.get((severity or '').upper(), ('À planifier', 'Faible'))


def _enrich_ai_analysis(ai: dict, scans: dict, services: list) -> dict:
    """
    Complète aiAnalysis avec les champs manquants qu'attend le frontend :
      - score_securite
      - risque_global (normalisé)
      - vecteurs_attaque
      - recommandations_globales
      - plan_action  {immediat, court_terme, moyen_terme}
      - urgence + effort sur chaque finding
    """
    ai = dict(ai)  # copie

    # Stats
    stats = ai.get('stats', {})

    # Score
    if 'score_securite' not in ai or ai['score_securite'] == 0:
        ai['score_securite'] = _compute_score(stats)

    # Risque normalisé
    ai['risque_global'] = _risk_to_label(ai.get('risque_global', 'inconnu'))

    # urgence + effort sur chaque finding
    findings = ai.get('findings_valides', [])
    for f in findings:
        if not f.get('urgence') or not f.get('effort'):
            u, e = _urgence_effort(f.get('severite', ''))
            f.setdefault('urgence', u)
            f.setdefault('effort',  e)

    # ── Vecteurs d'attaque ────────────────────────────────────────────────────
    if not ai.get('vecteurs_attaque'):
        vectors = []
        crit_high = [f for f in findings
                     if f.get('severite', '').upper() in ('CRITICAL', 'HIGH')]
        for f in crit_high[:5]:
            vectors.append(f"[{f.get('severite','?')}] {f.get('titre','Vulnérabilité')} — {f.get('source','unknown')}")

        # Vecteurs SSL
        ssl_issues = [s for s in (scans.get('ssl') or [])
                      if s.get('severity', '') in ('CRITICAL', 'HIGH')]
        for s in ssl_issues[:3]:
            vectors.append(f"[SSL/TLS] {s.get('issue', 'Problème SSL/TLS')}")

        # Vecteurs Nikto
        nikto = scans.get('nikto') or []
        if nikto:
            vectors.append(f"[Web] {len(nikto)} vulnérabilités web détectées par Nikto")

        # Vecteurs Hydra
        creds = [h for h in (scans.get('hydra') or [])
                 if h.get('type') == 'credential']
        if creds:
            vectors.append(f"[Auth] {len(creds)} credential(s) faible(s) trouvé(s) par Hydra")

        # Services exposés
        if services:
            ports = [f"{s.get('port')}/{s.get('service','?')}" for s in services[:6]]
            vectors.append(f"[Réseau] Services exposés : {', '.join(ports)}")

        if not vectors:
            vectors.append("Aucun vecteur critique identifié — posture de sécurité acceptable")

        ai['vecteurs_attaque'] = vectors

    # ── Recommandations globales ──────────────────────────────────────────────
    if not ai.get('recommandations_globales'):
        recos = []
        seen = set()
        for f in findings:
            rem = f.get('remediation', '').strip()
            if rem and rem not in seen and len(rem) > 10:
                recos.append(rem)
                seen.add(rem)
            if len(recos) >= 8:
                break

        # Recommandations génériques si peu de findings
        defaults = [
            "Maintenir tous les services à jour avec les derniers correctifs de sécurité",
            "Mettre en place une politique de mots de passe forts et l'authentification multi-facteurs",
            "Configurer un pare-feu applicatif (WAF) pour les services web exposés",
            "Effectuer des audits de sécurité réguliers (trimestriels minimum)",
            "Activer la journalisation centralisée et la surveillance en temps réel",
        ]
        for d in defaults:
            if len(recos) < 5:
                recos.append(d)

        ai['recommandations_globales'] = recos[:8]

    # ── Plan d'action ─────────────────────────────────────────────────────────
    if not ai.get('plan_action'):
        immediat    = []
        court_terme = []
        moyen_terme = []

        for f in findings:
            sev = (f.get('severite') or '').upper()
            titre = f.get('titre', 'Vulnérabilité')
            rem   = f.get('remediation', 'Corriger ce problème')[:120]
            item  = f"{titre} — {rem}"
            if sev == 'CRITICAL':
                immediat.append(item)
            elif sev == 'HIGH':
                court_terme.append(item)
            elif sev in ('MEDIUM', 'LOW'):
                moyen_terme.append(item)

        # Défauts si vides
        if not immediat:
            immediat = ["Vérifier les configurations de sécurité des services exposés"]
        if not court_terme:
            court_terme = ["Mettre à jour les dépendances et patcher les CVEs connues",
                           "Renforcer les politiques d'authentification"]
        if not moyen_terme:
            moyen_terme = ["Implémenter une politique de sécurité globale",
                           "Planifier des tests de pénétration réguliers",
                           "Former les équipes aux bonnes pratiques DevSecOps"]

        ai['plan_action'] = {
            'immediat':    immediat[:5],
            'court_terme': court_terme[:5],
            'moyen_terme': moyen_terme[:5],
        }

    return ai


def _enrich_payload(payload: dict) -> dict:
    """Enrichit le payload complet reçu de n8n."""
    payload = dict(payload)
    ai      = payload.get('aiAnalysis') or {}
    scans   = payload.get('scans')      or {}
    services = payload.get('services')  or []

    payload['aiAnalysis'] = _enrich_ai_analysis(ai, scans, services)

    # Assure que completedAt est présent
    payload.setdefault('completedAt', datetime.utcnow().isoformat() + 'Z')
    payload.setdefault('status', 'completed')

    return payload


# ══════════════════════════════════════════════════════════════════════════════
#  CACHE HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _save_cache(scan_id: str, data: dict):
    with _lock:
        _scan_cache[scan_id] = data
        if scan_id in _scan_meta:
            _scan_meta[scan_id]['status'] = 'done'
    try:
        save_scan_results(data)
    except Exception as e:
        log.warning(f"[DB] save_scan_results: {e}")


def _load_from_disk(scan_id: str) -> dict | None:
    """
    Cherche un résultat sur disque dans /tmp/vulnscan/ et RESULTS_DIR.
    Stratégie : match scanId > match target > premier fichier valide récent.
    """
    search_dirs = list({RESULTS_DIR, '/tmp/vulnscan'})
    files = []
    for d in search_dirs:
        files.extend(glob.glob(os.path.join(d, '*.json')))

    if not files:
        return None
    files.sort(key=os.path.getctime, reverse=True)

    with _lock:
        meta = _scan_meta.get(scan_id, {})
    scan_target = meta.get('target', '')
    fallback = None

    for fpath in files:
        try:
            if time.time() - os.path.getctime(fpath) > RESULT_MAX_AGE:
                continue
            with open(fpath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if not isinstance(data, dict):
                continue
            if not (data.get('target') or data.get('aiAnalysis') or data.get('services')):
                continue

            if data.get('scanId') == scan_id:
                log.info(f"[DISK] scanId match: {os.path.basename(fpath)}")
                data['scanId'] = scan_id
                return data
            if scan_target and data.get('target') == scan_target:
                log.info(f"[DISK] target match: {os.path.basename(fpath)}")
                data['scanId'] = scan_id
                return data
            if fallback is None:
                data['scanId'] = scan_id
                fallback = data
        except Exception:
            pass
    return fallback


# ══════════════════════════════════════════════════════════════════════════════
#  FILE WATCHER — surveille /tmp/vulnscan toutes les 5s
# ══════════════════════════════════════════════════════════════════════════════

def _file_watcher():
    log.info(f"[WATCHER] Démarré — surveille /tmp/vulnscan et {RESULTS_DIR}")
    while True:
        try:
            search_dirs = list({RESULTS_DIR, '/tmp/vulnscan'})
            for d in search_dirs:
                for fpath in glob.glob(os.path.join(d, '*.json')):
                    if fpath in _watched:
                        continue
                    try:
                        if time.time() - os.path.getctime(fpath) > RESULT_MAX_AGE:
                            _watched.add(fpath)
                            continue
                        with open(fpath, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        if not isinstance(data, dict):
                            continue
                        if not (data.get('target') or data.get('aiAnalysis')):
                            continue

                        file_scan_id = data.get('scanId', '')
                        file_target  = data.get('target', '')
                        matched_id   = None

                        with _lock:
                            if file_scan_id and file_scan_id in _scan_meta and file_scan_id not in _scan_cache:
                                matched_id = file_scan_id
                            if not matched_id:
                                for sid, m in _scan_meta.items():
                                    if m.get('target') == file_target and sid not in _scan_cache:
                                        matched_id = sid
                                        break
                            if not matched_id:
                                for sid, m in _scan_meta.items():
                                    if sid not in _scan_cache and m.get('status') in ('pending', 'running'):
                                        matched_id = sid
                                        break

                        if matched_id:
                            data['scanId'] = matched_id
                            enriched = _enrich_payload(data)
                            _save_cache(matched_id, enriched)
                            log.info(f"[WATCHER] Injecté scanId={matched_id} depuis {os.path.basename(fpath)}")

                        _watched.add(fpath)
                    except Exception as e:
                        log.debug(f"[WATCHER] {fpath}: {e}")
        except Exception as e:
            log.warning(f"[WATCHER] boucle: {e}")
        time.sleep(5)


# ══════════════════════════════════════════════════════════════════════════════
#  N8N SENDER
# ══════════════════════════════════════════════════════════════════════════════

def _send_to_n8n(payload: dict):
    scan_id = payload.get('scanId') or payload.get('scan_id')
    try:
        log.info(f"[N8N] → {N8N_WEBHOOK_URL}  scanId={scan_id}")
        with _lock:
            if scan_id in _scan_meta:
                _scan_meta[scan_id]['status'] = 'running'
        resp = requests.post(N8N_WEBHOOK_URL, json=payload, timeout=SCAN_TIMEOUT)
        log.info(f"[N8N] ← HTTP {resp.status_code}")
        # Si n8n répond directement avec le résultat complet
        if resp.status_code == 200:
            try:
                result = resp.json()
                if isinstance(result, dict) and (result.get('scanId') or result.get('target')):
                    result.setdefault('scanId', scan_id)
                    enriched = _enrich_payload(result)
                    _save_cache(scan_id, enriched)
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
#  HELPERS HTTP
# ══════════════════════════════════════════════════════════════════════════════

def ok(data, code=200):
    return jsonify(data), code

def err(msg, code=400):
    return jsonify({'success': False, 'error': msg}), code

def _safe_val(v):
    if hasattr(v, 'isoformat'):
        return v.isoformat()
    try:
        import math
        if isinstance(v, float) and math.isnan(v):
            return None
    except Exception:
        pass
    return v


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — PAGES
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
        n_active = sum(1 for m in _scan_meta.values()
                       if m.get('status') == 'running')
    return ok({'api': 'ok', 'db': DB_AVAILABLE,
               'cache': n_cache, 'active_scans': n_active,
               'results_dir': RESULTS_DIR,
               'ts': datetime.utcnow().isoformat() + 'Z'})


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — SCAN
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/scan', methods=['POST'])
def trigger_scan():
    """Lance un scan — transmet à n8n en arrière-plan."""
    data   = request.get_json(silent=True) or {}
    target = data.get('target', '').strip()
    email  = data.get('email',  '').strip()
    ports  = data.get('ports',  '22,80,443,8080').strip()

    if not target:
        return err('Le champ "target" est requis.')
    if not email:
        return err('Le champ "email" est requis.')

    scan_id = f"scan_{int(time.time())}"
    payload = {
        'scan_id':   scan_id,      # Flask ID
        'scanId':    scan_id,      # alias n8n
        'target':    target,
        'network':   target,       # alias n8n
        'email':     email,
        'emailTo':   email,        # alias n8n
        'ports':     ports,
        'portRange': ports,        # alias n8n
    }

    with _lock:
        _scan_meta[scan_id] = {
            'target':     target,
            'email':      email,
            'ports':      ports,
            'started_at': datetime.utcnow().isoformat() + 'Z',
            'status':     'pending',
        }

    t = threading.Thread(target=_send_to_n8n, args=(payload,), daemon=True)
    t.start()

    log.info(f"[SCAN] Démarré — scanId={scan_id}  target={target}")
    return ok({'success': True, 'scan_id': scan_id})


@app.route('/api/scan/<scan_id>/status')
def scan_status(scan_id):
    with _lock:
        done = scan_id in _scan_cache
        meta = dict(_scan_meta.get(scan_id, {}))
    if done:
        return ok({'scan_id': scan_id, 'status': 'done', **meta})
    return ok({'scan_id': scan_id, 'status': meta.get('status', 'unknown'), **meta})


@app.route('/api/results/<scan_id>')
def get_results(scan_id):
    """
    200 + JSON → résultats disponibles
    204        → en cours (pending)
    """
    # 1. Cache mémoire
    with _lock:
        data = _scan_cache.get(scan_id)
    if data:
        return ok(data)

    # 2. Disque
    data = _load_from_disk(scan_id)
    if data:
        enriched = _enrich_payload(data)
        _save_cache(scan_id, enriched)
        return ok(enriched)

    # 3. Pending
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
        result.append({'scan_id': sid, 'status': status, **meta})
    result.sort(key=lambda x: x.get('started_at', ''), reverse=True)
    return ok({'scans': result, 'total': len(result)})


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — WEBHOOK (n8n → Flask)
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/webhook-result', methods=['POST'])
def webhook_result():
    """
    Reçoit le payload final de n8n (nœud 'Code in JavaScript1').
    Enrichit les champs manquants et met à jour le cache.
    """
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return err('JSON invalide.', 400)

    # Résoudre le scan_id
    scan_id = (data.get('scanId')
               or data.get('scan_id')
               or f"scan_{int(time.time())}")

    # Si pas de scanId dans le cache, essaie de matcher par target
    if scan_id not in _scan_meta:
        file_target = data.get('target', '')
        with _lock:
            for sid, m in _scan_meta.items():
                if m.get('target') == file_target and sid not in _scan_cache:
                    scan_id = sid
                    break

    data['scanId'] = scan_id
    enriched = _enrich_payload(data)

    # Sauvegarde JSON sur disque (pour le watcher et les rechargements)
    try:
        out_path = os.path.join(RESULTS_DIR,
                                f"result_{scan_id}_{int(time.time())}.json")
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(enriched, f, ensure_ascii=False, indent=2)
        log.info(f"[WEBHOOK] Résultat sauvegardé → {out_path}")
    except Exception as e:
        log.warning(f"[WEBHOOK] Impossible de sauvegarder sur disque: {e}")

    _save_cache(scan_id, enriched)
    log.info(f"[WEBHOOK] Résultat reçu — scanId={scan_id}  target={data.get('target')}")
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
            # Fallback mémoire
            with _lock:
                cached = list(_scan_cache.values())
            records = []
            for d in cached:
                ai = d.get('aiAnalysis', {})
                records.append({
                    'target':         d.get('target', '—'),
                    'completed_at':   d.get('completedAt', ''),
                    'security_score': ai.get('score_securite', 0),
                    'risk_level':     ai.get('risque_global', 'INCONNU'),
                    'total_findings': ai.get('stats', {}).get('total_findings', 0),
                    'critical':       ai.get('stats', {}).get('critical', 0),
                    'high':           ai.get('stats', {}).get('high', 0),
                    'weak_credentials': len([h for h in d.get('scans', {}).get('hydra', [])
                                             if h.get('type') == 'credential']),
                })
            return ok({'history': records, 'total': len(records)})

        records = df.to_dict(orient='records')
        for rec in records:
            rec.update({k: _safe_val(v) for k, v in rec.items()})
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
            # Génère des tendances depuis le cache mémoire
            with _lock:
                cached = list(_scan_cache.values())
            by_date = {}
            for d in cached:
                dt = (d.get('completedAt') or '')[:10]
                if not dt:
                    continue
                ai    = d.get('aiAnalysis', {}) or {}
                stats = ai.get('stats', {})
                if dt not in by_date:
                    by_date[dt] = {'scores': [], 'critical': [], 'high': [], 'medium': []}
                by_date[dt]['scores'].append(ai.get('score_securite', 0))
                by_date[dt]['critical'].append(stats.get('critical', 0))
                by_date[dt]['high'].append(stats.get('high', 0))
                by_date[dt]['medium'].append(stats.get('medium', 0))

            records = []
            for dt, vals in sorted(by_date.items()):
                def avg(lst): return round(sum(lst)/len(lst), 1) if lst else 0
                records.append({
                    'date':        dt,
                    'avg_score':   avg(vals['scores']),
                    'avg_critical': avg(vals['critical']),
                    'avg_high':    avg(vals['high']),
                    'avg_medium':  avg(vals['medium']),
                })
            return ok({'trends': records, 'days': days})

        records = df.to_dict(orient='records')
        for rec in records:
            rec.update({k: (str(v) if hasattr(v, 'isoformat') else
                            (0 if (isinstance(v, float) and v != v) else v))
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
            db_crit  = int(df['critical'].sum())          if 'critical'        in df else 0

        with _lock:
            cached = list(_scan_cache.values())

        mem_scores = [c.get('aiAnalysis', {}).get('score_securite', 0) for c in cached]
        mem_crit   = sum(c.get('aiAnalysis', {}).get('stats', {}).get('critical', 0) for c in cached)

        total = db_total or len(cached)
        avg   = db_avg   if db_total else (sum(mem_scores)/len(mem_scores) if mem_scores else 0)
        crit  = db_crit  if db_total else mem_crit

        return ok({'total_scans':    total,
                   'avg_score':      round(avg, 1),
                   'total_critical': crit,
                   'db_available':   DB_AVAILABLE})
    except Exception as e:
        log.exception("[/api/stats]")
        return err(str(e), 500)


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — EXPORT / DOWNLOAD
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/download-pdf')
def download_pdf():
    """Télécharge le rapport PDF généré par n8n (wkhtmltopdf)."""
    path = request.args.get('path', '').strip()
    if not path:
        abort(400)

    # Sécurité : pas de path traversal
    real_path = os.path.realpath(path)
    safe_dirs = [os.path.realpath(RESULTS_DIR), os.path.realpath('/tmp/vulnscan')]
    if not any(real_path.startswith(d) for d in safe_dirs):
        log.warning(f"[SECURITY] Accès refusé : {path}")
        abort(403)

    if not os.path.isfile(real_path):
        abort(404)

    return send_file(real_path, as_attachment=True,
                     download_name=os.path.basename(real_path))


@app.route('/api/results/<scan_id>/export')
def export_json(scan_id):
    """Télécharge le résultat complet en JSON."""
    with _lock:
        data = _scan_cache.get(scan_id)
    if not data:
        data = _load_from_disk(scan_id)
    if not data:
        return err('Résultat introuvable.', 404)

    blob = json.dumps(data, indent=2, ensure_ascii=False).encode('utf-8')
    return send_file(io.BytesIO(blob), mimetype='application/json',
                     as_attachment=True,
                     download_name=f"agentsec_{scan_id}.json")


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — ADMIN
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    with _lock:
        n = len(_scan_cache)
        _scan_cache.clear()
        _scan_meta.clear()
        _watched.clear()
    log.info(f"[CACHE] Vidé — {n} entrées supprimées")
    return ok({'cleared': True, 'removed': n})


# ──── Error handlers ──────────────────────────────────────────────────────────
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

    # Démarrer le watcher de fichiers
    threading.Thread(target=_file_watcher, daemon=True).start()

    banner = f"""
{'='*60}
  🛡  AGENTSEC — Backend v4.0
{'='*60}
  📱 Interface    : http://localhost:{FLASK_PORT}
  📊 Stats        : http://localhost:{FLASK_PORT}/api/stats
  📋 Historique   : http://localhost:{FLASK_PORT}/api/history
  🔗 n8n webhook  : {N8N_WEBHOOK_URL}
  📥 Résultats    : {RESULTS_DIR}
  🗄  Base DB      : {'activée' if DB_AVAILABLE else 'désactivée (mode mémoire)'}
{'='*60}
  Routes :
    POST /api/scan                 ← lancer un scan
    GET  /api/results/<id>         ← résultats
    POST /api/webhook-result       ← callback n8n
    GET  /api/history              ← historique
    GET  /api/trends               ← tendances
    GET  /api/stats                ← statistiques
    GET  /api/download-pdf?path=   ← télécharger PDF
    GET  /api/check-n8n            ← santé n8n
{'='*60}
"""
    print(banner)
    app.run(host='0.0.0.0', port=FLASK_PORT, debug=True)
