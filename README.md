# AgentSec — Scanner de Vulnérabilités

Interface web Flask + workflow n8n pour scanner des cibles réseau avec Nmap, Nikto, SSLScan, Hydra, WhatWeb, Gobuster et analyse IA via Groq.

---

## Structure du projet

```
agentsec/
├── app.py                          ← Backend Flask principal
├── database.py                     ← Persistance SQLite
├── templates/
│   └── index.html                  ← Frontend (interface web)
├── workflow_complet.json           ← Workflow n8n à importer
├── requirements.txt
└── README.md
```

---

## Installation

```bash
# 1. Cloner le repo
git clone https://github.com/TON_USER/agentsec.git
cd agentsec

# 2. Créer l'environnement virtuel
python3 -m venv venv
source venv/bin/activate

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Lancer Flask
python3 app.py
```

Interface disponible sur : http://localhost:3000

---

## Configuration n8n

1. Importer `workflow_complet.json` dans n8n
2. Le nœud final **"Code in JavaScript1"** envoie les résultats à :
   `http://172.17.0.1:3000/api/webhook-result`
3. Vérifier que l'URL pointe bien vers votre machine Flask

---

## Variables d'environnement (optionnelles)

```bash
export FLASK_PORT=3000
export N8N_BASE_URL=http://localhost:5678
export N8N_WEBHOOK_URL=http://localhost:5678/webhook/vulnerability-scan
export RESULTS_DIR=/tmp/vulnscan/results
export AGENTSEC_DB=~/agentsec/agentsec.db
```

---

## Routes API

| Méthode | Route | Description |
|---------|-------|-------------|
| POST | `/api/scan` | Lancer un scan |
| GET | `/api/results/<id>` | Résultats d'un scan |
| POST | `/api/webhook-result` | Callback depuis n8n |
| GET | `/api/history` | Historique des scans |
| GET | `/api/trends` | Tendances 30 jours |
| GET | `/api/stats` | Statistiques globales |
| GET | `/api/download-pdf?path=` | Télécharger un rapport PDF |
| GET | `/api/check-n8n` | Santé de n8n |
