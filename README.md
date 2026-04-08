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

