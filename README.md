# RT0806 | Boutique sécurisée sur MQTT

Implémentation d'une boutique en ligne dont tous les échanges transitent par
un broker MQTT. La sécurité repose sur trois mécanismes complémentaires :

| Mécanisme | Algorithme | Rôle |
|-----------|-----------|------|
| Authentification serveur | CA locale + certificat serveur X.509 signé (RSA-3072 / SHA-256) | Prouver l'identité du serveur |
| Établissement de session | RSA-OAEP-SHA256 | Transmettre la clé AES de façon confidentielle |
| Échanges applicatifs | AES-256-CBC + SHA-1 | Chiffrement et intégrité des messages |

---

## Architecture

```
Broker MQTT (Mosquitto)
    │
    ├─► rt0806/srv/cert          ← certificat serveur (retained)
    ├─► rt0806/auth/<cid>        ← clé AES wrappée (client → serveur)
    ├─► rt0806/auth/<cid>/ready  ← accusé de réception (serveur → client)
    ├─► rt0806/products/<cid>    ← catalogue chiffré (serveur → client)
    └─► rt0806/order/<cid>       ← commande chiffrée (client → serveur)
```

Le client utilise la bibliothèque **paho-mqtt** (callbacks asynchrones) ;
aucun outil en ligne de commande (`mosquitto_pub`/`mosquitto_sub`) n'est requis.

---

## Prérequis

Broker MQTT via Docker Compose :
```bash
docker compose version
```

Dépendances Python pour le serveur et le client :
```bash
python3 -m pip install -r requirements.txt
```

---

## Lancement

**Terminal 1 | broker MQTT avec Docker**
```bash
docker compose up
```

**Terminal 2 | serveur Python local**
```bash
python3 server.py
```

Au premier démarrage, le serveur génère la CA locale et le certificat serveur.

**Terminal 3 | client Python local**
```bash
python3 client.py
```

Avec une adresse de livraison personnalisée :
```bash
python3 client.py --adresse "42 avenue de la République, 69003 Lyon"
```

Commande automatique d'un article :
```bash
python3 client.py --article-id 3
```

**Arrêt du broker**
```bash
docker compose down
```

---

## Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `MQTT_BROKER` | `127.0.0.1` | Adresse IP du broker |
| `MQTT_PORT` | `1883` | Port TCP du broker |
| `PKI_DIR` | dossier du script | Dossier contenant la CA et le certificat serveur |
| `CLIENT_ARTICLE_ID` | vide | ID d'article à commander automatiquement |
| `CLIENT_ADRESSE` | `9 rue des Crayères, 51100 Reims` | Adresse de livraison du client |

---

## Fichiers générés au premier démarrage serveur

| Fichier | Contenu |
|---------|---------|
| `ca_priv.pem` | Clé privée de la CA locale |
| `ca_cert.pem` | Certificat public de la CA locale |
| `server_priv.pem` | Clé privée RSA du serveur |
| `server_cert.pem` | Certificat serveur signé par la CA locale |

---

