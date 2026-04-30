# RT0806 | Boutique sécurisée sur MQTT

Implémentation d'une boutique en ligne dont tous les échanges transitent par
un broker MQTT. La sécurité repose sur trois mécanismes complémentaires :

| Mécanisme | Algorithme | Rôle |
|-----------|-----------|------|
| Authentification serveur | X.509 auto-signé (RSA-2048 / SHA-256) | Prouver l'identité du serveur |
| Établissement de session | RSA-OAEP-SHA1 | Transmettre la clé AES de façon confidentielle |
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

```bash
pip install cryptography paho-mqtt
```

Broker Mosquitto installé localement (`mosquitto` dans le PATH).

---

## Lancement

**Terminal 1 | broker**
```bash
mosquitto
```

**Terminal 2 | serveur**
```bash
python server.py
```

**Terminal 3 | client**
```bash
python client.py
# ou avec une adresse de livraison personnalisée :
python client.py --address "42 avenue de la République, 69003 Lyon"
```

---

## Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `MQTT_BROKER` | `127.0.0.1` | Adresse IP du broker |
| `MQTT_PORT` | `1883` | Port TCP du broker |

---

## Fichiers générés au premier démarrage serveur

| Fichier | Contenu |
|---------|---------|
| `server_priv.pem` | Clé privée RSA-2048 (PEM TraditionalOpenSSL) |
| `server_cert.pem` | Certificat X.509 auto-signé (validité 365 jours) |

---

