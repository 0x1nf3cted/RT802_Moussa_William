#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
server.py | RT0806 : serveur de la boutique sécurisée.

Séquence de démarrage :
  1. Générer (ou recharger) la CA locale et le certificat serveur signé.
  2. Se connecter au courtier MQTT via paho-mqtt.
  3. Publier le certificat (PEM base64, retained) sur rt0806/srv/cert.
  4. À chaque demande d'établissement de session (rt0806/auth/<cid>) :
       - Déchiffrer la clé AES enveloppée avec la clé privée RSA.
       - Accuser réception sur rt0806/auth/<cid>/ready.
       - Envoyer le catalogue chiffré sur rt0806/products/<cid>.
  5. À chaque commande reçue (rt0806/order/<cid>) :
       - Déchiffrer et journaliser la commande.
"""

import os
import json
import base64
import time

import paho.mqtt.client as mqtt

from core import (
    COURTIER, PORT,
    T_CERTIFICAT, T_AUTH, T_PRET, T_PRODUITS, T_COMMANDE,
    ouvrir_enveloppe_cle, chiffrer, dechiffrer, CryptoErreur,
)
from pki import charger_cle_privee, initialiser_pki_serveur

_REPERTOIRE = os.path.dirname(os.path.abspath(__file__))
_REPERTOIRE_PKI = os.getenv("PKI_DIR", _REPERTOIRE)
CHEMIN_CLE_CA = os.path.join(_REPERTOIRE_PKI, "ca_priv.pem")
CHEMIN_CERT_CA = os.path.join(_REPERTOIRE_PKI, "ca_cert.pem")
CHEMIN_CLE = os.path.join(_REPERTOIRE_PKI, "server_priv.pem")
CHEMIN_CERT = os.path.join(_REPERTOIRE_PKI, "server_cert.pem")

CATALOGUE = [
    {"id": 1, "ref": "RS-AU1", "libelle": "Audi RS6 Avant",        "prix": 125000.00, "stock": 5},
    {"id": 2, "ref": "BM-M32", "libelle": "BMW M3 Competition",    "prix": 98000.00,  "stock": 7},
    {"id": 3, "ref": "MB-AM3", "libelle": "Mercedes-AMG C63 S",    "prix": 110000.00, "stock": 4},
    {"id": 4, "ref": "PO-911", "libelle": "Porsche 911 Carrera",   "prix": 140000.00, "stock": 3},
    {"id": 5, "ref": "FE-F82", "libelle": "Ferrari F8 Tributo",    "prix": 280000.00, "stock": 2},
]


class ServeurBoutique:

    def __init__(self):
        self._initialiser_identite()
        self._cle_privee = charger_cle_privee(CHEMIN_CLE)
        self._sessions: dict[str, bytes] = {}

        self._mq = mqtt.Client(
            client_id="rt0806-serveur",
            protocol=mqtt.MQTTv311,
            callback_api_version=mqtt.CallbackAPIVersion.VERSION1,
        )
        self._mq.on_connect    = self._a_la_connexion
        self._mq.on_disconnect = self._a_la_deconnexion
        self._mq.on_message    = self._a_la_reception

    # ── Cycle de vie ─────────────────────────────────────────────────────────

    def _initialiser_identite(self):
        os.makedirs(_REPERTOIRE_PKI, exist_ok=True)
        ca_creee, cert_cree = initialiser_pki_serveur(
            CHEMIN_CLE_CA,
            CHEMIN_CERT_CA,
            CHEMIN_CLE,
            CHEMIN_CERT,
        )
        if ca_creee:
            self._journaliser("CA locale générée (ca_priv.pem + ca_cert.pem)")
        if cert_cree:
            self._journaliser("Certificat serveur signé par la CA locale généré")

    def demarrer(self):
        self._journaliser(f"Connexion au courtier {COURTIER}:{PORT}")
        self._mq.connect(COURTIER, PORT, keepalive=60)
        self._mq.loop_forever()

    # ── Rappels MQTT ─────────────────────────────────────────────────────────

    def _a_la_connexion(self, client, userdata, flags, rc):
        if rc != 0:
            self._journaliser(f"Connexion refusée (rc={rc})")
            return
        self._journaliser("Connecté au courtier")
        client.subscribe("rt0806/auth/#")
        client.subscribe("rt0806/order/#")
        self._publier_certificat()

    def _a_la_deconnexion(self, client, userdata, rc):
        self._journaliser(f"Déconnecté (rc={rc})")

    def _a_la_reception(self, client, userdata, msg):
        topic   = msg.topic
        try:
            contenu = msg.payload.decode()
        except UnicodeDecodeError:
            self._journaliser(f"Message ignoré sur {topic} | payload non UTF-8")
            return

        if topic.startswith("rt0806/auth/") and not topic.endswith("/ready"):
            self._traiter_auth(topic, contenu)
        elif topic.startswith("rt0806/order/"):
            self._traiter_commande(topic, contenu)

    # ── Traitements ──────────────────────────────────────────────────────────

    def _publier_certificat(self):
        with open(CHEMIN_CERT, "rb") as f:
            cert_b64 = base64.b64encode(f.read()).decode()
        self._mq.publish(T_CERTIFICAT, cert_b64, retain=True)
        self._journaliser(f"Certificat publié (retained) sur {T_CERTIFICAT}")

    def _traiter_auth(self, topic: str, contenu: str):
        try:
            donnees      = json.loads(contenu)
            cid          = donnees["cid"]
            cle_env      = base64.b64decode(donnees["cle_enveloppee"])
            cle_aes      = ouvrir_enveloppe_cle(self._cle_privee, cle_env)
            if len(cle_aes) != 32:
                raise CryptoErreur("Clé de session invalide | 32 octets attendus")
            self._sessions[cid] = cle_aes
            self._journaliser(f"Session établie pour {cid}")

            self._mq.publish(T_PRET.format(cid=cid), json.dumps({"accordee": True}))
            self._mq.publish(T_PRODUITS.format(cid=cid), chiffrer(cle_aes, {"articles": CATALOGUE}))
            self._journaliser(f"Catalogue chiffré envoyé à {cid}")
        except CryptoErreur as exc:
            self._journaliser(f"Auth rejetée : {exc}")
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            self._journaliser(f"Auth invalide/corrompue : {exc}")
        except Exception as exc:
            self._journaliser(f"Erreur inattendue lors de l'authentification : {exc}")



    def _traiter_commande(self, topic: str, contenu: str):
        cid     = topic.rsplit("/", 1)[-1]
        cle_aes = self._sessions.get(cid)
        if not cle_aes:
            self._journaliser(f"Commande reçue d'une session inconnue : {cid}")
            return
        try:
            commande = dechiffrer(cle_aes, contenu)
            self._journaliser(f"Commande reçue de {cid} : {json.dumps(commande, ensure_ascii=False)}")
        except CryptoErreur as exc:
            self._journaliser(f"Commande corrompue/invalide de {cid} : {exc}")
        except Exception as exc:
            self._journaliser(f"Échec inattendu du déchiffrement de la commande : {exc}")

    # ── Utilitaire ───────────────────────────────────────────────────────────

    def _journaliser(self, msg: str):
        print(f"[SERVEUR {time.strftime('%H:%M:%S')}] {msg}", flush=True)


if __name__ == "__main__":
    ServeurBoutique().demarrer()
