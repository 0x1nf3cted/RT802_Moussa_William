#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
client.py | RT0806 : client de la boutique sécurisée.

Déroulement du protocole :
  1. Souscrire à rt0806/srv/cert, rt0806/auth/<cid>/ready
     et rt0806/products/<cid>.
  2. À réception du certificat serveur (retained) :
       - Vérifier qu'il est signé par la CA locale.
       - Extraire la clé publique RSA.
       - Générer une clé AES-256 aléatoire.
       - Envelopper la clé AES avec RSA-OAEP-SHA256.
       - Publier la clé enveloppée sur rt0806/auth/<cid>.
  3. Attendre l'accusé de réception du serveur (rt0806/auth/<cid>/ready).
  4. Recevoir et déchiffrer le catalogue sur rt0806/products/<cid>.
  5. Laisser l'utilisateur choisir un article et envoyer
     la commande chiffrée sur rt0806/order/<cid>.
"""

import os
import json
import time
import uuid
import base64
import secrets
import argparse
import threading

import paho.mqtt.client as mqtt

from core import (
    COURTIER, PORT,
    T_CERTIFICAT, T_AUTH, T_PRET, T_PRODUITS, T_COMMANDE,
    envelopper_cle, chiffrer, dechiffrer, CryptoErreur,
)
from pki import ErreurPKI, certificat_depuis_b64, charger_certificat, verifier_certificat_serveur

_REPERTOIRE = os.path.dirname(os.path.abspath(__file__))
_REPERTOIRE_PKI = os.getenv("PKI_DIR", _REPERTOIRE)
CHEMIN_CERT_CA = os.path.join(_REPERTOIRE_PKI, "ca_cert.pem")
ID_CLIENT = f"c-{uuid.uuid4().hex[:8]}"


class ClientBoutique:

    def __init__(self, adresse_livraison: str, id_article_auto: int | None = None):
        self._adresse   = adresse_livraison
        self._id_article_auto = id_article_auto
        self._cle_aes: bytes | None = None
        self._catalogue: list | None = None

        self._session_etablie  = threading.Event()
        self._catalogue_pret   = threading.Event()

        self._mq = mqtt.Client(
            client_id=ID_CLIENT,
            protocol=mqtt.MQTTv311,
            callback_api_version=mqtt.CallbackAPIVersion.VERSION1,
        )
        self._mq.on_connect    = self._a_la_connexion
        self._mq.on_disconnect = self._a_la_deconnexion
        self._mq.on_message    = self._a_la_reception

    # ── Cycle de vie ─────────────────────────────────────────────────────────

    def demarrer(self):
        self._journaliser(f"Connexion au courtier {COURTIER}:{PORT} (identifiant : {ID_CLIENT})")
        self._mq.connect(COURTIER, PORT, keepalive=60)
        self._mq.loop_start()
        try:
            self._passer_commande()
        finally:
            time.sleep(0.5)
            self._mq.loop_stop()
            self._mq.disconnect()


    # ── Rappels MQTT ─────────────────────────────────────────────────────────

    def _a_la_connexion(self, client, userdata, flags, rc):
        if rc != 0:
            self._journaliser(f"Connexion refusée (rc={rc})")
            return
        self._journaliser("Connecté | attente du certificat serveur")
        client.subscribe(T_CERTIFICAT)
        client.subscribe(T_PRET.format(cid=ID_CLIENT))
        client.subscribe(T_PRODUITS.format(cid=ID_CLIENT))

    def _a_la_deconnexion(self, client, userdata, rc):
        self._journaliser(f"Déconnecté (rc={rc})")

    def _a_la_reception(self, client, userdata, msg):
        topic   = msg.topic
        try:
            contenu = msg.payload.decode()
        except UnicodeDecodeError:
            self._journaliser(f"Message ignoré sur {topic} | payload non UTF-8")
            return

        if topic == T_CERTIFICAT:
            self._etablir_session(contenu)
        elif topic == T_PRET.format(cid=ID_CLIENT):
            self._journaliser("Session confirmée par le serveur")
            self._session_etablie.set()
        elif topic == T_PRODUITS.format(cid=ID_CLIENT):
            self._recevoir_catalogue(contenu)

    # ── Traitements ──────────────────────────────────────────────────────────

    def _etablir_session(self, cert_b64: str):
        try:
            certificat      = certificat_depuis_b64(cert_b64)
            cert_ca         = charger_certificat(CHEMIN_CERT_CA)
            verifier_certificat_serveur(certificat, cert_ca)
            self._cle_aes   = secrets.token_bytes(32)
            cle_enveloppee  = envelopper_cle(certificat.public_key(), self._cle_aes)
            self._mq.publish(
                T_AUTH.format(cid=ID_CLIENT),
                json.dumps({
                    "cid":             ID_CLIENT,
                    "cle_enveloppee":  base64.b64encode(cle_enveloppee).decode(),
                }),
            )
            self._journaliser("Handshake envoyé | certificat vérifié, clé AES-256 enveloppée RSA-OAEP-SHA256")
        except (ErreurPKI, FileNotFoundError) as exc:
            self._journaliser(f"Handshake rejeté | certificat invalide : {exc}")
        except CryptoErreur as exc:
            self._journaliser(f"Handshake rejeté | erreur crypto : {exc}")
        except Exception as exc:
            self._journaliser(f"Erreur inattendue lors du handshake : {exc}")

    def _recevoir_catalogue(self, enveloppe: str):
        if not self._cle_aes:
            self._journaliser("Catalogue reçu avant l'établissement de la clé AES | ignoré")
            return
        try:
            donnees          = dechiffrer(self._cle_aes, enveloppe)
            articles = donnees.get("articles")
            if not isinstance(articles, list):
                raise CryptoErreur("Catalogue invalide | liste 'articles' absente")
            self._catalogue = articles
            self._journaliser("Catalogue reçu et déchiffré")
            self._catalogue_pret.set()
        except CryptoErreur as exc:
            self._journaliser(f"Catalogue corrompu/invalide : {exc}")
        except Exception as exc:
            self._journaliser(f"Échec inattendu du déchiffrement du catalogue : {exc}")

    # ── Saisie et envoi de commande ───────────────────────────────────────────

    def _passer_commande(self):
        if not self._catalogue_pret.wait(timeout=30):
            raise TimeoutError("Délai dépassé | aucun catalogue reçu du serveur")

        print("\nArticles disponibles :")
        for article in self._catalogue:
            print(f"  [{article['id']}] {article['ref']}  {article['libelle']}  |  {article['prix']} €  (stock : {article['stock']})")

        if self._id_article_auto is None:
            saisie = input("\nID de l'article à commander : ").strip()
            try:
                id_article = int(saisie)
            except ValueError as exc:
                raise ValueError("Identifiant d'article invalide") from exc
        else:
            id_article = self._id_article_auto
            self._journaliser(f"Sélection automatique de l'article {id_article}")

        article = next((a for a in self._catalogue if a["id"] == id_article), None)
        if not article:
            raise ValueError(f"Article {id_article} introuvable dans le catalogue")

        enveloppe = chiffrer(self._cle_aes, {
            "article":  article,
            "livraison": self._adresse,
            "horodatage": int(time.time()),
        })
        self._mq.publish(T_COMMANDE.format(cid=ID_CLIENT), enveloppe)
        self._journaliser("Commande transmise (chiffrée AES-256)")

    # ── Utilitaire ───────────────────────────────────────────────────────────

    def _journaliser(self, msg: str):
        print(f"[CLIENT {time.strftime('%H:%M:%S')}] {msg}", flush=True)


if __name__ == "__main__":
    analyseur = argparse.ArgumentParser(description="Client RT0806 | boutique sécurisée MQTT")
    analyseur.add_argument(
        "--adresse",
        default=os.getenv("CLIENT_ADRESSE", "9 rue des Crayères, 51100 Reims"),
        help="Adresse de livraison",
    )
    analyseur.add_argument(
        "--article-id",
        type=int,
        default=int(os.getenv("CLIENT_ARTICLE_ID")) if os.getenv("CLIENT_ARTICLE_ID") else None,
        help="ID d'article à commander automatiquement",
    )
    args = analyseur.parse_args()
    ClientBoutique(args.adresse, args.article_id).demarrer()
