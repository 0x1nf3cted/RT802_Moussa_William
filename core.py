"""
core.py | RT0806 : primitives cryptographiques et configuration MQTT.

Algorithmes utilisés :
    - RSA + OAEP-SHA256     (enveloppement asymétrique de la clé de session)
    - AES-256-CBC + PKCS7   (chiffrement symétrique des messages)
    - SHA-1 (empreinte hex) (contrôle d'intégrité du texte clair)

Topics MQTT (préfixe rt0806/) :
    srv/cert            certificat serveur base64 PEM (retenu)
    auth/<cid>          client → serveur  clé AES enveloppée
    auth/<cid>/ready    serveur → client  accusé de réception de session
    products/<cid>      serveur → client  catalogue chiffré
    order/<cid>         client → serveur  commande chiffrée
"""

import os
import json
import base64
import hashlib
import binascii

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as rembourrage_asym
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as rembourrage_sym


class CryptoErreur(ValueError):
    """Erreur fonctionnelle liée aux données crypto invalides/corrompues."""

# ── Paramètres de connexion MQTT ─────────────────────────────────────────────

COURTIER = os.getenv("MQTT_BROKER", "127.0.0.1")
PORT     = int(os.getenv("MQTT_PORT", "1883"))

# ── Gabarits de topics ────────────────────────────────────────────────────────

T_CERTIFICAT = "rt0806/srv/cert"
T_AUTH       = "rt0806/auth/{cid}"
T_PRET       = "rt0806/auth/{cid}/ready"
T_PRODUITS   = "rt0806/products/{cid}"
T_COMMANDE   = "rt0806/order/{cid}"


# ── Enveloppement asymétrique de clé ─────────────────────────────────────────

_OAEP = rembourrage_asym.OAEP(
    mgf=rembourrage_asym.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def envelopper_cle(cle_publique, cle_aes: bytes) -> bytes:
    """Chiffre *cle_aes* avec la clé publique RSA du serveur (OAEP-SHA256)."""
    return cle_publique.encrypt(cle_aes, _OAEP)


def ouvrir_enveloppe_cle(cle_privee, cle_enveloppee: bytes) -> bytes:
    """Déchiffre une clé AES enveloppée avec la clé privée RSA du serveur."""
    return cle_privee.decrypt(cle_enveloppee, _OAEP)


# ── Enveloppe symétrique ──────────────────────────────────────────────────────

def chiffrer(cle_aes: bytes, donnees: dict) -> str:
    """Sérialise *donnees* en JSON, chiffre en AES-256-CBC et retourne l'enveloppe JSON.

    Champs de l'enveloppe :
        iv       | vecteur d'initialisation AES (base64, 16 octets)
        contenu  | texte chiffré avec padding PKCS7 (base64)
        empreinte | SHA-1 hex du texte clair (intégrité)
    """
    if len(cle_aes) != 32:
        raise CryptoErreur("Clé AES invalide | 32 octets attendus")
    texte_clair = json.dumps(donnees, sort_keys=True).encode()
    vi = os.urandom(16)

    ajusteur = rembourrage_sym.PKCS7(128).padder()
    rembourre = ajusteur.update(texte_clair) + ajusteur.finalize()

    chiffreur = Cipher(algorithms.AES(cle_aes), modes.CBC(vi)).encryptor()
    texte_chiffre = chiffreur.update(rembourre) + chiffreur.finalize()

    return json.dumps({
        "iv":        base64.b64encode(vi).decode(),
        "contenu":   base64.b64encode(texte_chiffre).decode(),
        "empreinte": hashlib.sha1(texte_clair).hexdigest(),
    })


def dechiffrer(cle_aes: bytes, enveloppe_json: str) -> dict:
    """Déchiffre et vérifie une enveloppe produite par :func:`chiffrer`."""
    if len(cle_aes) != 32:
        raise CryptoErreur("Clé AES invalide | 32 octets attendus")
    try:
        env = json.loads(enveloppe_json)
    except json.JSONDecodeError as exc:
        raise CryptoErreur("Enveloppe JSON invalide") from exc
    try:
        vi = base64.b64decode(env["iv"], validate=True)
        texte_chiffre = base64.b64decode(env["contenu"], validate=True)
        empreinte = env["empreinte"]
    except (KeyError, TypeError, binascii.Error) as exc:
        raise CryptoErreur("Enveloppe crypto incomplète ou corrompue") from exc
    if len(vi) != 16:
        raise CryptoErreur("IV AES invalide | 16 octets attendus")

    dechiffreur = Cipher(algorithms.AES(cle_aes), modes.CBC(vi)).decryptor()
    try:
        rembourre = dechiffreur.update(texte_chiffre) + dechiffreur.finalize()
    except ValueError as exc:
        raise CryptoErreur("Texte chiffré invalide pour AES-CBC") from exc

    desajusteur = rembourrage_sym.PKCS7(128).unpadder()
    try:
        texte_clair = desajusteur.update(rembourre) + desajusteur.finalize()
    except ValueError as exc:
        raise CryptoErreur("Padding PKCS7 invalide | données potentiellement altérées") from exc

    if hashlib.sha1(texte_clair).hexdigest() != empreinte:
        raise CryptoErreur("Contrôle d'intégrité échoué | empreinte SHA-1 incorrecte")

    try:
        return json.loads(texte_clair)
    except json.JSONDecodeError as exc:
        raise CryptoErreur("Contenu déchiffré invalide (JSON)") from exc
