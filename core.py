"""
core.py | RT0806 : primitives cryptographiques et configuration MQTT.

Algorithmes utilisés :
    - RSA-2048 + OAEP-SHA1  (enveloppement asymétrique de la clé de session)
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
import datetime
import binascii

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rembourrage_asym
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


# ── Identité RSA ──────────────────────────────────────────────────────────────

def generer_paire_rsa(taille: int = 2048):
    """Génère et retourne (clé_privée, clé_publique) RSA."""
    cle_privee = rsa.generate_private_key(public_exponent=65537, key_size=taille)
    return cle_privee, cle_privee.public_key()


def creer_certificat_auto_signe(cle_privee, nom_commun: str = "rt0806.local"):
    """Émet un certificat X.509 auto-signé valable un an pour *cle_privee*."""
    identite = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RT0806"),
        x509.NameAttribute(NameOID.COMMON_NAME, nom_commun),
    ])
    maintenant = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(identite)
        .issuer_name(identite)
        .public_key(cle_privee.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(maintenant)
        .not_valid_after(maintenant + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(cle_privee, hashes.SHA256())
    )


def sauvegarder_cle_privee(cle, chemin: str):
    with open(chemin, "wb") as f:
        f.write(cle.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))


def charger_cle_privee(chemin: str):
    with open(chemin, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def sauvegarder_certificat(cert, chemin: str):
    with open(chemin, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def certificat_depuis_b64(donnees: str):
    """Décode et parse un certificat PEM fourni en base64."""
    try:
        brut = base64.b64decode(donnees, validate=True)
        return x509.load_pem_x509_certificate(brut)
    except (binascii.Error, ValueError) as exc:
        raise CryptoErreur("Certificat serveur invalide ou corrompu") from exc


# ── Enveloppement asymétrique de clé ─────────────────────────────────────────

_OAEP = rembourrage_asym.OAEP(
    mgf=rembourrage_asym.MGF1(algorithm=hashes.SHA1()),
    algorithm=hashes.SHA1(),
    label=None,
)


def envelopper_cle(cle_publique, cle_aes: bytes) -> bytes:
    """Chiffre *cle_aes* avec la clé publique RSA du serveur (OAEP-SHA1)."""
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
