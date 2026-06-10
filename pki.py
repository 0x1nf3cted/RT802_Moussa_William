"""
pki.py | RT0806 : autorité de certification locale et certificats X.509.

Ce module sépare la PKI du chiffrement applicatif :
    - une CA locale signe le certificat du serveur ;
    - le client vérifie le certificat serveur avec le certificat de la CA ;
    - les clés et certificats sont sauvegardés au format PEM.
"""

import base64
import binascii
import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rembourrage_asym, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class ErreurPKI(ValueError):
    """Erreur fonctionnelle liée à la PKI ou à un certificat invalide."""


TAILLE_RSA_DEFAUT = 3072
NOM_CA_DEFAUT = "RT0806 Autorite Locale"
NOM_SERVEUR_DEFAUT = "rt0806.local"


def generer_paire_rsa(taille: int = TAILLE_RSA_DEFAUT):
    """Génère et retourne (clé_privée, clé_publique) RSA."""
    cle_privee = rsa.generate_private_key(public_exponent=65537, key_size=taille)
    return cle_privee, cle_privee.public_key()


def creer_certificat_ca(cle_ca, nom_commun: str = NOM_CA_DEFAUT):
    """Crée un certificat X.509 auto-signé pour la CA locale."""
    identite = _nom_x509(nom_commun)
    maintenant = _maintenant_utc()
    return (
        x509.CertificateBuilder()
        .subject_name(identite)
        .issuer_name(identite)
        .public_key(cle_ca.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(maintenant)
        .not_valid_after(maintenant + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(cle_ca.public_key()), critical=False)
        .sign(cle_ca, hashes.SHA256())
    )


def creer_certificat_serveur(cle_serveur, cle_ca, cert_ca, nom_commun: str = NOM_SERVEUR_DEFAUT):
    """Crée un certificat serveur signé par la CA locale."""
    maintenant = _maintenant_utc()
    return (
        x509.CertificateBuilder()
        .subject_name(_nom_x509(nom_commun))
        .issuer_name(cert_ca.subject)
        .public_key(cle_serveur.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(maintenant)
        .not_valid_after(maintenant + datetime.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(cle_serveur.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(cle_ca.public_key()),
            critical=False,
        )
        .sign(cle_ca, hashes.SHA256())
    )


def initialiser_pki_serveur(chemin_cle_ca: str, chemin_cert_ca: str, chemin_cle_serveur: str, chemin_cert_serveur: str):
    """Crée ou recharge la CA locale et l'identité serveur."""
    ca_creee = False
    cert_serveur_cree = False

    try:
        cle_ca = charger_cle_privee(chemin_cle_ca)
        cert_ca = charger_certificat(chemin_cert_ca)
        if not _certificat_ca_valide(cert_ca, cle_ca):
            raise ErreurPKI("CA locale invalide ou incohérente")
    except (FileNotFoundError, ValueError, ErreurPKI):
        cle_ca, _ = generer_paire_rsa()
        cert_ca = creer_certificat_ca(cle_ca)
        sauvegarder_cle_privee(cle_ca, chemin_cle_ca)
        sauvegarder_certificat(cert_ca, chemin_cert_ca)
        ca_creee = True

    try:
        cle_serveur = charger_cle_privee(chemin_cle_serveur)
    except (FileNotFoundError, ValueError):
        cle_serveur, _ = generer_paire_rsa()
        sauvegarder_cle_privee(cle_serveur, chemin_cle_serveur)
        cert_serveur_cree = True

    if cert_serveur_cree or not _certificat_serveur_valide(chemin_cert_serveur, cert_ca, cle_serveur):
        cert_serveur = creer_certificat_serveur(cle_serveur, cle_ca, cert_ca)
        sauvegarder_certificat(cert_serveur, chemin_cert_serveur)
        cert_serveur_cree = True

    return ca_creee, cert_serveur_cree


def sauvegarder_cle_privee(cle, chemin: str):
    with open(chemin, "wb") as f:
        f.write(
            cle.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )


def charger_cle_privee(chemin: str):
    with open(chemin, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def sauvegarder_certificat(cert, chemin: str):
    with open(chemin, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def charger_certificat(chemin: str):
    with open(chemin, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def certificat_depuis_b64(donnees: str):
    """Décode et parse un certificat PEM fourni en base64."""
    try:
        brut = base64.b64decode(donnees, validate=True)
        return x509.load_pem_x509_certificate(brut)
    except (binascii.Error, ValueError) as exc:
        raise ErreurPKI("Certificat serveur invalide ou corrompu") from exc


def verifier_certificat_serveur(cert_serveur, cert_ca):
    """Vérifie que le certificat serveur est signé par la CA locale."""
    try:
        contraintes = cert_ca.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise ErreurPKI("Certificat CA invalide | extension CA absente") from exc

    if not contraintes.ca:
        raise ErreurPKI("Certificat CA invalide | BasicConstraints.ca doit être vrai")
    if cert_serveur.issuer != cert_ca.subject:
        raise ErreurPKI("Certificat serveur rejeté | émetteur différent de la CA locale")

    _verifier_dates(cert_ca, "CA")
    _verifier_dates(cert_serveur, "serveur")
    _verifier_signature(cert_serveur, cert_ca)


def _certificat_serveur_valide(chemin_cert_serveur: str, cert_ca, cle_serveur) -> bool:
    try:
        cert_serveur = charger_certificat(chemin_cert_serveur)
        verifier_certificat_serveur(cert_serveur, cert_ca)
    except (FileNotFoundError, ValueError, ErreurPKI, InvalidSignature):
        return False
    return _cles_publiques_identiques(cert_serveur.public_key(), cle_serveur.public_key())


def _verifier_signature(cert_serveur, cert_ca):
    try:
        cert_ca.public_key().verify(
            cert_serveur.signature,
            cert_serveur.tbs_certificate_bytes,
            rembourrage_asym.PKCS1v15(),
            cert_serveur.signature_hash_algorithm,
        )
    except InvalidSignature as exc:
        raise ErreurPKI("Certificat serveur rejeté | signature CA incorrecte") from exc


def _verifier_dates(cert, libelle: str):
    maintenant = _maintenant_utc()
    debut, fin = _periode_validite(cert)
    if debut > maintenant or fin < maintenant:
        raise ErreurPKI(f"Certificat {libelle} expiré ou pas encore valide")


def _certificat_ca_valide(cert_ca, cle_ca) -> bool:
    try:
        contraintes = cert_ca.extensions.get_extension_for_class(x509.BasicConstraints).value
        _verifier_dates(cert_ca, "CA")
        cert_ca.public_key().verify(
            cert_ca.signature,
            cert_ca.tbs_certificate_bytes,
            rembourrage_asym.PKCS1v15(),
            cert_ca.signature_hash_algorithm,
        )
    except (ValueError, InvalidSignature, x509.ExtensionNotFound, ErreurPKI):
        return False
    return contraintes.ca and _cles_publiques_identiques(cert_ca.public_key(), cle_ca.public_key())


def _periode_validite(cert):
    if hasattr(cert, "not_valid_before_utc") and hasattr(cert, "not_valid_after_utc"):
        return cert.not_valid_before_utc, cert.not_valid_after_utc
    return (
        cert.not_valid_before.replace(tzinfo=datetime.timezone.utc),
        cert.not_valid_after.replace(tzinfo=datetime.timezone.utc),
    )


def _cles_publiques_identiques(cle_a, cle_b) -> bool:
    encodage = serialization.Encoding.PEM
    format_cle = serialization.PublicFormat.SubjectPublicKeyInfo
    return cle_a.public_bytes(encodage, format_cle) == cle_b.public_bytes(encodage, format_cle)


def _nom_x509(nom_commun: str):
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RT0806"),
            x509.NameAttribute(NameOID.COMMON_NAME, nom_commun),
        ]
    )


def _maintenant_utc():
    return datetime.datetime.now(datetime.timezone.utc)
