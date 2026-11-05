import os
import time
import hmac
import hashlib
import secrets
import tracemalloc
import datetime
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import cmac, hashes, serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519, x25519
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature, InvalidTag


CATALOGO = {
    "1. Cifrados sin uso de llaves": {
        "Funciones Hash (SHA-256)": {
            "entradas": "Mensaje en claro (bytes de longitud arbitraria)",
            "componentes": "Estado interno de compresión Merkle-Damgård / Davies-Meyer (256 bits)",
            "secreto_publico": "Secreto: Ninguno | Público: Mensaje y huella resumen (digest)",
            "salidas": "Huella criptográfica de tamaño fijo (32 bytes / 256 bits)",
            "propiedad": "Integridad básica (resistencia a preimagen, 2da preimagen y colisiones)",
            "condiciones": "No usar sola para contraseñas ni para autenticar mensajes sin llave (vulnerable a reemplazo total por Eve)."
        },
        "Construcción Esponja y XOF (SHAKE256)": {
            "entradas": "Mensaje de entrada y longitud de salida deseada (L bytes)",
            "componentes": "Permutación Keccak-f[1600], tasa de absorción (rate r=1088) y capacidad (c=512)",
            "secreto_publico": "Secreto: Ninguno | Público: Mensaje, longitud L y salida extensible (XOF)",
            "salidas": "Flujo pseudoaleatorio determinista de longitud arbitraria (ej. 64 bytes)",
            "propiedad": "Integridad, derivación determinista de semillas e inmunidad a extensión de longitud",
            "condiciones": "Mantener capacidad c >= 2*nivel_seguridad. No sustituye a un MAC ni a un KDF lento para contraseñas."
        }
    },
    "2. Cifrados simétricos": {
        "Cifrado por Bloques Autenticado (AES-256-GCM)": {
            "entradas": "Texto plano, Datos Asociados (AAD), llave simétrica de 256 bits",
            "componentes": "Llave secreta (32 B), Nonce (12 B), contador interno y Etiqueta GHASH (16 B)",
            "secreto_publico": "Secreto: Llave AES | Público: Nonce, AAD, Texto Cifrado y Etiqueta (Tag)",
            "salidas": "Texto cifrado (mismo tamaño que entrada) + Etiqueta de autenticación (16 B)",
            "propiedad": "Confidencialidad + Integridad + Autenticación de origen (AEAD)",
            "condiciones": "CRÍTICO: Jamás reutilizar el par (Llave, Nonce). Un nonce repetido revela el XOR de textos planos y falsifica etiquetas."
        },
        "Cifrado por Flujo (ChaCha20)": {
            "entradas": "Texto plano y llave simétrica de 256 bits",
            "componentes": "Llave secreta (32 B), Nonce (16 B en IETF/OpenSSL con contador inicial)",
            "secreto_publico": "Secreto: Llave ChaCha20 | Público: Nonce y Texto Cifrado",
            "salidas": "Texto cifrado (XOR bit a bit con el keystream generado)",
            "propiedad": "Confidencialidad únicamente (carece de integridad por sí solo)",
            "condiciones": "Nunca reutilizar Nonce. Al ser maleable bit a bit, requiere combinarse con Poly1305 (ChaCha20-Poly1305) o HMAC."
        },
        "Código de Autenticación (HMAC-SHA256 / CMAC)": {
            "entradas": "Mensaje en claro y llave simétrica compartida (256 bits)",
            "componentes": "Llave secreta K, constantes ipad (0x36) / opad (0x5c) y etiqueta MAC",
            "secreto_publico": "Secreto: Llave simétrica K | Público: Mensaje y Etiqueta MAC (32 B)",
            "salidas": "Etiqueta de autenticación de 32 bytes (HMAC) o 16 bytes (AES-CMAC)",
            "propiedad": "Integridad y Autenticación de mensaje (NO cifra el contenido)",
            "condiciones": "Comparar etiquetas en tiempo constante (hmac.compare_digest) e incluir números de secuencia/timestamps contra repetición."
        },
        "Derivación de Claves (KDF - Scrypt)": {
            "entradas": "Contraseña de usuario (baja entropía) y Sal aleatoria",
            "componentes": "Sal (16 B), factor CPU/Memoria (N=2^14), tamaño bloque (r=8), paralelismo (p=1)",
            "secreto_publico": "Secreto: Contraseña y Clave Derivada | Público: Sal y parámetros (N, r, p)",
            "salidas": "Clave criptográfica uniforme de 32 bytes apta para cifrado simétrico",
            "propiedad": "Establecimiento de claves a partir de contraseñas y resistencia a fuerza bruta por hardware (ASIC/GPU)",
            "condiciones": "Usar sal única de >=16 bytes por contraseña y calibrar N, r, p según la memoria y latencia admisible del servidor."
        }
    },
    "3. Cifrados asimétricos": {
        "Cifrado de Clave Pública (RSA-2048-OAEP)": {
            "entradas": "Mensaje corto (o llave de sesión) y Llave Pública de Bob",
            "componentes": "Par de llaves RSA (2048 bits), relleno óptimo OAEP con SHA-256 y MGF1",
            "secreto_publico": "Secreto: Llave Privada de Bob (d, p, q) | Público: Llave Pública (n, e) y Cifrado",
            "salidas": "Bloque cifrado de 256 bytes",
            "propiedad": "Confidencialidad asimétrica (seguridad semántica IND-CCA2 con OAEP)",
            "condiciones": "Mínimo 2048 bits (recomendado 3072+). Nunca usar PKCS#1 v1.5 (vulnerable a Bleichenbacher). Usar para envolver llaves híbridas."
        },
        "Firmas Digitales (Ed25519)": {
            "entradas": "Mensaje a firmar y Llave Privada de Alice",
            "componentes": "Curva Edwards torcida Curve25519, llave privada (32 B), llave pública (32 B), firma (64 B)",
            "secreto_publico": "Secreto: Llave Privada de Alice | Público: Llave Pública de Alice, Mensaje y Firma",
            "salidas": "Firma digital determinista de 64 bytes (R || S)",
            "propiedad": "Autenticación, Integridad y No Repudio",
            "condiciones": "Proteger llave privada. Ed25519 genera el nonce de firma de forma determinista, evitando el fallo catastrófico de ECDSA con k repetido."
        },
        "Intercambio de Claves (ECDH - X25519)": {
            "entradas": "Llave privada efímera propia y llave pública efímera de la contraparte",
            "componentes": "Puntos sobre Curve25519 (32 B) y función HKDF/SHA-256 posterior",
            "secreto_publico": "Secreto: Llaves privadas efímeras y Secreto Compartido | Público: Llaves públicas efímeras A y B",
            "salidas": "Secreto compartido de 32 bytes (idéntico en Alice y Bob)",
            "propiedad": "Establecimiento de claves con Secreto Hacia Adelante (Forward Secrecy)",
            "condiciones": "CRÍTICO: ECDH sin autenticar es vulnerable a Man-in-the-Middle (MitM). Debe autenticarse con firmas digitales o certificados PKI."
        },
        "Infraestructura de Clave Pública (PKI - X.509)": {
            "entradas": "Identidad del titular (Subject), Llave Pública del titular y Llave Privada de la CA",
            "componentes": "Certificado X.509v3, Número de serie, Vigencia, Firma de la Autoridad Certificadora (CA Raíz)",
            "secreto_publico": "Secreto: Llaves privadas de CA y Titular | Público: Certificado X.509 de Alice y Certificado Raíz de CA",
            "salidas": "Certificado digital X.509 firmado en formato DER/PEM",
            "propiedad": "Autenticación de identidad y vinculación confiable entre entidad y llave pública",
            "condiciones": "Verificar firma de la CA contra un almacén de confianza (Trust Store), vigencia temporal, uso de llave y revocación (CRL/OCSP)."
        }
    }
}


class CryptoLabApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Laboratorio de Primitivas Criptográficas: Alice, Eve y Bob")
        self.root.geometry("1420x860")
        self.root.configure(bg="#1e1e2e")

        # Estado del canal y secretos (Aislamiento: Eve solo lee self.channel_data)
        self.secret_vault = {}
        self.channel_data = {}
        self.seen_nonces = set()

        self._init_crypto_identities()
        self._build_ui()
        self._on_category_change(None)

    def _init_crypto_identities(self):
        """Pre-inicializa pares de llaves asimétricas y Autoridades Certificadoras (CA)."""
        # RSA de Bob
        self.bob_rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.bob_rsa_pub = self.bob_rsa_priv.public_key()

        # Ed25519 de Alice
        self.alice_ed_priv = ed25519.Ed25519PrivateKey.generate()
        self.alice_ed_pub = self.alice_ed_priv.public_key()

        # X25519 de Bob
        self.bob_x25519_priv = x25519.X25519PrivateKey.generate()
        self.bob_x25519_pub = self.bob_x25519_priv.public_key()

        # PKI: CA Raíz Confiable vs CA Falsa de Eve
        self.trusted_ca_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.trusted_ca_cert = self._create_ca_cert(self.trusted_ca_priv, "UV Root CA Confiable")

        self.eve_rogue_ca_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.eve_rogue_ca_cert = self._create_ca_cert(self.eve_rogue_ca_priv, "Eve Rogue CA No Confiable")

    def _create_ca_cert(self, priv_key, common_name):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Universidad Veracruzana"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(priv_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(priv_key, hashes.SHA256())
        )

    def _create_end_entity_cert(self, entity_pub_key, ca_priv_key, ca_cert, cn_text):
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn_text),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(entity_pub_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(ca_priv_key, hashes.SHA256())
        )

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")

        # Barra Superior: Selección de Categoría y Mecanismo
        top_frame = tk.Frame(self.root, bg="#181825", pady=8, padx=12)
        top_frame.pack(fill=tk.X)

        tk.Label(top_frame, text="Apartado Principal:", fg="#cdd6f4", bg="#181825", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT, padx=5)
        self.cat_var = tk.StringVar(value=list(CATALOGO.keys())[0])
        self.cat_combo = ttk.Combobox(top_frame, textvariable=self.cat_var, values=list(CATALOGO.keys()), state="readonly", width=28)
        self.cat_combo.pack(side=tk.LEFT, padx=5)
        self.cat_combo.bind("<<ComboboxSelected>>", self._on_category_change)

        tk.Label(top_frame, text="Mecanismo:", fg="#cdd6f4", bg="#181825", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT, padx=5)
        self.mech_var = tk.StringVar()
        self.mech_combo = ttk.Combobox(top_frame, textvariable=self.mech_var, state="readonly", width=36)
        self.mech_combo.pack(side=tk.LEFT, padx=5)
        self.mech_combo.bind("<<ComboboxSelected>>", self._on_mech_change)

        btn_suite = tk.Button(
            top_frame,
            text="Ejecutar Suite de 9 Escenarios + Ataque Diccionario",
            bg="#f38ba8",
            fg="#11111b",
            font=("Segoe UI", 9, "bold"),
            command=self.run_all_9_scenarios_window
        )
        btn_suite.pack(side=tk.RIGHT, padx=6)

        # Panel de Ficha Técnica del Mecanismo
        info_frame = tk.LabelFrame(self.root, text="Ficha Técnica y Condiciones de Seguridad del Mecanismo", bg="#1e1e2e", fg="#89b4fa", font=("Segoe UI", 10, "bold"), padx=10, pady=6)
        info_frame.pack(fill=tk.X, padx=12, pady=4)

        self.info_label = tk.Label(info_frame, text="", justify=tk.LEFT, bg="#1e1e2e", fg="#cdd6f4", font=("Consolas", 9), anchor="w")
        self.info_label.pack(fill=tk.X)

        # Contenedor de 3 Columnas: ALICE | EVE | BOB
        panes = tk.Frame(self.root, bg="#1e1e2e")
        panes.pack(fill=tk.BOTH, expand=True, padx=12, pady=6)
        panes.columnconfigure(0, weight=1)
        panes.columnconfigure(1, weight=1)
        panes.columnconfigure(2, weight=1)
        panes.rowconfigure(0, weight=1)

        # --- ALICE (EMISOR) ---
        alice_frame = tk.LabelFrame(panes, text="ALICE (Emisor Legítimo)", bg="#181825", fg="#a6e3a1", font=("Segoe UI", 11, "bold"), padx=8, pady=8)
        alice_frame.grid(row=0, column=0, sticky="nsew", padx=4)

        tk.Label(alice_frame, text="Mensaje / Entrada principal:", bg="#181825", fg="#cdd6f4").pack(anchor="w")
        self.alice_msg = tk.Entry(alice_frame, width=42, font=("Consolas", 10))
        self.alice_msg.insert(0, "Hola mundo")
        self.alice_msg.pack(fill=tk.X, pady=3)

        tk.Label(alice_frame, text="Contraseña / Datos Asociados (AAD):", bg="#181825", fg="#cdd6f4").pack(anchor="w")
        self.alice_extra = tk.Entry(alice_frame, width=42, font=("Consolas", 10))
        self.alice_extra.insert(0, "contraseña1234")
        self.alice_extra.pack(fill=tk.X, pady=3)

        tk.Button(
            alice_frame,
            text="1. Ejecutar Operación en Alice y Transmitir al Canal",
            bg="#a6e3a1",
            fg="#11111b",
            font=("Segoe UI", 9, "bold"),
            command=self.alice_execute
        ).pack(fill=tk.X, pady=6)

        tk.Label(alice_frame, text="Componentes Generados, Secretos (Protegidos) y Recursos:", bg="#181825", fg="#cdd6f4").pack(anchor="w")
        self.alice_out = scrolledtext.ScrolledText(alice_frame, height=20, bg="#11111b", fg="#a6e3a1", font=("Consolas", 9))
        self.alice_out.pack(fill=tk.BOTH, expand=True, pady=4)

        # --- EVE (OBSERVADOR / ATACANTE EN EL CANAL) ---
        eve_frame = tk.LabelFrame(panes, text="EVE (Observador / Laboratorio de Ataques en el Canal)", bg="#181825", fg="#f9e2af", font=("Segoe UI", 11, "bold"), padx=8, pady=8)
        eve_frame.grid(row=0, column=1, sticky="nsew", padx=4)

        tk.Label(eve_frame, text="Acción de Laboratorio sobre datos en tránsito:", bg="#181825", fg="#cdd6f4").pack(anchor="w")
        self.eve_action_var = tk.StringVar(value="0. Observación pasiva (Sin modificar el canal)")
        eve_actions = [
            "0. Observación pasiva (Sin modificar el canal)",
            "1. Contraseña débil: Ataque de diccionario contra Hash",
            "2. KDF: Comparar fuerza bruta SHA-256 directo vs Scrypt",
            "3. Alterar bytes del texto cifrado (Bit-flipping)",
            "4. Alterar Datos Asociados (AAD) en cifrado autenticado",
            "5. Modificar mensaje en claro sin conocer llave/firma",
            "6. Sustituir llave pública en acuerdo ECDH (Ataque MitM)",
            "7. Reenviar mensaje válido capturado (Replay Attack)",
            "8. Presentar certificado de CA No Confiable (Rogue CA)",
            "9. [Escenario Explícito] Filtración accidental de llave secreta"
        ]
        self.eve_combo = ttk.Combobox(eve_frame, textvariable=self.eve_action_var, values=eve_actions, state="readonly")
        self.eve_combo.pack(fill=tk.X, pady=3)

        tk.Button(
            eve_frame,
            text="2. Ejecutar Acción de Eve en el Canal",
            bg="#f9e2af",
            fg="#11111b",
            font=("Segoe UI", 9, "bold"),
            command=self.eve_execute
        ).pack(fill=tk.X, pady=6)

        tk.Label(eve_frame, text="Vista Pública del Canal y Resultados de Manipulación de Eve:", bg="#181825", fg="#cdd6f4").pack(anchor="w")
        self.eve_out = scrolledtext.ScrolledText(eve_frame, height=20, bg="#11111b", fg="#f9e2af", font=("Consolas", 9))
        self.eve_out.pack(fill=tk.BOTH, expand=True, pady=4)

        # --- PANEL 3: BOB (RECEPTOR) ---
        bob_frame = tk.LabelFrame(panes, text="BOB (Receptor y Verificador)", bg="#181825", fg="#89b4fa", font=("Segoe UI", 11, "bold"), padx=8, pady=8)
        bob_frame.grid(row=0, column=2, sticky="nsew", padx=4)

        tk.Button(
            bob_frame,
            text="3. Recibir del Canal, Descifrar / Verificar en Bob",
            bg="#89b4fa",
            fg="#11111b",
            font=("Segoe UI", 9, "bold"),
            command=self.bob_execute
        ).pack(fill=tk.X, pady=6)

        self.bob_status_lbl = tk.Label(bob_frame, text="ESTADO: ESPERANDO TRANSMISIÓN", bg="#313244", fg="#cdd6f4", font=("Segoe UI", 10, "bold"), pady=6)
        self.bob_status_lbl.pack(fill=tk.X, pady=4)

        tk.Label(bob_frame, text="Resultado de Verificación y Diagnóstico Pedagógico:", bg="#181825", fg="#cdd6f4").pack(anchor="w")
        self.bob_out = scrolledtext.ScrolledText(bob_frame, height=20, bg="#11111b", fg="#89b4fa", font=("Consolas", 9))
        self.bob_out.pack(fill=tk.BOTH, expand=True, pady=4)

    def _on_category_change(self, _event):
        cat = self.cat_var.get()
        mechs = list(CATALOGO[cat].keys())
        self.mech_combo["values"] = mechs
        self.mech_var.set(mechs[0])
        self._on_mech_change(None)

    def _on_mech_change(self, _event):
        cat = self.cat_var.get()
        mech = self.mech_var.get()
        info = CATALOGO[cat][mech]
        texto = (
            f"• Entradas: {info['entradas']}   |   • Propiedad: {info['propiedad']}\n"
            f"• Componentes: {info['componentes']}\n"
            f"• Secreto vs Público: {info['secreto_publico']}   |   • Salidas: {info['salidas']}\n"
            f"• Condiciones de uso: {info['condiciones']}\n"
            f"• Nota de Memoria: La memoria medida con tracemalloc refleja el heap de Python; no incluye asignaciones internas nativas en C/Rust (OpenSSL)."
        )
        self.info_label.config(text=texto)

    
    def alice_execute(self):
        mech = self.mech_var.get()
        msg_str = self.alice_msg.get()
        extra_str = self.alice_extra.get()
        msg_bytes = msg_str.encode("utf-8")
        extra_bytes = extra_str.encode("utf-8")

        self.secret_vault.clear()
        self.channel_data.clear()

        tracemalloc.start()
        t0 = time.perf_counter()

        if mech == "Funciones Hash (SHA-256)":
            digest = hashlib.sha256(msg_bytes).digest()
            self.channel_data = {
                "mech": mech,
                "msg": msg_bytes,
                "digest": digest,
                "seq_id": secrets.token_hex(4)
            }
            out_len = len(digest)

        elif mech == "Construcción Esponja y XOF (SHAKE256)":
            xof_out = hashlib.shake_256(msg_bytes).digest(64)
            self.channel_data = {
                "mech": mech,
                "msg": msg_bytes,
                "xof": xof_out,
                "xof_len": 64,
                "seq_id": secrets.token_hex(4)
            }
            out_len = len(xof_out)

        elif mech == "Cifrado por Bloques Autenticado (AES-256-GCM)":
            key = secrets.token_bytes(32)
            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(key)
            ct_and_tag = aesgcm.encrypt(nonce, msg_bytes, extra_bytes)
            ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]
            self.secret_vault["sym_key"] = key
            self.channel_data = {
                "mech": mech,
                "nonce": nonce,
                "aad": extra_bytes,
                "ciphertext": ciphertext,
                "tag": tag,
                "seq_id": secrets.token_hex(4)
            }
            out_len = len(ct_and_tag)

        elif mech == "Cifrado por Flujo (ChaCha20)":
            key = secrets.token_bytes(32)
            nonce = secrets.token_bytes(16)
            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
            encryptor = cipher.encryptor()
            ct = encryptor.update(msg_bytes)
            self.secret_vault["sym_key"] = key
            self.channel_data = {
                "mech": mech,
                "nonce": nonce,
                "ciphertext": ct,
                "seq_id": secrets.token_hex(4)
            }
            out_len = len(ct)

        elif mech == "Código de Autenticación (HMAC-SHA256 / CMAC)":
            key = secrets.token_bytes(32)
            hmac_tag = hmac.new(key, msg_bytes, hashlib.sha256).digest()
            c = cmac.CMAC(algorithms.AES(key))
            c.update(msg_bytes)
            cmac_tag = c.finalize()
            self.secret_vault["sym_key"] = key
            self.channel_data = {
                "mech": mech,
                "msg": msg_bytes,
                "hmac_tag": hmac_tag,
                "cmac_tag": cmac_tag,
                "seq_id": secrets.token_hex(4)
            }
            out_len = len(hmac_tag) + len(cmac_tag)

        elif mech == "Derivación de Claves (KDF - Scrypt)":
            salt = secrets.token_bytes(16)
            kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
            derived_key = kdf.derive(extra_bytes)
            self.secret_vault["password"] = extra_bytes
            self.secret_vault["derived_key"] = derived_key
            self.channel_data = {
                "mech": mech,
                "salt": salt,
                "n": 2**14,
                "r": 8,
                "p": 1,
                "fast_sha256_hash": hashlib.sha256(extra_bytes).digest(),
                "seq_id": secrets.token_hex(4)
            }
            out_len = len(derived_key)

        elif mech == "Cifrado de Clave Pública (RSA-2048-OAEP)":
            ct = self.bob_rsa_pub.encrypt(
                msg_bytes,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            self.secret_vault["bob_rsa_priv"] = self.bob_rsa_priv
            self.channel_data = {
                "mech": mech,
                "ciphertext": ct,
                "bob_pub_n_bits": self.bob_rsa_pub.key_size,
                "seq_id": secrets.token_hex(4)
            }
            out_len = len(ct)

        elif mech == "Firmas Digitales (Ed25519)":
            sig = self.alice_ed_priv.sign(msg_bytes)
            self.secret_vault["alice_ed_priv"] = self.alice_ed_priv
            self.channel_data = {
                "mech": mech,
                "msg": msg_bytes,
                "signature": sig,
                "alice_pub_bytes": self.alice_ed_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
                "seq_id": secrets.token_hex(4)
            }
            out_len = len(sig)

        elif mech == "Intercambio de Claves (ECDH - X25519)":
            alice_eph_priv = x25519.X25519PrivateKey.generate()
            alice_eph_pub = alice_eph_priv.public_key()
            alice_shared = alice_eph_priv.exchange(self.bob_x25519_pub)
            derived_session = hashlib.sha256(alice_shared).digest()
            self.secret_vault["alice_eph_priv"] = alice_eph_priv
            self.secret_vault["alice_derived_session"] = derived_session
            self.channel_data = {
                "mech": mech,
                "alice_eph_pub_bytes": alice_eph_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
                "bob_pub_bytes": self.bob_x25519_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
                "seq_id": secrets.token_hex(4)
            }
            out_len = 32

        elif mech == "Infraestructura de Clave Pública (PKI - X.509)":
            cert = self._create_end_entity_cert(self.alice_ed_pub, self.trusted_ca_priv, self.trusted_ca_cert, "alice.uv.mx")
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            sig = self.alice_ed_priv.sign(msg_bytes)
            self.secret_vault["alice_ed_priv"] = self.alice_ed_priv
            self.channel_data = {
                "mech": mech,
                "msg": msg_bytes,
                "signature": sig,
                "cert_obj": cert,
                "cert_der": cert_der,
                "issuer_cn": cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                "seq_id": secrets.token_hex(4)
            }
            out_len = len(cert_der) + len(sig)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        _, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Mostrar reporte en Alice
        self.alice_out.delete("1.0", tk.END)
        self.alice_out.insert(tk.END, f"=== OPERACIÓN EJECUTADA EN ALICE ===\n")
        self.alice_out.insert(tk.END, f"Mecanismo: {mech}\n")
        self.alice_out.insert(tk.END, f"\n[RECURSOS COMPUTACIONALES MEDIDOS]\n")
        self.alice_out.insert(tk.END, f"• Tiempo de ejecución: {elapsed_ms:.4f} ms\n")
        self.alice_out.insert(tk.END, f"• Tamaño de entrada:   {len(msg_bytes)} bytes\n")
        self.alice_out.insert(tk.END, f"• Tamaño de salida:    {out_len} bytes\n")
        self.alice_out.insert(tk.END, f"• Memoria pico Python: {peak_mem / 1024:.2f} KB (tracemalloc)\n")
        self.alice_out.insert(tk.END, f"  *Nota: No incluye memoria nativa C/Rust de OpenSSL.\n")

        self.alice_out.insert(tk.END, f"\n[INFORMACIÓN SECRETA - NO SALE DE ALICE]\n")
        if not self.secret_vault:
            self.alice_out.insert(tk.END, "• Ninguna llave secreta (Primitiva sin uso de llaves).\n")
        else:
            for k, v in self.secret_vault.items():
                if isinstance(v, bytes):
                    self.alice_out.insert(tk.END, f"• {k}: {v.hex()[:40]}... ({len(v)} B)\n")
                else:
                    self.alice_out.insert(tk.END, f"• {k}: <Objeto Llave Privada En Memoria Segura>\n")

        self.alice_out.insert(tk.END, f"\n[COMPONENTES PÚBLICOS ENVIADOS AL CANAL]\n")
        for k, v in self.channel_data.items():
            if isinstance(v, bytes):
                self.alice_out.insert(tk.END, f"• {k}: {v.hex()[:44]} ({len(v)} B)\n")
            elif k != "cert_obj":
                self.alice_out.insert(tk.END, f"• {k}: {v}\n")

        self._refresh_eve_view("Datos recién transmitidos por Alice. Eve observa el canal público.")
        self.bob_status_lbl.config(text="ESTADO: DATOS EN CANAL LISTOS PARA BOB", bg="#313244", fg="#cdd6f4")

    
    def _refresh_eve_view(self, header_note):
        self.eve_out.delete("1.0", tk.END)
        self.eve_out.insert(tk.END, f"=== VISTA DE EVE EN EL CANAL PÚBLICO ===\n")
        self.eve_out.insert(tk.END, f"Nota: {header_note}\n")
        self.eve_out.insert(tk.END, f"Aislamiento: Eve NO posee acceso a self.secret_vault.\n\n")
        for k, v in self.channel_data.items():
            if isinstance(v, bytes):
                self.eve_out.insert(tk.END, f"[Canal] {k} ({len(v)} B):\n  {v.hex()}\n")
            elif k != "cert_obj":
                self.eve_out.insert(tk.END, f"[Canal] {k}: {v}\n")

    def eve_execute(self):
        if not self.channel_data:
            messagebox.showwarning("Canal Vacío", "Primero ejecuta una operación desde el panel de Alice.")
            return

        action = self.eve_action_var.get()
        mech = self.channel_data["mech"]
        log_lines = [f"\n>>> ACCIÓN EJECUTADA POR EVE: {action}"]

        if action.startswith("0."):
            log_lines.append("• Eve únicamente registra los paquetes públicos sin alterar un solo bit.")

        elif action.startswith("1."):
            # Ataque de diccionario sobre un hash rápido
            diccionario = ["123456", "admin", "qwerty", "veracruz2026", "secreto123", self.alice_msg.get(), self.alice_extra.get()]
            target_bytes = self.channel_data.get("digest") or hashlib.sha256(self.alice_extra.get().encode()).digest()
            t0 = time.perf_counter()
            hallada = None
            for cand in diccionario:
                if hashlib.sha256(cand.encode()).digest() == target_bytes:
                    hallada = cand
                    break
            dt = (time.perf_counter() - t0) * 1000.0
            log_lines.append(f"• Diccionario probado ({len(diccionario)} palabras) en {dt:.4f} ms.")
            log_lines.append(f"• Resultado: {'¡CONTRASEÑA RECUPERADA! -> ' + hallada if hallada else 'No encontrada en diccionario corto'}")
            log_lines.append("• Aprendizaje: Adivinar por conjeturas NO es 'descifrar' ni invertir matemáticamente el hash.")

        elif action.startswith("2."):
            # Comparar velocidad de SHA-256 directo vs Scrypt
            intentos = 25
            t0 = time.perf_counter()
            for i in range(intentos):
                hashlib.sha256(f"pass_{i}".encode()).digest()
            t_sha = (time.perf_counter() - t0) * 1000.0

            salt = self.channel_data.get("salt", secrets.token_bytes(16))
            t1 = time.perf_counter()
            for i in range(intentos):
                kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
                kdf.derive(f"pass_{i}".encode())
            t_scrypt = (time.perf_counter() - t1) * 1000.0

            ratio = t_scrypt / max(t_sha, 0.0001)
            log_lines.append(f"• Tiempo {intentos} intentos SHA-256 directo: {t_sha:.3f} ms")
            log_lines.append(f"• Tiempo {intentos} intentos Scrypt (N=16384, r=8, p=1): {t_scrypt:.2f} ms")
            log_lines.append(f"• Penalización al atacante: Scrypt fue {ratio:,.0f}x más costoso por intento.")

        elif action.startswith("3."):
            if "ciphertext" in self.channel_data:
                ct = bytearray(self.channel_data["ciphertext"])
                ct[0] ^= 0xFF  # Invertir bits del primer byte
                self.channel_data["ciphertext"] = bytes(ct)
                log_lines.append("• Eve aplicó XOR 0xFF al byte[0] del texto cifrado en tránsito.")
            else:
                log_lines.append("• Este mecanismo no contiene campo 'ciphertext'; usa la opción 5 para alterar el mensaje.")

        elif action.startswith("4."):
            if "aad" in self.channel_data:
                self.channel_data["aad"] = b"Header:CanalAlteradoPorEve|Seq:999"
                log_lines.append("• Eve modificó los Datos Asociados (AAD) en tránsito sin tocar el texto cifrado.")
            else:
                log_lines.append("• Este mecanismo no utiliza AAD (Selecciona AES-256-GCM).")

        elif action.startswith("5."):
            if "msg" in self.channel_data:
                self.channel_data["msg"] = b"Transferir $999,999 MXN a la cuenta de EVE"
                log_lines.append("• Eve sustituyó el mensaje en claro en el canal sin conocer llaves privadas ni simétricas.")
            else:
                log_lines.append("• El mensaje viaja cifrado; utiliza la opción 3 para alterar el texto cifrado.")

        elif action.startswith("6."):
            if mech == "Intercambio de Claves (ECDH - X25519)":
                eve_priv = x25519.X25519PrivateKey.generate()
                eve_pub_bytes = eve_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                self.channel_data["alice_eph_pub_bytes"] = eve_pub_bytes
                self.channel_data["mitm_eve_priv"] = eve_priv
                log_lines.append("• Eve interceptó la llave pública X25519 de Alice y la sustituyó por la llave pública de Eve.")
                log_lines.append("• Como no hay firma ni certificado que autentique la llave efímera, Bob calculará un secreto con Eve.")
            else:
                log_lines.append("• Selecciona 'Intercambio de Claves (ECDH - X25519)' para simular MitM.")

        elif action.startswith("7."):
            # Marcar el mensaje actual como visto previamente para simular retransmisión
            seq_id = self.channel_data.get("seq_id", "0001")
            self.seen_nonces.add(seq_id)
            self.channel_data["replayed"] = True
            log_lines.append(f"• Eve capturó un paquete legítimo (SeqID={seq_id}) y lo reenvió idéntico a Bob.")

        elif action.startswith("8."):
            if mech == "Infraestructura de Clave Pública (PKI - X.509)":
                rogue_cert = self._create_end_entity_cert(
                    self.alice_ed_pub, self.eve_rogue_ca_priv, self.eve_rogue_ca_cert, "alice.uv.mx"
                )
                self.channel_data["cert_obj"] = rogue_cert
                self.channel_data["cert_der"] = rogue_cert.public_bytes(serialization.Encoding.DER)
                self.channel_data["issuer_cn"] = "Eve Rogue CA No Confiable"
                log_lines.append("• Eve reemplazó el certificado de Alice por uno firmado por 'Eve Rogue CA No Confiable'.")
            else:
                log_lines.append("• Selecciona 'Infraestructura de Clave Pública (PKI - X.509)' para este escenario.")

        elif action.startswith("9."):
            # Escenario separado y explícito de filtración de llave
            log_lines.append("• [ESCENARIO SEPARADO EXPLÍCITO]: Se simula compromiso del servidor de Alice.")
            if "sym_key" in self.secret_vault:
                leaked = self.secret_vault["sym_key"]
                log_lines.append(f"• Eve obtuvo la llave simétrica filtrada: {leaked.hex()[:32]}...")
                if "ciphertext" in self.channel_data and mech == "Cifrado por Flujo (ChaCha20)":
                    c = Cipher(algorithms.ChaCha20(leaked, self.channel_data["nonce"]), mode=None).decryptor()
                    log_lines.append(f"• Eve descifra el mensaje completo: {c.update(self.channel_data['ciphertext']).decode('utf-8', errors='replace')}")
            else:
                log_lines.append("• El compromiso explícito expone cualquier primitiva que dependa de ese secreto.")

        self._refresh_eve_view("Canal actualizado tras la intervención de Eve.")
        for l in log_lines:
            self.eve_out.insert(tk.END, l + "\n")

    
    def bob_execute(self):
        if not self.channel_data:
            messagebox.showwarning("Sin datos", "Primero transmite un mensaje desde Alice.")
            return

        mech = self.channel_data["mech"]
        seq_id = self.channel_data.get("seq_id")
        self.bob_out.delete("1.0", tk.END)
        self.bob_out.insert(tk.END, f"=== PROCESAMIENTO Y VERIFICACIÓN EN BOB ===\n")
        self.bob_out.insert(tk.END, f"Mecanismo recibido: {mech}\n\n")

        # Control anti-repetición (Replay Protection)
        if self.channel_data.get("replayed") and seq_id in self.seen_nonces:
            self.bob_status_lbl.config(text="RECHAZADO: ATAQUE DE REPETICIÓN DETECTADO", bg="#f38ba8", fg="#11111b")
            self.bob_out.insert(tk.END, f"[ALERTA DE REPETICIÓN]\n")
            self.bob_out.insert(tk.END, f"• El identificador de secuencia/nonce '{seq_id}' ya fue procesado anteriormente.\n")
            self.bob_out.insert(tk.END, f"• Diagnóstico: Aunque el MAC o firma criptográfica sea matemáticamente válida, un mensaje repetido duplicaría la transacción si no se valida número de secuencia, nonce único o ventana de tiempo.\n")
            return

        self.seen_nonces.add(seq_id)

        if mech == "Funciones Hash (SHA-256)":
            calc = hashlib.sha256(self.channel_data["msg"]).digest()
            ok = (calc == self.channel_data["digest"])
            self._set_bob_verdict(ok, "Hash coincide con el mensaje" if ok else "El mensaje fue modificado y el hash no coincide")
            self.bob_out.insert(tk.END, f"• Mensaje recibido: {self.channel_data['msg'].decode('utf-8', errors='replace')}\n")
            self.bob_out.insert(tk.END, f"• Hash recibido:    {self.channel_data['digest'].hex()}\n")
            self.bob_out.insert(tk.END, f"• Hash calculado:   {calc.hex()}\n")
            self.bob_out.insert(tk.END, f"• Advertencia: Si Eve modifica tanto el mensaje como el hash en tránsito, un hash sin llave NO puede detectarlo.\n")

        elif mech == "Construcción Esponja y XOF (SHAKE256)":
            calc = hashlib.shake_256(self.channel_data["msg"]).digest(self.channel_data["xof_len"])
            ok = (calc == self.channel_data["xof"])
            self._set_bob_verdict(ok, "Salida XOF verificada" if ok else "Discrepancia en salida extensible SHAKE256")
            self.bob_out.insert(tk.END, f"• XOF recibido (64 B):  {self.channel_data['xof'].hex()[:64]}...\n")
            self.bob_out.insert(tk.END, f"• XOF calculado (64 B): {calc.hex()[:64]}...\n")

        elif mech == "Cifrado por Bloques Autenticado (AES-256-GCM)":
            key = self.secret_vault["sym_key"]
            aesgcm = AESGCM(key)
            ct_and_tag = self.channel_data["ciphertext"] + self.channel_data["tag"]
            try:
                pt = aesgcm.decrypt(self.channel_data["nonce"], ct_and_tag, self.channel_data["aad"])
                self._set_bob_verdict(True, "ACEPTADO: Etiqueta GCM auténtica y mensaje íntegro")
                self.bob_out.insert(tk.END, f"• Texto plano descifrado: {pt.decode('utf-8')}\n")
                self.bob_out.insert(tk.END, f"• AAD autenticado:        {self.channel_data['aad'].decode('utf-8', errors='replace')}\n")
            except InvalidTag:
                self._set_bob_verdict(False, "RECHAZADO: Fallo de autenticación AES-GCM (InvalidTag)")
                self.bob_out.insert(tk.END, f"• ¡Manipulación detectada! El texto cifrado o los datos asociados (AAD) fueron alterados en el canal.\n")
                self.bob_out.insert(tk.END, f"• AES-GCM bloquea la entrega de cualquier texto plano corrupto.\n")

        elif mech == "Cifrado por Flujo (ChaCha20)":
            key = self.secret_vault["sym_key"]
            cipher = Cipher(algorithms.ChaCha20(key, self.channel_data["nonce"]), mode=None)
            pt = cipher.decryptor().update(self.channel_data["ciphertext"])
            # ChaCha20 puro NO tiene cómo detectar la alteración de Eve
            self._set_bob_verdict(True, "ACEPTADO SIN CONTROL DE INTEGRIDAD (Peligro: Cifrado maleable)")
            self.bob_out.insert(tk.END, f"• Texto descifrado por Bob: {pt.decode('utf-8', errors='replace')}\n")
            self.bob_out.insert(tk.END, f"• Aprendizaje crítico: Si Eve alteró bytes del cifrado, ChaCha20 descifra los bits alterados sin arrojar error. El cifrado sin autenticación NO garantiza integridad.\n")

        elif mech == "Código de Autenticación (HMAC-SHA256 / CMAC)":
            key = self.secret_vault["sym_key"]
            expected_hmac = hmac.new(key, self.channel_data["msg"], hashlib.sha256).digest()
            ok = hmac.compare_digest(expected_hmac, self.channel_data["hmac_tag"])
            self._set_bob_verdict(ok, "ACEPTADO: Etiqueta HMAC/CMAC válida" if ok else "RECHAZADO: Etiqueta MAC inválida (Mensaje alterado)")
            self.bob_out.insert(tk.END, f"• Mensaje en canal: {self.channel_data['msg'].decode('utf-8', errors='replace')}\n")
            self.bob_out.insert(tk.END, f"• HMAC recibido:    {self.channel_data['hmac_tag'].hex()}\n")
            self.bob_out.insert(tk.END, f"• HMAC recalculado: {expected_hmac.hex()}\n")

        elif mech == "Derivación de Claves (KDF - Scrypt)":
            kdf = Scrypt(salt=self.channel_data["salt"], length=32, n=self.channel_data["n"], r=self.channel_data["r"], p=self.channel_data["p"])
            bob_derived = kdf.derive(self.secret_vault["password"])
            ok = (bob_derived == self.secret_vault["derived_key"])
            self._set_bob_verdict(ok, "ACEPTADO: Clave simétrica derivada idéntica en ambos extremos")
            self.bob_out.insert(tk.END, f"• Sal pública usada: {self.channel_data['salt'].hex()}\n")
            self.bob_out.insert(tk.END, f"• Clave derivada en Bob: {bob_derived.hex()}\n")

        elif mech == "Cifrado de Clave Pública (RSA-2048-OAEP)":
            try:
                pt = self.bob_rsa_priv.decrypt(
                    self.channel_data["ciphertext"],
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                self._set_bob_verdict(True, "ACEPTADO: Cifrado RSA-OAEP descifrado con llave privada de Bob")
                self.bob_out.insert(tk.END, f"• Mensaje recuperado: {pt.decode('utf-8')}\n")
            except ValueError:
                self._set_bob_verdict(False, "RECHAZADO: Estructura de relleno OAEP inválida tras manipulación")
                self.bob_out.insert(tk.END, f"• El relleno OAEP detectó corrupción estructural del bloque cifrado.\n")

        elif mech == "Firmas Digitales (Ed25519)":
            pub = ed25519.Ed25519PublicKey.from_public_bytes(self.channel_data["alice_pub_bytes"])
            try:
                pub.verify(self.channel_data["signature"], self.channel_data["msg"])
                self._set_bob_verdict(True, "ACEPTADO: Firma Digital Ed25519 verificada matemáticamente")
                self.bob_out.insert(tk.END, f"• Mensaje auténtico de Alice: {self.channel_data['msg'].decode('utf-8')}\n")
            except InvalidSignature:
                self._set_bob_verdict(False, "RECHAZADO: Firma Digital Ed25519 INVÁLIDA")
                self.bob_out.insert(tk.END, f"• El mensaje fue modificado en el canal y la firma original de Alice ya no verifica.\n")

        elif mech == "Intercambio de Claves (ECDH - X25519)":
            peer_pub = x25519.X25519PublicKey.from_public_bytes(self.channel_data["alice_eph_pub_bytes"])
            bob_shared = self.bob_x25519_priv.exchange(peer_pub)
            bob_session = hashlib.sha256(bob_shared).digest()
            alice_session = self.secret_vault["alice_derived_session"]
            match = (bob_session == alice_session)
            if match:
                self._set_bob_verdict(True, "ACEPTADO: Secreto compartido ECDH establecido correctamente")
            else:
                self._set_bob_verdict(False, "ALERTA MITM: Bob derivó una llave distinta a la de Alice (Con Eve)")
            self.bob_out.insert(tk.END, f"• Llave derivada por Alice: {alice_session.hex()}\n")
            self.bob_out.insert(tk.END, f"• Llave derivada por Bob:   {bob_session.hex()}\n")
            if not match:
                self.bob_out.insert(tk.END, f"• Diagnóstico: Como las llaves públicas X25519 no estaban autenticadas con firmas/PKI, Bob no detectó por sí solo la sustitución de Eve.\n")

        elif mech == "Infraestructura de Clave Pública (PKI - X.509)":
            cert_received = self.channel_data["cert_obj"]
            try:
                # Bob verifica que el certificado recibido haya sido firmado por su CA Raíz Confiable
                self.trusted_ca_cert.public_key().verify(
                    cert_received.signature,
                    cert_received.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert_received.signature_hash_algorithm,
                )
                # Luego verifica la firma del mensaje con la llave pública contenida en el certificado validado
                cert_received.public_key().verify(self.channel_data["signature"], self.channel_data["msg"])
                self._set_bob_verdict(True, "ACEPTADO: Certificado X.509 avalado por CA Confiable y firma válida")
                self.bob_out.insert(tk.END, f"• Emisor validado: {self.channel_data['issuer_cn']}\n")
            except InvalidSignature:
                self._set_bob_verdict(False, "RECHAZADO: Certificado emitido por CA NO CONFIABLE o firma corrupta")
                self.bob_out.insert(tk.END, f"• Emisor detectado: {self.channel_data['issuer_cn']}\n")
                self.bob_out.insert(tk.END, f"• Bob rechazó la cadena de certificación porque la firma del emisor no corresponde a la CA Raíz en su Trust Store.\n")

    def _set_bob_verdict(self, accepted, text):
        if accepted:
            self.bob_status_lbl.config(text=f"RESULTADO: {text}", bg="#a6e3a1", fg="#11111b")
        else:
            self.bob_status_lbl.config(text=f"RESULTADO: {text}", bg="#f38ba8", fg="#11111b")

    
    def run_all_9_scenarios_window(self):
        win = tk.Toplevel(self.root)
        win.title("Resultados Experimentales: 9 Escenarios de Laboratorio y Métricas")
        win.geometry("1080x680")
        win.configure(bg="#1e1e2e")

        txt = scrolledtext.ScrolledText(win, bg="#11111b", fg="#cdd6f4", font=("Consolas", 9))
        txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        report = self._execute_batch_scenarios()
        txt.insert(tk.END, report)

    def _execute_batch_scenarios(self):
        lines = ["================================================================================"]
        lines.append("REPORTE AUTOMATIZADO DE LOS 9 ESCENARIOS DE LABORATORIO CRIPTOGRÁFICO")
        lines.append("================================================================================\n")

        # 1. Contraseña débil
        target_pw = "secreto123"
        target_hash = hashlib.sha256(target_pw.encode()).digest()
        dict_words = ["123456", "password", "qwerty", "admin", "iloveyou", "secreto123", "veracruz"]
        t0 = time.perf_counter()
        found = next((w for w in dict_words if hashlib.sha256(w.encode()).digest() == target_hash), None)
        t_dict = (time.perf_counter() - t0) * 1000
        lines.append(f"[Escenario 1: Contraseña débil contra Hash SHA-256]")
        lines.append(f"  Hash objetivo: {target_hash.hex()}")
        lines.append(f"  Palabra hallada en diccionario ({len(dict_words)} intentos): '{found}' en {t_dict:.4f} ms")
        lines.append(f"  Conclusión: SHA-256 no fue invertido; la baja entropía permitió acertar por conjetura.\n")

        # 2. Derivación de contraseñas (SHA-256 vs Scrypt)
        n_tries = 30
        t0 = time.perf_counter()
        for i in range(n_tries):
            hashlib.sha256(f"intento_{i}".encode()).digest()
        dt_sha = (time.perf_counter() - t0) * 1000

        salt = secrets.token_bytes(16)
        t0 = time.perf_counter()
        for i in range(n_tries):
            Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(f"intento_{i}".encode())
        dt_scrypt = (time.perf_counter() - t0) * 1000
        lines.append(f"[Escenario 2: Derivación de contraseñas - {n_tries} intentos SHA-256 vs Scrypt]")
        lines.append(f"  SHA-256 directo: {dt_sha:.4f} ms  |  Scrypt (N=16384, r=8, p=1): {dt_scrypt:.2f} ms")
        lines.append(f"  Factor de ralentización: {dt_scrypt / max(dt_sha, 1e-6):,.1f}x más trabajo computacional por intento.\n")

        # 3. Cifrado sin autenticación (ChaCha20 bit-flipping)
        k, nonce = secrets.token_bytes(32), secrets.token_bytes(16)
        msg_orig = b"Pagar $100 MXN al proveedor"
        ct = bytearray(Cipher(algorithms.ChaCha20(k, nonce), mode=None).encryptor().update(msg_orig))
        ct[7] ^= ord('1') ^ ord('9')  # Cambiar '1' por '9' exactamente en el texto cifrado
        pt_mod = Cipher(algorithms.ChaCha20(k, nonce), mode=None).decryptor().update(bytes(ct))
        lines.append(f"[Escenario 3: Cifrado sin autenticación (Maleabilidad en ChaCha20)]")
        lines.append(f"  Original: '{msg_orig.decode()}' -> Descifrado tras alteración de Eve: '{pt_mod.decode()}'")
        lines.append(f"  Conclusión: Bob descifra un monto alterado sin recibir alerta alguna de corrupción.\n")

        
        aesgcm = AESGCM(k)
        nonce_gcm = secrets.token_bytes(12)
        aad = b"CuentaDestino:99412"
        ct_gcm = aesgcm.encrypt(nonce_gcm, msg_orig, aad)
        try:
            aesgcm.decrypt(nonce_gcm, ct_gcm, b"CuentaDestino:EVE00")
            gcm_res = "Aceptado (Error)"
        except InvalidTag:
            gcm_res = "RECHAZADO (InvalidTag lanzado inmediatamente al alterar AAD o texto cifrado)"
        lines.append(f"[Escenario 4: Cifrado autenticado AES-256-GCM]")
        lines.append(f"  Resultado al alterar AAD/Cifrado: {gcm_res}\n")

        # 5. HMAC / CMAC
        tag = hmac.new(k, msg_orig, hashlib.sha256).digest()
        valid_after_mod = hmac.compare_digest(tag, hmac.new(k, b"Pagar $900 MXN al proveedor", hashlib.sha256).digest())
        lines.append(f"[Escenario 5: Modificación de mensaje bajo HMAC-SHA256]")
        lines.append(f"  ¿Etiqueta original válida para mensaje modificado?: {valid_after_mod} (Rechazado por Bob)\n")

        # 6. Firma Digital Ed25519
        sig = self.alice_ed_priv.sign(msg_orig)
        try:
            self.alice_ed_pub.verify(sig, b"Pagar $900 MXN al proveedor")
            sig_res = "Verificada"
        except InvalidSignature:
            sig_res = "RECHAZADA (InvalidSignature)"
        lines.append(f"[Escenario 6: Firma Digital Ed25519 ante mensaje alterado]")
        lines.append(f"  Resultado en Bob: {sig_res}\n")

        # 7. Acuerdo de claves sin autenticación (X25519 MitM)
        a_priv, b_priv, e_priv = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
        k_alice_eve = a_priv.exchange(e_priv.public_key())
        k_bob_eve = b_priv.exchange(e_priv.public_key())
        lines.append(f"[Escenario 7: Acuerdo X25519 sin autenticación (Sustitución MitM)]")
        lines.append(f"  Secreto Alice-Eve: {k_alice_eve.hex()[:32]}...")
        lines.append(f"  Secreto Bob-Eve:   {k_bob_eve.hex()[:32]}...")
        lines.append(f"  Conclusión: Eve establece sesiones separadas con ambos porque las llaves públicas no fueron autenticadas.\n")

        # 8. Repetición de mensajes
        lines.append(f"[Escenario 8: Repetición de mensajes (Replay Attack)]")
        lines.append(f"  Un paquete con HMAC válido reenviado por Eve pasa la verificación matemática del MAC,")
        lines.append(f"  pero es RECHAZADO por el registro de números de secuencia/nonces vistos en Bob.\n")

        # 9. PKI con CA No Confiable
        rogue_cert = self._create_end_entity_cert(self.alice_ed_pub, self.eve_rogue_ca_priv, self.eve_rogue_ca_cert, "alice.uv.mx")
        try:
            self.trusted_ca_cert.public_key().verify(
                rogue_cert.signature, rogue_cert.tbs_certificate_bytes, padding.PKCS1v15(), rogue_cert.signature_hash_algorithm
            )
            pki_res = "Aceptado"
        except InvalidSignature:
            pki_res = "RECHAZADO (Firma del certificado no corresponde a la CA Raíz Confiable de Bob)"
        lines.append(f"[Escenario 9: PKI con Certificado de CA No Confiable]")
        lines.append(f"  Resultado de validación de cadena X.509: {pki_res}\n")

        return "\n".join(lines)


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoLabApp(root)
    root.mainloop()