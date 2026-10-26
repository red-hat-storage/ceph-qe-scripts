"""
GKLM (IBM Guardium Key Lifecycle Manager) container install and KMIP client setup.

Mirrors the Keycloak pattern used by STS ASWI tests:
  - skip install if the container is already running
  - configure via curl REST (login, client, cert, symmetric key)
  - wire RGW KMIP by placing certs under /var/run/ceph/<fsid>/ (already
    mounted into the RGW container as /var/run/ceph/) — no orch remount

Expects under configs/rgw/gklm/:
  IGKLM_5.1_F_CNTR_LNX.tar
  rgwselfsigned.cert / rgwselfsigned.key   (KMIP client identity)
  optional license zip
"""

import json
import logging
import os
import re
import time

import v2.utils.utils as utils

log = logging.getLogger()

GKLM_CONFIGS_DIR = "/home/cephuser/configs/rgw/gklm"
GKLM_IMAGE_TAR = f"{GKLM_CONFIGS_DIR}/IGKLM_5.1_F_CNTR_LNX.tar"
# Source KMIP client identity (from rgw_configs)
CONFIG_CERT_PATH = f"{GKLM_CONFIGS_DIR}/rgwselfsigned.cert"
CONFIG_KEY_PATH = f"{GKLM_CONFIGS_DIR}/rgwselfsigned.key"
GKLM_LICENSE_CANDIDATES = (
    f"{GKLM_CONFIGS_DIR}/IGKLM_5.1_F_License.zip",
    f"{GKLM_CONFIGS_DIR}/gklm.license.zip",
    f"{GKLM_CONFIGS_DIR}/SKLM_License.zip",
)
GKLM_CONTAINER_NAME = "gklm"
GKLM_POSTGRES_NAME = "gklm-postgres"
GKLM_APP_VOLUME = "gklmAppVolume"
GKLM_PG_VOLUME = "gklmPostgresVolume"
# Persist key alias across suite steps on the same host
GKLM_KEY_ALIAS_FILE = f"{GKLM_CONFIGS_DIR}/kmip_key_alias"
# Host path: /var/run/ceph/<fsid>/...  →  container path: /var/run/ceph/...
RGW_CERT_BASENAME = "rgw_certificate.crt"
RGW_KEY_BASENAME = "rgw_certificate.key"
# Paths RGW reads inside its container (cephadm already mounts /var/run/ceph/<fsid>)
RGW_CONTAINER_CERT = f"/var/run/ceph/{RGW_CERT_BASENAME}"
RGW_CONTAINER_KEY = f"/var/run/ceph/{RGW_KEY_BASENAME}"

DEFAULT_ADMIN_USER = "sklmadmin"
DEFAULT_ADMIN_PASSWORD = "Db2@pass123"
DEFAULT_DB_USER = "klmdb51"
DEFAULT_DB_NAME = "klmdb51"
DEFAULT_DB_PASSWORD = "GklmDb@pass123"
DEFAULT_LIBERTY_PASSWORD = "Ch@ngemypa55word"
DEFAULT_SEED = "68d95f0081f1dbfc0b06de9b0916df1c"
DEFAULT_CLIENT_NAME = "rgw_kmip_client"
DEFAULT_CERT_ALIAS = "rgw_kmip_cert"
DEFAULT_KEY_PREFIX = "rgw"
DEFAULT_SERVER_CERT_ALIAS = "gklm_server_cert"
REST_PREFIX = "/GKLM/rest/v1"
# Path inside GKLM container for IMPORT_CERT
CONTAINER_CERT_IMPORT_PATH = "/opt/ibm/wlp/products/sklm/data/rgwselfsigned.crt"


class GKLM:
    """Deploy GKLM 5.1 as a normal podman container and configure KMIP for RGW SSE-KMS."""

    def __init__(
        self,
        ip_addr=None,
        admin_user=DEFAULT_ADMIN_USER,
        admin_password=DEFAULT_ADMIN_PASSWORD,
        client_name=DEFAULT_CLIENT_NAME,
        cert_alias=DEFAULT_CERT_ALIAS,
        key_prefix=DEFAULT_KEY_PREFIX,
        image_tar=GKLM_IMAGE_TAR,
        configure_rgw=True,
    ):
        self.ip_addr = ip_addr or utils.get_localhost_ip_address()
        self.admin_user = admin_user
        self.admin_password = admin_password
        self.client_name = client_name
        self.cert_alias = cert_alias
        self.key_prefix = key_prefix
        self.image_tar = image_tar
        self.rest_base = f"https://{self.ip_addr}:9443{REST_PREFIX}"
        self.auth_token = None
        self.key_alias = None

        self._validate_config_certs()
        self.fsid = utils.get_cluster_fsid().strip()
        # Host-side destination already bind-mounted into RGW as /var/run/ceph/
        self.host_cert_dir = f"/var/run/ceph/{self.fsid}"
        self.host_cert_path = f"{self.host_cert_dir}/{RGW_CERT_BASENAME}"
        self.host_key_path = f"{self.host_cert_dir}/{RGW_KEY_BASENAME}"

        out = utils.exec_shell_cmd("sudo podman ps") or ""
        if GKLM_CONTAINER_NAME in out:
            log.info("GKLM container already running; skipping deployment")
            self.auth_token = self.login()
            self._ensure_kmip_listener()
            self.key_alias = self._load_or_ensure_kmip_setup()
        else:
            self.install_gklm()
            self.auth_token = self.login()
            self._upload_license_if_present()
            # KMIP :5696 only listens after a KEYSERVING_TLS system cert + restart
            self._ensure_kmip_listener()
            self.key_alias = self.configure_kmip_client()

        if configure_rgw:
            self.configure_rgw_for_kmip()

    def _validate_config_certs(self):
        missing = [
            p for p in (CONFIG_CERT_PATH, CONFIG_KEY_PATH) if not os.path.exists(p)
        ]
        if missing:
            raise Exception(
                "KMIP client cert/key missing from rgw_configs: "
                f"{missing}. Expected {CONFIG_CERT_PATH} and {CONFIG_KEY_PATH}."
            )

    # ------------------------------------------------------------------
    # Install
    # ------------------------------------------------------------------
    def install_gklm(self):
        """Load image tar, start PostgreSQL + GKLM containers, wait until REST is up."""
        if not os.path.exists(self.image_tar):
            raise Exception(
                f"GKLM image tar not found at {self.image_tar}. "
                "Clone rgw_configs (git_clone_configs_repo) and place "
                "IGKLM_5.1_F_CNTR_LNX.tar under configs/rgw/gklm/."
            )

        self._open_firewall_ports()
        image_ref = self._load_image()
        self._start_postgres()
        self._start_gklm_app(image_ref)
        self._wait_until_ready(timeout=600)

    def _load_image(self):
        log.info(f"Loading GKLM image from {self.image_tar}")
        out = utils.exec_shell_cmd(f"sudo podman load -i {self.image_tar}")
        if out is False:
            raise Exception("podman load of GKLM image failed")
        log.info(out)
        # "Loaded image(s): <ref>" or "Loaded image: <ref>"
        match = re.search(r"Loaded image(?:\(s\))?:\s*(\S+)", out)
        if match:
            return match.group(1).strip()
        # Fallback: newest non-postgres image
        images = utils.exec_shell_cmd(
            "sudo podman images --format '{{.Repository}}:{{.Tag}}'"
        )
        for line in (images or "").splitlines():
            ref = line.strip()
            if ref and "postgres" not in ref.lower():
                log.info(f"Using loaded image ref: {ref}")
                return ref
        raise Exception("Could not determine loaded GKLM image name")

    def _start_postgres(self):
        running = utils.exec_shell_cmd("sudo podman ps") or ""
        if GKLM_POSTGRES_NAME in running:
            log.info("PostgreSQL container already running")
            return
        # Remove stale stopped container with same name
        utils.exec_shell_cmd(f"sudo podman rm -f {GKLM_POSTGRES_NAME}", return_err=True)
        cmd = (
            f"sudo podman run -d --name {GKLM_POSTGRES_NAME} "
            f"--restart=always "
            f"-e POSTGRES_USER={DEFAULT_DB_USER} "
            f"-e POSTGRES_PASSWORD={DEFAULT_DB_PASSWORD} "
            f"-e POSTGRES_DB={DEFAULT_DB_NAME} "
            f"-p 5432:5432 "
            f"-v {GKLM_PG_VOLUME}:/var/lib/postgresql/data "
            f"docker.io/library/postgres:15"
        )
        out = utils.exec_shell_cmd(cmd)
        if out is False:
            raise Exception("Failed to start GKLM PostgreSQL container")
        log.info("Waiting for PostgreSQL to accept connections")
        time.sleep(30)

    def _start_gklm_app(self, image_ref):
        utils.exec_shell_cmd(
            f"sudo podman rm -f {GKLM_CONTAINER_NAME}", return_err=True
        )
        # Host IP so the app container can reach the published postgres port.
        # Set both Liberty password env names for image compatibility.
        cmd = (
            f"sudo podman run -d --name {GKLM_CONTAINER_NAME} "
            f"--hostname gklm.local "
            f"--restart=always "
            f"-p 9443:9443 -p 5696:5696 -p 1441:1441 -p 3801:3801 "
            f"-e LICENSE=accept "
            f"-e DB_TYPE=postgres "
            f"-e DB_HOST={self.ip_addr} "
            f"-e DB_PORT=5432 "
            f"-e DB_USER={DEFAULT_DB_USER} "
            f"-e DB_NAME={DEFAULT_DB_NAME} "
            f"-e DB_PASSWORD={DEFAULT_DB_PASSWORD} "
            f"-e SKLM_SEED={DEFAULT_SEED} "
            f"-e SKLMADMIN_USERNAME={self.admin_user} "
            f"-e SKLMADMIN_PASSWORD={self.admin_password} "
            f"-e LIBERTY_KEYSTORE_PASSWORD={DEFAULT_LIBERTY_PASSWORD} "
            f"-e LIBERTY_KEY_STORE_PASSWORD={DEFAULT_LIBERTY_PASSWORD} "
            f"-v {GKLM_APP_VOLUME}:/opt/ibm/wlp/products "
            f"{image_ref}"
        )
        out = utils.exec_shell_cmd(cmd)
        if out is False:
            raise Exception("Failed to start GKLM application container")
        log.info(f"Started GKLM container from image {image_ref}")

    def _wait_until_ready(self, timeout=600):
        log.info("Waiting for GKLM REST/UI to become ready")
        deadline = time.time() + timeout
        login_url = f"{self.rest_base}/ckms/login"
        while time.time() < deadline:
            # Prefer login API; UI path varies by release
            out = utils.exec_shell_cmd(
                "curl -sk -o /dev/null -w '%{http_code}' "
                f"-H 'Content-Type: application/json' "
                f"-X POST '{login_url}' "
                f'-d \'{{"userid":"{self.admin_user}",'
                f'"password":"{self.admin_password}"}}\''
            )
            code = (out or "").strip()
            if code in ("200", "201"):
                log.info("GKLM login API is ready")
                return
            logs = utils.exec_shell_cmd(
                f"sudo podman logs --tail 20 {GKLM_CONTAINER_NAME}", return_err=True
            )
            if logs and "server started" in logs.lower():
                # Give REST a few more seconds after log message
                time.sleep(15)
                out = utils.exec_shell_cmd(
                    "curl -sk -o /dev/null -w '%{http_code}' "
                    f"-H 'Content-Type: application/json' "
                    f"-X POST '{login_url}' "
                    f'-d \'{{"userid":"{self.admin_user}",'
                    f'"password":"{self.admin_password}"}}\''
                )
                if (out or "").strip() in ("200", "201"):
                    log.info("GKLM is ready after server-started log")
                    return
            log.info(f"GKLM not ready yet (login HTTP {code}); sleeping 20s")
            time.sleep(20)
        raise Exception(f"GKLM did not become ready within {timeout}s")

    def _open_firewall_ports(self):
        for port in ("9443/tcp", "5696/tcp", "1441/tcp", "3801/tcp", "5432/tcp"):
            utils.exec_shell_cmd(
                f"sudo firewall-cmd --permanent --add-port={port}", return_err=True
            )
        utils.exec_shell_cmd("sudo firewall-cmd --reload", return_err=True)

    # ------------------------------------------------------------------
    # REST helpers (curl, same flow as GUI client/key setup)
    # ------------------------------------------------------------------
    def login(self):
        out = utils.exec_shell_cmd(
            "curl -sk --show-error --fail "
            "-H 'Content-Type: application/json' "
            f"-X POST '{self.rest_base}/ckms/login' "
            f'-d \'{{"userid":"{self.admin_user}",'
            f'"password":"{self.admin_password}"}}\''
        )
        if out is False:
            raise Exception("GKLM login failed")
        body = json.loads(out)
        token = (
            body.get("UserAuthId") or body.get("userAuthId") or body.get("userauthid")
        )
        if not token:
            raise Exception(f"GKLM login response missing UserAuthId: {body}")
        log.info("GKLM login successful")
        return token

    def _auth_headers(self):
        return (
            f"-H 'Accept: application/json' "
            f"-H 'Accept-Language: en' "
            f"-H 'Authorization: SKLMAuth userAuthId={self.auth_token}'"
        )

    def _curl_json(self, method, path, data=None, fail_ok=False):
        data_arg = ""
        if data is not None:
            payload = json.dumps(data).replace("'", "'\\''")
            data_arg = f"-H 'Content-Type: application/json' -d '{payload}'"
        fail_flag = "" if fail_ok else "--fail"
        cmd = (
            f"curl -sk --show-error {fail_flag} -X {method} "
            f"{self._auth_headers()} {data_arg} "
            f"'{self.rest_base}{path}'"
        )
        out = utils.exec_shell_cmd(cmd)
        if out is False:
            if fail_ok:
                return None
            raise Exception(f"GKLM REST {method} {path} failed")
        out = (out or "").strip()
        if not out:
            return {}
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return {"raw": out}

    def _upload_license_if_present(self):
        license_path = next(
            (p for p in GKLM_LICENSE_CANDIDATES if os.path.exists(p)), None
        )
        if not license_path:
            log.info("No GKLM license zip found under configs; skipping license upload")
            return
        log.info(f"Uploading GKLM license from {license_path}")
        out = utils.exec_shell_cmd(
            "curl -sk --show-error "
            f"{self._auth_headers()} "
            f"-F 'fileToUpload=@{license_path}' "
            f"'{self.rest_base}/filetransfer/upload/license'"
        )
        log.info(out)

    # ------------------------------------------------------------------
    # KMIP listener (system cert + restart)
    # ------------------------------------------------------------------
    def _kmip_port_open(self):
        """Return True if TCP 5696 accepts connections on this host."""
        out = utils.exec_shell_cmd(
            "timeout 3 bash -c 'echo >/dev/tcp/127.0.0.1/5696' "
            "&& echo OK || echo FAIL",
            return_err=True,
        )
        return out is not False and "OK" in str(out)

    def _ensure_kmip_listener(self):
        """
        GKLM container publishes 5696 but the KMIP service only binds after a
        KEYSERVING_TLS system certificate exists and the server is restarted.
        Without this, RGW sees: BIO_do_connect failed ... Connection refused.
        """
        if self._kmip_port_open():
            log.info("KMIP port 5696 is already accepting connections")
            return

        log.info(
            "KMIP :5696 not listening — creating KEYSERVING_TLS system cert "
            "and restarting GKLM"
        )
        self._create_keyserving_system_cert()
        self._restart_gklm_server()
        # Token invalidated by restart
        self.auth_token = self.login()
        self._wait_for_kmip_port(timeout=180)

    def _create_keyserving_system_cert(self):
        """Create (or reuse) system cert used for KMIP/TLS key serving."""
        existing = self._curl_json("GET", "/system/certificates", fail_ok=True) or {}
        aliases = set()
        entries = []
        if isinstance(existing, list):
            entries = existing
        elif isinstance(existing, dict):
            for key in (
                "certificate",
                "certificates",
                "systemCertificate",
                "systemCertificates",
            ):
                val = existing.get(key)
                if isinstance(val, list):
                    entries = val
                    break
        for entry in entries:
            alias = entry.get("alias") or entry.get("Alias") or entry.get("name")
            if alias:
                aliases.add(str(alias))
        if DEFAULT_SERVER_CERT_ALIAS in aliases:
            log.info(
                f"System cert {DEFAULT_SERVER_CERT_ALIAS} already exists; "
                "ensuring KEYSERVING_TLS usage"
            )
            self._curl_json(
                "PUT",
                "/system/certificates",
                {
                    "alias": DEFAULT_SERVER_CERT_ALIAS,
                    "addUsageSubtype": "KEYSERVING_TLS",
                },
                fail_ok=True,
            )
            return

        log.info(f"Creating system certificate {DEFAULT_SERVER_CERT_ALIAS}")
        resp = self._curl_json(
            "POST",
            "/system/certificates",
            {
                "type": "Self-signed",
                "alias": DEFAULT_SERVER_CERT_ALIAS,
                "cn": "gklm.local",
                "ou": "Storage",
                "o": "Red Hat Inc",
                "country": "IN",
                "validity": "3650",
                "algorithm": "RSA",
                "usageSubtype": "KEYSERVING_TLS",
            },
        )
        log.info(resp)

    def _restart_gklm_server(self):
        log.info("Restarting GKLM server so KMIP picks up system cert")
        resp = self._curl_json(
            "POST", "/ckms/servermanagement/restartServer", fail_ok=True
        )
        log.info(resp)
        log.info("Sleeping 90s for GKLM restart")
        time.sleep(90)

    def _wait_for_kmip_port(self, timeout=180):
        log.info("Waiting for KMIP port 5696 to accept connections")
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._kmip_port_open():
                log.info("KMIP port 5696 is ready")
                return
            time.sleep(10)
        raise Exception(
            f"KMIP port 5696 did not become ready within {timeout}s after restart"
        )

    # ------------------------------------------------------------------
    # KMIP client / cert / key (GUI flow via curl)
    # ------------------------------------------------------------------
    def configure_kmip_client(self):
        """Create Generic KMIP client, assign configs cert, create AES-256 key."""
        self._create_client_if_needed()
        self._assign_users()
        self._assign_certificate()
        alias = self._create_symmetric_key_and_get_alias()
        utils.exec_shell_cmd(
            f"bash -c \"echo -n '{alias}' > {GKLM_KEY_ALIAS_FILE} && "
            f'chmod 644 {GKLM_KEY_ALIAS_FILE}"'
        )
        log.info(f"GKLM KMIP key alias for SSE-KMS: {alias}")
        return alias

    def _load_or_ensure_kmip_setup(self):
        if os.path.exists(GKLM_KEY_ALIAS_FILE):
            with open(GKLM_KEY_ALIAS_FILE) as fh:
                raw = fh.read().strip()
            alias = self._normalize_key_alias(raw)
            if alias:
                log.info(f"Reusing existing GKLM key alias {alias}")
                # Ensure client cert is assigned (prior runs may have failed assign)
                self._assign_certificate()
                # Rewrite file if older runs stored bracketed alias
                if raw != alias:
                    utils.exec_shell_cmd(
                        f"bash -c \"echo -n '{alias}' > {GKLM_KEY_ALIAS_FILE}\""
                    )
                return alias
        return self.configure_kmip_client()

    def _create_client_if_needed(self):
        clients = self._curl_json("GET", "/clients", fail_ok=True) or {}
        names = set()
        if isinstance(clients, list):
            entries = clients
        elif isinstance(clients, dict):
            entries = []
            for key in ("client", "clients", "genericKmipClient"):
                val = clients.get(key)
                if isinstance(val, list):
                    entries = val
                    break
        else:
            entries = []
        for entry in entries:
            name = (
                entry.get("clientName") or entry.get("name") or entry.get("ClientName")
            )
            if name:
                names.add(str(name).upper())
        if self.client_name.upper() in names:
            log.info(f"GKLM client {self.client_name} already exists")
            return
        log.info(f"Creating GKLM Generic KMIP client {self.client_name}")
        resp = self._curl_json(
            "POST",
            "/clients",
            {"clientName": self.client_name, "applicationUsage": "Generic"},
        )
        log.info(resp)

    def _assign_users(self):
        resp = self._curl_json(
            "PUT",
            f"/clients/{self.client_name}/assignUsers",
            {"users": [self.admin_user]},
            fail_ok=True,
        )
        log.info(f"assignUsers: {resp}")

    def _assign_certificate(self):
        """
        Assign configs rgwselfsigned.cert via IMPORT_CERT.

        certText multipart via curl was rejected by GKLM 5.1 with
        CTGKM0542E / Incomplete data; IMPORT_CERT (podman cp + PUT) works.
        """
        # Skip if client already has this cert alias
        clients = self._curl_json("GET", "/clients", fail_ok=True) or {}
        entries = []
        if isinstance(clients, dict):
            for key in ("client", "clients"):
                val = clients.get(key)
                if isinstance(val, list):
                    entries = val
                    break
        for entry in entries:
            name = str(entry.get("clientName") or entry.get("name") or "").upper()
            cert = str(entry.get("clientCert") or "")
            if name == self.client_name.upper() and cert == self.cert_alias:
                log.info(
                    f"Client {self.client_name} already has cert {self.cert_alias}"
                )
                return

        log.info(
            f"Importing {CONFIG_CERT_PATH} into GKLM and assigning to "
            f"{self.client_name} as {self.cert_alias}"
        )
        utils.exec_shell_cmd(
            f"sudo podman exec {GKLM_CONTAINER_NAME} "
            f"mkdir -p /opt/ibm/wlp/products/sklm/data"
        )
        out = utils.exec_shell_cmd(
            f"sudo podman cp {CONFIG_CERT_PATH} "
            f"{GKLM_CONTAINER_NAME}:{CONTAINER_CERT_IMPORT_PATH}"
        )
        if out is False:
            raise Exception(f"Failed to copy {CONFIG_CERT_PATH} into GKLM container")
        resp = self._curl_json(
            "PUT",
            f"/clients/{self.client_name}/assignCertificate",
            {
                "certUseOption": "IMPORT_CERT",
                "certAlias": self.cert_alias,
                "importPath": CONTAINER_CERT_IMPORT_PATH,
            },
        )
        log.info(f"assignCertificate: {resp}")

    def _create_symmetric_key_and_get_alias(self):
        existing = self._list_client_objects()
        if existing:
            alias = self._extract_alias(existing[0])
            if alias:
                log.info(f"Reusing existing symmetric key alias {alias}")
                return alias
        log.info(
            f"Creating AES-256 symmetric key for client {self.client_name} "
            f"with prefix {self.key_prefix}"
        )
        resp = self._curl_json(
            "POST",
            "/objects/symmetrickey",
            {
                "clientName": self.client_name,
                "numberOfObjects": "1",
                "algorithm": "AES",
                "bitLength": "256",
                "prefixName": self.key_prefix,
                "cryptoUsageMask": "Encrypt_Decrypt",
            },
        )
        log.info(resp)
        # Prefer alias from list (S3 needs alias, not KEY- uuid)
        time.sleep(2)
        objects = self._list_client_objects()
        for obj in objects:
            alias = self._extract_alias(obj)
            if alias:
                return alias
        raise Exception(
            f"Symmetric key created but alias not found in object list: {objects}"
        )

    def _list_client_objects(self):
        data = self._curl_json(
            "GET", f"/objects?clientName={self.client_name}", fail_ok=True
        )
        if not data:
            return []
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict):
            for key in ("managedObject", "managedObjects", "object", "objects"):
                val = data.get(key)
                if isinstance(val, list):
                    return [x for x in val if isinstance(x, dict)]
        return []

    @staticmethod
    def _normalize_key_alias(alias):
        """
        GKLM 5.x often returns alias as '[rgw00...]' (literal brackets) or
        embeds it in Name as '[VALUE rgw00...]'. S3/KMIP needs the bare alias.
        """
        if alias is None:
            return None
        alias = str(alias).strip()
        if not alias or alias.startswith("KEY-"):
            return None
        # Strip wrapping brackets/quotes: [rgw00...] -> rgw00...
        if alias.startswith("[") and alias.endswith("]") and alias.count("[") == 1:
            alias = alias[1:-1].strip()
        alias = alias.strip("\"'")
        # Name field style: [[INDEX 0] [TYPE TEXT] [VALUE rgw00...]]
        m = re.search(r"\[VALUE\s+([^\]]+)\]", alias)
        if m:
            alias = m.group(1).strip()
        return alias or None

    @classmethod
    def _extract_alias(cls, obj):
        # Prefer structured Name VALUE when present
        for key in ("Name", "name"):
            normalized = cls._normalize_key_alias(obj.get(key))
            if normalized and not normalized.startswith("[["):
                return normalized
        for key in ("alias", "Alias", "keyAlias"):
            normalized = cls._normalize_key_alias(obj.get(key))
            if normalized:
                return normalized
            val = obj.get(key)
            if isinstance(val, list) and val:
                normalized = cls._normalize_key_alias(val[0])
                if normalized:
                    return normalized
        aliases = obj.get("aliases") or obj.get("Aliases")
        if isinstance(aliases, list) and aliases:
            first = aliases[0]
            if isinstance(first, dict):
                return cls._normalize_key_alias(first.get("alias") or first.get("name"))
            return cls._normalize_key_alias(first)
        return None

    # ------------------------------------------------------------------
    # RGW wiring — certs under /var/run/ceph/<fsid>/ (no remount needed)
    # ------------------------------------------------------------------
    def configure_rgw_for_kmip(self):
        """
        Place rgwselfsigned cert/key on every RGW host at
        /var/run/ceph/<fsid>/rgw_certificate.{crt,key}, set KMIP ceph config
        to the in-container paths /var/run/ceph/rgw_certificate.*, and restart
        RGW (no extra_container_args remount).
        """
        self._place_certs_on_rgw_hosts()
        kmip_addr = f"{self.ip_addr}:5696"
        log.info(
            f"Setting RGW KMIP config: addr={kmip_addr}, "
            f"cert={RGW_CONTAINER_CERT}, key={RGW_CONTAINER_KEY}"
        )
        for cmd in (
            "ceph config set client.rgw rgw_crypt_require_ssl false",
            "ceph config set client.rgw rgw_crypt_s3_kms_backend kmip",
            f"ceph config set client.rgw rgw_crypt_kmip_client_cert {RGW_CONTAINER_CERT}",
            f"ceph config set client.rgw rgw_crypt_kmip_client_key {RGW_CONTAINER_KEY}",
            f"ceph config set client.rgw rgw_crypt_kmip_addr {kmip_addr}",
        ):
            out = utils.exec_shell_cmd(cmd)
            if out is False:
                raise Exception(f"Failed: {cmd}")
        self._restart_rgw_services()
        log.info(f"RGW configured for GKLM KMIP; key alias={self.key_alias}")

    def _place_certs_on_rgw_hosts(self):
        """
        On each RGW node, copy certs already present via git_clone_configs_repo:

          /home/cephuser/configs/rgw/gklm/rgwselfsigned.cert
          /home/cephuser/configs/rgw/gklm/rgwselfsigned.key
            → /var/run/ceph/<fsid>/rgw_certificate.crt|key

        /var/run/ceph/<fsid>/ already exists (cephadm); no mkdir/scp needed.
        Commands run as root via connect_remote + remote_exec_shell_cmd.
        """
        hosts = self._get_rgw_host_addrs()
        log.info(
            f"Copying KMIP certs on RGW hosts {hosts} → "
            f"{self.host_cert_dir}/{{{RGW_CERT_BASENAME},{RGW_KEY_BASENAME}}}"
        )
        # Source paths exist on every RGW node after git_clone_configs_repo
        copy_cmd = (
            f"cp {CONFIG_CERT_PATH} {self.host_cert_path} && "
            f"cp {CONFIG_KEY_PATH} {self.host_key_path} && "
            f"chown 167:167 {self.host_cert_path} {self.host_key_path} && "
            f"chmod 640 {self.host_cert_path} {self.host_key_path} && "
            f"ls -la {self.host_cert_path} {self.host_key_path}"
        )
        for host in hosts:
            log.info(f"Copying KMIP certs on {host}")
            ssh = utils.connect_remote(host, user_nm="root", passw="passwd")
            ok = utils.remote_exec_shell_cmd(ssh, copy_cmd)
            try:
                ssh.close()
            except Exception:
                pass
            if not ok:
                raise Exception(f"Failed to copy KMIP certs on RGW host {host}")
            log.info(f"Placed {self.host_cert_path} and {self.host_key_path} on {host}")

    def _get_rgw_host_addrs(self):
        out_ps = utils.exec_shell_cmd("ceph orch ps --daemon_type rgw -f json")
        if not out_ps:
            return {self.ip_addr}
        daemons = json.loads(out_ps)
        hostnames = {d.get("hostname") for d in daemons if d.get("hostname")}
        out_hosts = utils.exec_shell_cmd("ceph orch host ls -f json")
        addrs = set()
        if out_hosts:
            for entry in json.loads(out_hosts):
                if entry.get("hostname") in hostnames:
                    addrs.add(entry.get("addr") or entry.get("hostname"))
        if not addrs:
            addrs = hostnames
        return addrs or {self.ip_addr}

    def _restart_rgw_services(self):
        """Restart RGW so it reloads KMIP cert paths (no orch remount)."""
        services = json.loads(
            utils.exec_shell_cmd("ceph orch ls --service-type rgw --format json")
            or "[]"
        )
        for svc in services:
            name = svc.get("service_name")
            if name:
                log.info(f"Restarting {name}")
                utils.exec_shell_cmd(f"ceph orch restart {name}")
        log.info("Sleeping 30s after RGW restart")
        time.sleep(30)
