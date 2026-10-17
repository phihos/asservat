"""Owned authenticated TLS registry fixture; never imported by product code.

Only the current test image is uploaded. No host Docker credential/trust changes,
external publication, node auth file, or credential-bearing diagnostic output.
"""
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import ssl
import shutil
import subprocess
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

# Official docker-library/repo-info registry:3 / Distribution 3.1.2, 2026-10-12.
# Published provenance is distinct from qualification of this fixture.
REGISTRY = "registry@sha256:ddf754342cfc8acc51a56d5d0ab6af06826461864460636d8bd5c546dab2a7b8"


def exported_image_identity(content, expected_image, config):
    """Bind exported configuration to the exact Docker image, on both stores.

    The classic store reports a config digest as Id. The containerd store may
    report an index/manifest digest instead. Follow its hash-verified descriptor
    chain to the one matching platform; never accept a different archive entry.
    """
    config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
    configuration = json.loads(config)
    if expected_image == config_digest:
        return {"dockerImageID": expected_image, "configDigest": config_digest,
                "identityKind": "config"}
    platform = {key: configuration.get(key) for key in ("os", "architecture")}
    if not all(isinstance(value, str) and value for value in platform.values()):
        raise RuntimeError("exported image platform unavailable")
    variant = configuration.get("variant")
    if variant:
        platform["variant"] = variant
    current, seen = expected_image, set()
    for _ in range(3):
        if not isinstance(current, str) or not current.startswith("sha256:") or len(current) != 71 or any(c not in "0123456789abcdef" for c in current[7:]) or current in seen:
            raise RuntimeError("invalid or recursive exported image identity")
        seen.add(current)
        raw = content("blobs/sha256/" + current[7:], 64 << 10)
        if "sha256:" + hashlib.sha256(raw).hexdigest() != current:
            raise RuntimeError("exported image descriptor digest differs")
        value = json.loads(raw)
        if value.get("schemaVersion") != 2:
            raise RuntimeError("unsupported exported image schema")
        media = value.get("mediaType")
        if media in ("application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"):
            descriptor = value.get("config", {})
            if descriptor.get("digest") != config_digest or descriptor.get("size") != len(config):
                raise RuntimeError("exported image differs from compiled configuration")
            return {"dockerImageID": expected_image, "configDigest": config_digest,
                    "selectedManifestDigest": current, "identityKind": "descriptor-chain"}
        if media not in ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"):
            raise RuntimeError("unsupported exported image descriptor")
        manifests = value.get("manifests")
        if not isinstance(manifests, list) or not 1 <= len(manifests) <= 8:
            raise RuntimeError("unbounded exported image index")
        selected = [item for item in manifests if isinstance(item, dict) and item.get("platform") == platform]
        if len(selected) != 1:
            raise RuntimeError("exported image platform is missing or ambiguous")
        descriptor = selected[0]
        current = descriptor.get("digest")
        if not isinstance(current, str) or not current.startswith("sha256:") or len(current) != 71 or any(c not in "0123456789abcdef" for c in current[7:]):
            raise RuntimeError("invalid exported image child identity")
        child = content("blobs/sha256/" + current[7:], 64 << 10)
        if descriptor.get("size") != len(child) or json.loads(child).get("mediaType") != descriptor.get("mediaType"):
            raise RuntimeError("exported image descriptor metadata differs")
    raise RuntimeError("exported image identity exceeds descriptor depth")


def exported_layer_media(data, original, maximum=256 << 20):
    """Verify rootfs diffID while preserving the export's exact layer bytes."""
    compressed = data.startswith(b"\x1f\x8b")
    if compressed:
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                plain = stream.read(maximum+1)
        except (OSError, EOFError):
            raise RuntimeError("invalid exported gzip layer") from None
    else:
        plain = data
    if len(plain) > maximum:
        raise RuntimeError("exported layer exceeds original uncompressed bound")
    if "sha256:"+hashlib.sha256(plain).hexdigest() != original:
        raise RuntimeError("exported layer differs from original rootfs identity")
    return "application/vnd.oci.image.layer.v1.tar" + ("+gzip" if compressed else "")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("owned registry unexpectedly redirected")


class HelmRegistry:
    def __init__(self, work, network, run_id, containers, run):
        self.run, self.name = run, network + "-registry"
        self.work = Path(work) / "registry"
        self.work.mkdir(mode=0o700)
        self.auth = base64.b64encode(b"synthetic-pull:allmine").decode()
        # Fixed synthetic bcrypt test vector; never a product credential.
        (self.work / "htpasswd").write_text("synthetic-pull:$2a$10$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga\n")
        (self.work / "htpasswd").chmod(0o600)
        uid, gid = os.getuid(), os.getgid()
        run(["docker", "create", "--name", self.name, "--network", network,
             "--label", "asservat.test=" + run_id, "--memory", "384m", "--cpus", "1",
             "--pids-limit", "128", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
             "--user", str(uid)+":"+str(gid), "--read-only",
             "--tmpfs", "/var/lib/registry:rw,nosuid,nodev,size=512m,mode=0700,uid="+str(uid)+",gid="+str(gid),
             "-v", str(self.work)+":/fixture:ro", "--entrypoint", "/bin/sh", REGISTRY,
             "-c", "i=0; while [ ! -f /fixture/ready ]; do i=$((i+1)); [ \"$i\" -le 150 ] || exit 1; sleep 0.1; done; exec /bin/registry serve /fixture/config.json"])
        containers.append(self.name)
        run(["docker", "start", self.name])
        info = json.loads(run(["docker", "inspect", self.name]))[0]
        self.ip = info["NetworkSettings"]["Networks"][network]["IPAddress"]
        self.authority = self.ip + ":5000"
        self.endpoint = "https://" + self.authority
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=owned-helm-registry", "-addext", "subjectAltName=IP:"+self.ip,
                        "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", str(self.work/"key.pem"),
                        "-out", str(self.work/"ca.pem")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        (self.work/"key.pem").chmod(0o600)
        config = {"version": 0.1, "log": {"level": "info", "formatter": "json"},
                  "storage": {"filesystem": {"rootdirectory": "/var/lib/registry"}},
                  "auth": {"htpasswd": {"realm": "owned-fixture", "path": "/fixture/htpasswd"}},
                  "http": {"addr": ":5000", "tls": {"certificate": "/fixture/ca.pem", "key": "/fixture/key.pem", "minimumtls": "tls1.3"}},
                  "health": {"storagedriver": {"enabled": False}}}
        (self.work/"config.json").write_text(json.dumps(config))
        (self.work/"ready").touch(mode=0o600)
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(self.work/"ca.pem"))))
        for _ in range(60):
            try:
                self.request("GET", "/v2/", authenticated=False)
                raise RuntimeError("registry allowed anonymous access")
            except urllib.error.HTTPError as exc:
                if exc.code == 401:
                    exc.close()
                    break
                raise RuntimeError("unexpected registry readiness status") from None
            except (OSError, urllib.error.URLError):
                time.sleep(.1)
        else:
            raise RuntimeError("owned TLS registry unavailable")
        with self.request("GET", "/v2/"):
            pass

    def request(self, method, path, data=None, content_type=None, authenticated=True):
        if not path.startswith("/") or path.startswith("//"):
            raise RuntimeError("registry path escaped owned origin")
        headers = {"Authorization": "Basic " + self.auth} if authenticated else {}
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(self.endpoint+path, data=data, headers=headers, method=method)
        return self.client.open(request, timeout=60)

    def upload(self, worker_tag, expected_image):
        archive = self.work/"image.tar"
        self.run(["docker", "image", "save", "-o", str(archive), worker_tag])
        archive.chmod(0o600)
        if archive.stat().st_size > 512 << 20:
            raise RuntimeError("fixture image archive exceeds fixed bound")
        with tarfile.open(archive) as bundle:
            def content(name, maximum):
                member = bundle.getmember(name)
                if not member.isfile() or member.size > maximum:
                    raise RuntimeError("unsupported fixture archive entry")
                return bundle.extractfile(member).read(maximum+1)
            entries = json.loads(content("manifest.json", 64 << 10))
            if len(entries) != 1 or not 1 <= len(entries[0]["Layers"]) <= 8:
                raise RuntimeError("fixture image archive must contain one bounded image")
            entry = entries[0]
            config = content(entry["Config"], 64 << 10)
            self.export_identity = exported_image_identity(content, expected_image, config)
            configuration = json.loads(config)
            diff_ids = configuration["rootfs"]["diff_ids"]
            if len(diff_ids) != len(entry["Layers"]):
                raise RuntimeError("fixture layer identity mismatch")
            def blob(data, media):
                digest = "sha256:" + hashlib.sha256(data).hexdigest()
                with self.request("POST", "/v2/asservat/blobs/uploads/", b"") as started:
                    location = urllib.parse.urlsplit(started.headers["Location"])
                if location.scheme and (location.scheme != "https" or location.netloc != self.authority):
                    raise RuntimeError("registry upload escaped exact origin")
                query = urllib.parse.parse_qsl(location.query, keep_blank_values=True)
                query.append(("digest", digest))
                target = location.path + "?" + urllib.parse.urlencode(query)
                with self.request("PUT", target, data, "application/octet-stream") as done:
                    if done.status != 201 or done.headers.get("Docker-Content-Digest") != digest:
                        raise RuntimeError("registry blob acknowledgement differs")
                return {"mediaType": media, "size": len(data), "digest": digest}
            config_descriptor = blob(config, "application/vnd.oci.image.config.v1+json")
            layers = []
            for path, original in zip(entry["Layers"], diff_ids):
                data = content(path, 256 << 20)
                layers.append(blob(data, exported_layer_media(data, original)))
            manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": config_descriptor, "layers": layers}, separators=(",", ":")).encode()
            self.digest = "sha256:"+hashlib.sha256(manifest).hexdigest()
            with self.request("PUT", "/v2/asservat/manifests/"+self.digest, manifest, "application/vnd.oci.image.manifest.v1+json") as done:
                if done.status != 201 or done.headers.get("Docker-Content-Digest") != self.digest:
                    raise RuntimeError("registry manifest acknowledgement differs")
        archive.unlink()
        self.image = self.authority+"/asservat@"+self.digest
        try:
            self.request("GET", "/v2/asservat/manifests/"+self.digest, authenticated=False)
        except urllib.error.HTTPError as exc:
            if exc.code != 401:
                raise RuntimeError("anonymous exact-image denial missing") from None
            exc.close()
        else:
            raise RuntimeError("anonymous exact-image pull allowed")
        return self.image

    def configure_owned_node(self, name):
        directory = "/etc/containerd/certs.d/"+self.authority
        self.run(["docker", "exec", name, "mkdir", "-p", directory])
        self.run(["docker", "cp", str(self.work/"ca.pem"), name+":"+directory+"/ca.crt"])
        hosts = self.work/"hosts.toml"
        hosts.write_text('server = "'+self.endpoint+'"\n[host."'+self.endpoint+'"]\n  capabilities = ["pull", "resolve"]\n  ca = "'+directory+'/ca.crt"\n')
        self.run(["docker", "cp", str(hosts), name+":"+directory+"/hosts.toml"])
        # No auth is installed into containerd/node state; only the public CA.
        self.assert_absent(name)

    def assert_absent(self, name):
        images = self.run(["docker", "exec", name, "ctr", "-n", "k8s.io", "images", "ls"])
        content = self.run(["docker", "exec", name, "ctr", "-n", "k8s.io", "content", "ls", "-q"])
        if self.image in images or self.digest in images or self.digest in content.splitlines():
            raise RuntimeError("exact product image was already available before authenticated pull")

    def material(self):
        return {"auths": {self.authority: {"auth": self.auth}}}

    def report(self, expected_nodes):
        # Never archive raw HTTP logs. Select fixed success counts by exact owned
        # remote IP and manifest digest; headers and credentials are discarded.
        result = subprocess.run(["docker", "logs", "--tail", "4000", self.name], capture_output=True, text=True, timeout=10, check=True)
        raw = result.stdout + result.stderr
        if len(raw) > 4 << 20:
            raise RuntimeError("fixture registry diagnostics exceed fixed bound")
        if self.auth in raw or "Authorization" in raw or "allmine" in raw:
            raise RuntimeError("fixture registry diagnostics contain credential material")
        counts = {address: 0 for address in expected_nodes}
        for line in raw.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            remote = item.get("http.request.remoteaddr", "").rsplit(":", 1)[0]
            if remote in counts and item.get("http.request.method") == "GET" and item.get("http.request.uri", "").split("?", 1)[0] == "/v2/asservat/manifests/"+self.digest and item.get("http.response.status") == 200:
                counts[remote] += 1
        if not all(counts.values()):
            raise RuntimeError("authenticated exact-image GET evidence missing for an owned node")
        return {"image": REGISTRY, "productImage": self.image, "anonymousExactImageDenied": True, "authenticatedManifestGetsByOwnedNode": counts, "nodeCredentialsInstalled": False}


def verify_registry_cleanup(run, work, network):
    """Positive exact absence after owned removal; no forensic erasure claim."""
    name = network + "-registry"
    if name in run(["docker", "container", "ls", "--all", "--format", "{{.Names}}"] ).splitlines():
        raise RuntimeError("owned registry container remains")
    if network in run(["docker", "network", "ls", "--format", "{{.Name}}"] ).splitlines():
        raise RuntimeError("owned registry network remains")
    private = Path(work) / "registry"
    if private.is_symlink():
        raise RuntimeError("owned registry private directory changed")
    if private.exists():
        if not private.is_dir():
            raise RuntimeError("owned registry private directory invalid")
        shutil.rmtree(private)
    if private.exists():
        raise RuntimeError("owned registry private files remain")
    return {"containerAbsent": True, "privateNetworkAbsent": True,
            "fixtureTLSAndAuthFilesAbsent": True, "upstreamImageCacheRemoved": False}
