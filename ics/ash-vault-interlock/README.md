# Ash-Vault Interlock Writeup

## The short version

This challenge is a small simulated industrial plant. A broken level sensor makes
the PLC believe the brine tank is nearly empty, so automatic mode keeps filling
an already-full tank. We have to:

1. Put the PLC in manual mode.
2. Drain the tank and vent its pressure.
3. Clear the safety latches.
4. Hold the tank inside the seal-ready operating window.
5. Command the seal for ten PLC scans.
6. Acknowledge the resulting alarm.

The flag was:

```text
HTB{4sh_v4ult_1nt3rl0ck_s3aled_cef4c0c1fc45fb974a9ce41bfb885c73}
```

---

## What are an HMI and a PLC?

The **PLC** is the small industrial computer controlling the valves and pump.
The **HMI** is the dashboard showing the operator what the PLC is doing.

The challenge exposed two TCP ports:

- One port served the HMI over HTTP.
- The other spoke Modbus/TCP to the PLC.

The ports were temporary and changed whenever the challenge instance restarted.
The HTTP port could be identified with `curl`; sending HTTP to the Modbus port
returned an empty response.

```bash
curl http://HOST:PORT/
```

The correct HTTP port returned a page titled:

```text
Asterion Controls AVX-470 Interlock PLC
```

---

## Looking at the live process

The HMI fetched its compact status data from:

```bash
curl http://HOST:HTTP_PORT/status.json
```

An early response looked similar to this:

```json
{
  "m": "AUTO",
  "p": [100.0, 76.6, 12.0, 6.4, 0.0, 0.0, 9.0],
  "o": [true, false, false, true, false],
  "s": [false, true, false, false, true, false, false],
  "t": [0, 201, 42],
  "a": [
    "PT301 pressure-high latch active",
    "LT204 vessel level high"
  ]
}
```

The useful fields were:

| Field | Meaning |
|---|---|
| `m` | PLC mode |
| `p[0]` | Actual tank level percentage |
| `p[1]` | Tank pressure in kPa |
| `p[2]` | Raw level reading used by automatic mode |
| `o` | Inlet, drain, vent, pump, and seal outputs |
| `s[1]` | Pressure-high latch |
| `s[2]` | Reset permissive |
| `s[3]` | Seal window active |
| `s[5]` | Final seal alarm active |
| `s[6]` | Bad-sequence latch |
| `t[0]` | Number of stable seal scans |
| `t[1]` | Last trip code |
| `t[2]` | PLC scan counter |
| `a` | Alarm messages |

The interesting contradiction was immediately visible:

- The real level was **100%**.
- Automatic mode's raw level input was stuck at **12%**.
- The inlet valve was still open.
- Pressure was already above the high-pressure trip point.

In plain English, the controller thought the full tank was empty and continued
filling it.

---

## Recovering the ladder logic

The JavaScript used by the HMI contained two useful header values:

```javascript
X-Requested-With: AVX-HMI
X-Engineering-Station: AVX-EWS-01
```

Supplying both headers allowed access to the engineering ladder export:

```bash
curl \
  -H 'X-Requested-With: AVX-HMI' \
  -H 'X-Engineering-Station: AVX-EWS-01' \
  http://HOST:HTTP_PORT/ladder.txt
```

The ladder listed these command coils:

| Coil | Purpose |
|---:|---|
| `C00000` | Enable automatic mode |
| `C00001` | Arm manual mode |
| `C00002` | Open the inlet valve |
| `C00003` | Open the drain valve |
| `C00004` | Open the pressure vent |
| `C00005` | Run the recirculation pump |
| `C00006` | Pulse the pressure-latch reset |
| `C00007` | Command the Ash-Vault seal |

Modbus coils are individual on/off bits. When coils 0 through 7 are written as
one packed byte, the useful values are:

| Value | Enabled coils | Use |
|---:|---|---|
| `0x22` | Manual + pump | Safe steady state |
| `0x2a` | Manual + drain + pump | Lower the level |
| `0x32` | Manual + vent + pump | Lower pressure |
| `0x3a` | Manual + drain + vent + pump | Initial recovery |
| `0x62` | Manual + pump + reset | Reset pulse |
| `0xa2` | Manual + pump + seal | Final sealing state |

---

## Understanding the safety conditions

The ladder was important because blindly pressing controls could set the
`BAD_SEQUENCE_LATCH`.

### Reset permissive

The pressure and bad-sequence latches could only be cleared when all of these
were true:

- Manual mode was active.
- Inlet was closed.
- Drain was closed.
- Vent was closed.
- Recirculation pump was running.
- Pressure was between **22 and 45 kPa**.
- Level was between **35% and 65%**.

Only then was it safe to pulse reset coil 6.

### Final seal window

The final seal required tighter conditions:

- Manual mode was active.
- Pressure-high latch was clear.
- Bad-sequence latch was clear.
- Seal command was on.
- Inlet, drain, and vent were closed.
- Recirculation pump was running.
- Pressure was between **28 and 36 kPa**.
- Level was between **38% and 54%**.

Those conditions had to remain true for **ten consecutive PLC scans**.

---

## Operating the plant

I first wrote `0x3a` to coils 0 through 7. This selected manual mode, closed the
inlet, opened the drain and vent, and kept the pump running.

The vent dropped pressure quickly. Once pressure was no longer high, I closed
the vent but kept draining with `0x2a`. The open drain held pressure at roughly
19 kPa, which was temporarily below the reset window, but that was fine while
the level was still being corrected.

At approximately 49% level, I closed the drain by writing the safe value
`0x22`. With all valves closed and the pump running, pressure naturally
recovered toward 32 kPa.

Once the HMI showed `RESET_PERMISSIVE`, I pulsed reset:

1. Write `0x62`.
2. Keep it asserted for slightly longer than one PLC scan.
3. Return to `0x22`.

The last-trip code became zero, and both safety latches cleared.

The tank was then around 49% and 31 kPa, already inside the final window. I
wrote `0xa2` and held it there. The stable counter climbed from 1 to 10, after
which the HMI displayed:

```text
AVX900 ASH-VAULT SEAL MADE - ENGINEERING ACK REQUIRED
```

That was not quite the flag. The final trick was hidden in the wording.

---

## The hidden acknowledgement coil

The exported main ladder only mentioned coils 0 through 7, but the PLC exposed
more coils. Because the alarm explicitly requested an engineering
acknowledgement, I tested the next coil.

Pulsing coil address **8** acknowledged AVX900:

```python
write_single_coil(8, True)
time.sleep(1.1)
write_single_coil(8, False)
```

The alarm table then changed to:

```text
AVX900 ASH-VAULT SEAL MADE - TOKEN HTB{4sh_v4ult_1nt3rl0ck_s3aled_cef4c0c1fc45fb974a9ce41bfb885c73}
```

---

## Minimal raw Modbus helper

This helper uses only Python's standard library. Function code 15 writes the
first eight coils as one byte, while function code 5 writes the hidden
acknowledgement coil.

```python
import socket
import struct
import time

HOST = "TARGET_IP"
MODBUS_PORT = 12345
transaction_id = 0


def modbus_request(pdu, unit_id=1):
    global transaction_id
    transaction_id = (transaction_id + 1) & 0xffff

    frame = struct.pack(
        ">HHHB",
        transaction_id,  # Transaction ID
        0,               # Modbus protocol ID
        len(pdu) + 1,    # Unit ID plus PDU length
        unit_id,
    ) + pdu

    with socket.create_connection((HOST, MODBUS_PORT), timeout=3) as sock:
        sock.sendall(frame)
        header = sock.recv(7)
        response_length = struct.unpack(">HHHB", header)[2] - 1
        return sock.recv(response_length)


def write_first_eight_coils(mask):
    # FC15, start address 0, quantity 8, byte count 1
    pdu = struct.pack(">BHHB", 15, 0, 8, 1) + bytes([mask])
    return modbus_request(pdu)


def write_single_coil(address, enabled):
    # Modbus represents ON as 0xff00 and OFF as 0x0000.
    value = 0xff00 if enabled else 0x0000
    return modbus_request(struct.pack(">BHH", 5, address, value))


# Example final steps, after the process is in the correct ranges:
write_first_eight_coils(0x62)  # Pulse reset
time.sleep(1.2)
write_first_eight_coils(0x22)  # Safe state

write_first_eight_coils(0xa2)  # Seal command
time.sleep(11)

write_single_coil(8, True)     # Engineering alarm acknowledgement
time.sleep(1.1)
write_single_coil(8, False)
```

In a real solver, the sleeps should be replaced with polling
`/status.json`. The script should only reset or seal after verifying the exact
level, pressure, valve, pump, and latch conditions.

---

## Takeaways

- The HMI was useful for understanding the physical process, not just for
  decoration.
- The stuck 12% automatic sensor reading explained the runaway cycle.
- Reading the ladder before issuing commands prevented unsafe sequences.
- The reset window and seal window were different.
- The final `ENGINEERING ACK REQUIRED` message was a hint that one more coil
  existed beyond those shown in the main ladder export.

