# Option B — Raw Kerberos S4U2Self (+U2U) in C#

> Status: **PLANNED / deferred**. Option A (`LsaLogonUser` + `KERB_S4U_LOGON`, see `FindGT/S4U.cs`)
> is implemented and verified. This document is the detailed implementation plan for the fully
> self-contained raw-Kerberos variant, to be implemented later.

## 1. Goal & rationale

Obtain an arbitrary domain user's **authoritative group membership** (the PAC the KDC builds from
current AD state) using **only the extracted machine-account secret**, performing every Kerberos
exchange ourselves — **without going through the local LSASS** at all.

Why bother, when Option A already works?

- **Full independence from a potentially-tampered local LSASS** on a compromised host. Option A asks
  LSASS to do S4U2Self; if LSASS itself is hooked/patched by an attacker with SYSTEM, results could be
  faked. Option B talks to the KDC directly with our own socket and crypto, trusting nothing local
  except the machine secret we already verified against the DC (Phase 2 secure channel).
- Reuses the machine secret we already extract and store (`secrets/machine.nthash`, and optionally the
  cleartext password for AES keys).

Threat-model note: S4U2Self is authoritative regardless of the impersonated user's (possibly forged)
TGT — the KDC builds a fresh PAC and the user's TGT is never part of the exchange. Option B simply
removes the local LSASS from the trust path.

## 2. Prerequisites / inputs

| Input                                         | Source                                                   |
| --------------------------------------------- | -------------------------------------------------------- |
| Machine sAMAccountName (`HOST01$`)            | `Environment.MachineName + "$"`                          |
| Domain DNS + realm (`CONTOSO.COM`)            | `USERDNSDOMAIN` / `Domain.GetComputerDomain()`           |
| KDC host/IP (`DC02.contoso.com` / `192.168.1.100`) | `DsGetDcName` (already used in `Nrpc.cs`)           |
| Machine **NT hash** (RC4 key)                 | `LsaSecretExtractor --nthash` → `secrets/machine.nthash` |
| Machine **cleartext password** (for AES keys) | `LsaSecretExtractor` raw output (UTF-16LE)               |
| Target user UPN / sAMAccountName              | per session (SID → name)                                 |

For AES enctypes the long-term key is `PBKDF2-HMAC-SHA1(password, salt)`; salt for a computer account
is typically `<REALM>host<lowercase-fqdn-without-$>` (MS-style machine salt). Because we use **U2U**
to decrypt the result, we mainly need the keys for the **AS-REQ pre-auth**, not for ticket decryption.

## 3. High-level flow

```
machine NThash/AES key
        │  AS-REQ (PA-ENC-TIMESTAMP)
        ▼
   AS-REP  ──►  machine TGT + TGT session key
        │
        │  TGS-REQ:  PA-TGS-REQ(AP-REQ from TGT)
        │           + PA-FOR-USER(target user, cksum w/ TGT session key)
        │           + kdc-options: forwardable,renewable,canonicalize,ENC-TKT-IN-SKEY
        │           + additional-tickets = [machine TGT]      (U2U)
        │           + sname = machine account (self)
        ▼
   TGS-REP  ──►  service ticket (ST) to self, for target user
        │
        │  ST.enc-part encrypted with TGT **session key** (because of U2U)
        ▼
  decrypt ST (usage KRB5_KU_TICKET=2) ──► EncTicketPart
        │
        ▼
  authorization-data → AD-IF-RELEVANT → AD-WIN2K-PAC (type 128)
        │
        ▼
  PACTYPE → PAC_INFO_BUFFER[] → LOGON_INFO(type 1) → KERB_VALIDATION_INFO (NDR)
        │
        ▼
  LogonDomainId + GroupIds[].RelativeId + ExtraSids[]  →  authoritative SIDs
```

## 4. Detailed steps

### 4.1 Key derivation

- **RC4-HMAC (etype 23)**: key = machine NT hash (16 bytes) — we already have it.
- **AES128 (17) / AES256 (18)**: `key = PBKDF2-HMAC-SHA1(UTF-16LE? NO — UTF-8 of password, salt, 4096, keylen)`
  then `DK = AES-CTS` derivation constant. Use the cleartext machine password + computer-account salt.
  (Only needed if we choose AES for AS-REQ pre-auth; RC4 is simplest if the domain still allows it.)

### 4.2 AS-REQ / AS-REP (machine TGT)

- Build `AS-REQ` for client `HOST01$`, sname `krbtgt/CONTOSO.COM`.
- Include `PA-ENC-TIMESTAMP` pre-auth encrypted with the machine key (etype RC4 or AES).
- kdc-options: forwardable, renewable, canonicalize, **proxiable** (helps S4U).
- Send to KDC (TCP 88), parse `AS-REP`.
- Decrypt `AS-REP.enc-part` (usage `KRB5_KU_AS_REP_ENCPART=3`) with the machine key →
  `EncASRepPart` → **TGT session key** + flags + times. Keep the raw `Ticket` (the TGT).

### 4.3 PA-FOR-USER checksum (the crux)

`PA-FOR-USER` (padata type **129**) contains:

- `userName` = target user `PrincipalName` (NT_PRINCIPAL/NT_ENTERPRISE).
- `userRealm`.
- `cksum` = keyed checksum over `S4UByteArray` using the **TGT session key**,
  key-usage `KERB_NON_KERB_CKSUM_SALT = 17`, checksum type **`KERB_CHECKSUM_HMAC_MD5` (-138)**
  (this specific cksum type is mandatory for PA-FOR-USER regardless of session-key enctype).
- `auth-package` = `"Kerberos"`.

`S4UByteArray` = `LE32(nameType) || userName || userRealm || "Kerberos"` (concatenated bytes),
matching MS-SFU 2.2.1 and impacket's construction.

### 4.4 S4U2Self + U2U TGS-REQ

- `req-body.kdc-options`: forwardable, renewable, canonicalize, **enc-tkt-in-skey** (U2U).
- `req-body.sname` = our **own** machine account (S4U2Self = ticket to self). For U2U the sname is the
  TGT client (the machine account), not a host SPN.
- `req-body.additional-tickets` = `[ machine TGT ]` (this is what makes it U2U → ST encrypted with the
  TGT session key).
- `padata[0]` = `PA-TGS-REQ` = an `AP-REQ` built from the TGT (authenticator encrypted with TGT
  session key, usage `KRB5_KU_TGS_REQ_AUTH=7`; authenticator cksum over req-body usage 6).
- `padata[1]` = `PA-FOR-USER` (from 4.3).
- (optional) `padata[2]` = `PA-PAC-OPTIONS` for resource SID compression control.
- Send, parse `TGS-REP`.

### 4.5 Decrypt the service ticket via U2U

- `TGS-REP.enc-part` (the KDC's reply wrapper) decrypts with the **TGT session key**
  (usage `KRB5_KU_TGS_REP_ENCPART_SESSKEY=8` for U2U) → `EncTGSRepPart` (ST session key etc.).
- The **ST ticket** (`TGS-REP.ticket.enc-part`) is encrypted, because of `ENC-TKT-IN-SKEY`, with the
  **TGT session key** too → decrypt with usage `KRB5_KU_TICKET=2` → `EncTicketPart`.
  (This is the U2U trick that avoids needing the service's AES long-term key.)

### 4.6 Extract & parse the PAC

- `EncTicketPart.authorization-data` → element type `AD-IF-RELEVANT (1)` → inner `AD-WIN2K-PAC (128)`
  → raw PAC bytes.
- Parse `PACTYPE`: `cBuffers`, then `PAC_INFO_BUFFER[]` (ulType, cbBufferSize, Offset).
- Find `ulType == 1` (`LOGON_INFO`) → blob is **NDR-marshalled** `KERB_VALIDATION_INFO`.
- NDR-decode `KERB_VALIDATION_INFO` → `LogonDomainId` (domain SID), `GroupCount`/`GroupIds[]`
  (each `GROUP_MEMBERSHIP{RelativeId,Attributes}`), `SidCount`/`ExtraSids[]`
  (`KERB_SID_AND_ATTRIBUTES{Sid,Attributes}`).
- Build full SID list: `LogonDomainId + "-" + RelativeId` for each group, plus each `ExtraSids.Sid`.
- (Optional) verify `PAC_SERVER_CHECKSUM`/`PAC_PRIVSVR_CHECKSUM` — not required for membership read.

## 5. Building blocks / libraries

| Concern                              | Approach                                                                                                                                    |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| ASN.1 DER (KRB messages)             | `System.Formats.Asn1` (already referenced via `System.Formats.Asn1.9.0.0`) or BouncyCastle. Prefer `System.Formats.Asn1` to avoid new deps. |
| Kerberos crypto RC4-HMAC             | `HMACMD5` + `RC4` (custom) — straightforward.                                                                                               |
| Kerberos crypto AES-CTS-HMAC-SHA1-96 | implement AES-CTS + PBKDF2 + DK; or vendor a small file.                                                                                    |
| HMAC-MD5 checksum (PA-FOR-USER)      | `HMACMD5` with key-usage salt 17.                                                                                                           |
| NDR decode of KERB_VALIDATION_INFO   | hand-rolled little-endian NDR reader (model after `NetlogonValidationSamInfo.cs`).                                                          |
| Sockets                              | `TcpClient` to KDC:88, 4-byte length prefix framing.                                                                                        |

A pragmatic option: vendor a vetted managed Kerberos library (e.g. **Kerberos.NET**) for the AS/TGS
ASN.1 + crypto, and only hand-roll the PA-FOR-USER + U2U bits it may not expose. Decide before coding.

## 6. Proposed file layout (FindGT)

- `Kerberos/KrbAsn1.cs` — DER encode/decode of AS-REQ/REP, TGS-REQ/REP, Ticket, authenticator, padata.
- `Kerberos/KrbCrypto.cs` — RC4-HMAC + AES-CTS-HMAC-SHA1, key derivation, checksums, key usages.
- `Kerberos/KrbClient.cs` — socket I/O, AS exchange, S4U2Self+U2U TGS exchange.
- `Kerberos/Pac.cs` — PAC + KERB_VALIDATION_INFO NDR parsing (reuse `NetlogonValidationSamInfo` model).
- `Kerberos/S4URaw.cs` — orchestration: `GetDomainGroupSids(upn, realm)` mirroring `S4U.cs`'s surface.

Keep the **same public surface** as `S4U.cs` so the membership provider can switch A↔B trivially.

## 7. Risks / unknowns

- **AES-only domains**: if AS-REQ pre-auth must be AES (RC4 disabled), AES-CTS + correct machine salt
  are required and salt format must be exact (computer-account salt quirk). Verify with a test AS-REQ.
- **PA-FOR-USER cksum type**: must be HMAC-MD5 (-138) even on AES channels; getting this wrong → KDC
  `KDC_ERR_S_PRINCIPAL_UNKNOWN`/`KRB_AP_ERR_MODIFIED`.
- **U2U key usages**: TGS-REP/ticket decryption usages differ for U2U vs normal — easy to get wrong.
- **NDR alignment**: KERB_VALIDATION_INFO has pointer/conformant-array quirks; align carefully.
- **Clock skew**: AS/TGS timestamps must be within skew (±5 min); machine is domain-synced.
- **Access to TokenGroupsGlobalAndUniversal**: same AD-permission requirement as Option A
  (machine = authenticated user; confirmed OK on the stand for Option A).

## 8. Testing strategy

1. Unit: encode→decode round-trip of each ASN.1 message; RC4/AES test vectors; HMAC-MD5 cksum vector.
2. AS exchange in isolation → assert we get a TGT (compare against `klist`/impacket).
3. Full S4U2Self+U2U for `testuser@contoso.com`; **diff the resulting SID set against Option A's output**
   (`S4U.cs`, 596 groups) — they must match. This is the acceptance test.
4. Resilience: wrong target, RC4-disabled, clock skew, DC down.

## 9. Reference impacket sequence (oracle for parity)

`getKerberosTGT(Principal(MACHINE$,NT_PRINCIPAL), domain, '', lmhash, nthash, kdcHost)` →
build S4U2Self+U2U TGS-REQ (PA-FOR-USER cksum on TGT session key, `additional-tickets=[TGT]`,
`enc-tkt-in-skey`) → `sendReceive` → decrypt ticket with session key (usage 2) →
`PACTYPE`/`KERB_VALIDATION_INFO`. See impacket `examples/getPac.py` (S4USelf+U2U) and `getST.py`.

## 10. Decision checkpoints before coding

- [ ] Vendor Kerberos.NET vs fully hand-roll? (recommend: hand-roll DER via `System.Formats.Asn1`,
      hand-roll RC4 path first; add AES only if RC4 is refused by the DC.)
- [ ] Need cleartext machine password stored too (for AES), or NThash-only (RC4) sufficient in CONTOSO.COM?
- [ ] Parity acceptance: SID set must equal Option A output for the same user.
