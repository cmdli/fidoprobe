# fidoprobe

`fidoprobe` is a utility to list, delete, and inspect credentials on a FIDO2 device (such as a Yubikey or other passkey device).

Note: It does not work with platform authenticators like TouchID or Windows Hello, as those don't use the USB HID API and instead have a separate API. Likewise, it will not work with browser extension-based passkeys (like Bitwarden) as those only exist in the browser.

## Installation

```
cargo install fidoprobe
```

## Usage

```
> fidoprobe --help
A utility to interact with FIDO2 devices

Usage: fidoprobe <COMMAND>

Commands:
  list     List credentials
  info     Get info for a particular credential
  create   Create a new credential
  delete   Delete a credential
  set-pin  Set the PIN on an authenticator
  reset    Reset an authenticator
  sign     Sign a challenge with a credential
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
> fidoprobe list
Enter PIN:
Authenticator: AAGuid(2fc0529f-8113-4eea-b116-bg5a8d592C2a)
Credential Count: 3 (Maximum: 25)
Relying Party "webauthn.io":
    Credential wQhAoc...qSukz:
        User ID: cnNETmhxTjRFdG5vb0FfdjI3OHhOVWRNTXRBdEpjN3JGaUdoS0daVEc2VQ==
        User Name: "Bob"
        Public key: MFkwEwYHKoZ...yVCNTYTA==
        Credential Protection Policy: UserVerificationOptional
    Credential fXOy9v...3qZAr:
        User ID: Ul81ZjF4c2FQQ2VtSm80SEZOMk1TOXF1MmFORFRMNlBINzFTaE9vWFFzYw==
        User Name: "Alice"
        Public key: MFkwEwYHKoZ...BA7Ba1BA==
        Credential Protection Policy: UserVerificationOptional
    Credential vnJ9Hh...QBeBh:
        User ID: ZXFXa21peDdPMHFqdXQyb240ZDhnaGVCcGVxSDdzcWp3WTAydHkxcWlZOA==
        User Name: "test"
        Public key: MFkwEwYHKoZ...UAuYmOeA==
        Credential Protection Policy: UserVerificationOptional
> fidoprobe info vnJ9Hh
RelyingParty:
    ID: "webauthn.io"
Credential:
    Public Key:
        ID: vnJ9HhKLnnzcwSLLAOMGTISVegLT1QOOjWiuaWsUzLuRchwxcgek/U10eSJQBeBh
        Transports: []
    User:
        ID: "ZXFXa21peDdPMHFqdXQyb240ZDhnaGVCcGVxSDdzcWp3WTAydHkxcWlZOA=="
        Name: "test"
        Display Name: "test"
    COSEKey:
        Alg: ES256
        EC2 Key:
            Curve: SECP256R1
            X: vnJ9HhKLnnzcwSLLAFBW1vCY/wFD57Gq2d9OeeNzmEI=
            Y: A25JWMQ04vVaFD4yC3Qqa62F+f391b3cxjPVALmJjng=
    Credential Protection Policy: UserVerificationOptional
```
