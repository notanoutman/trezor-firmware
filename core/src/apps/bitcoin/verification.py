from trezor import wire
from trezor.crypto.hashlib import sha256

from apps.common.coininfo import CoinInfo

from .common import ecdsa_hash_pubkey, ecdsa_verify
from .scripts import (
    input_script_p2wpkh_in_p2sh,
    input_script_p2wsh_in_p2sh,
    output_script_native_p2wpkh_or_p2wsh,
    output_script_p2pkh,
    output_script_p2sh,
    read_input_script_multisig,
    read_input_script_p2pkh,
    read_output_script_multisig,
    read_witness_p2wpkh,
    read_witness_p2wsh,
)


class SignatureVerifier:
    def __init__(
        self, script_pubkey: bytes, script_sig: bytes, witness: bytes, coin: CoinInfo,
    ):
        self.threshold = 1
        if not script_sig:
            if len(script_pubkey) == 22:  # P2WPKH
                self.public_keys, self.signatures = read_witness_p2wpkh(witness)
                pubkey_hash = ecdsa_hash_pubkey(self.public_keys[0], coin)
                if output_script_native_p2wpkh_or_p2wsh(pubkey_hash) != script_pubkey:
                    raise wire.DataError("Invalid public key hash")
                return
            if len(script_pubkey) == 34:  # P2WSH
                script, self.signatures = read_witness_p2wsh(witness)
                script_hash = sha256(script).digest()
                if output_script_native_p2wpkh_or_p2wsh(script_hash) != script_pubkey:
                    raise wire.DataError("Invalid script hash")
                self.public_keys, self.threshold = read_output_script_multisig(script)
                return
        elif witness and witness != b"\x00":
            if len(script_sig) == 23:  # P2WPKH nested in BIP16 P2SH
                self.public_keys, self.signatures = read_witness_p2wpkh(witness)
                pubkey_hash = ecdsa_hash_pubkey(self.public_keys[0], coin)
                if input_script_p2wpkh_in_p2sh(pubkey_hash) != script_sig:
                    raise wire.DataError("Invalid public key hash")
                script_hash = coin.script_hash(script_sig[1:])
                if output_script_p2sh(script_hash) != script_pubkey:
                    raise wire.DataError("Invalid script hash")
                return
            if len(script_sig) == 35:  # P2WSH nested in BIP16 P2SH
                script, self.signatures = read_witness_p2wsh(witness)
                script_hash = sha256(script).digest()
                if input_script_p2wsh_in_p2sh(script_hash) != script_sig:
                    raise wire.DataError("Invalid script hash")
                script_hash = coin.script_hash(script_sig[1:])
                if output_script_p2sh(script_hash) != script_pubkey:
                    raise wire.DataError("Invalid script hash")
                self.public_keys, self.threshold = read_output_script_multisig(script)
                return
        else:
            if len(script_pubkey) == 25:  # P2PKH
                self.public_keys, self.signatures = read_input_script_p2pkh(script_sig)
                pubkey_hash = ecdsa_hash_pubkey(self.public_keys[0], coin)
                if output_script_p2pkh(pubkey_hash) != script_pubkey:
                    raise wire.DataError("Invalid public key hash")
                return
            if len(script_pubkey) == 23:  # P2SH
                script, self.signatures = read_input_script_multisig(script_sig)
                script_hash = coin.script_hash(script)
                if output_script_p2sh(script_hash) != script_pubkey:
                    raise wire.DataError("Invalid script hash")
                self.public_keys, self.threshold = read_output_script_multisig(script)
                return

        raise wire.DataError("Unsupported signature script")

    def check_hash_type(self, hash_type: int) -> bool:
        for signature in self.signatures:
            if signature[1] != hash_type:
                return False
        return True

    def verify(self, digest: bytes) -> None:
        if self.threshold != len(self.signatures):
            raise wire.DataError("Invalid signature")

        try:
            i = 0
            for signature in self.signatures:
                while not ecdsa_verify(self.public_keys[i], signature[0], digest):
                    i += 1
        except Exception:
            raise wire.DataError("Invalid signature")
