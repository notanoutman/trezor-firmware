from trezor import wire
from trezor.crypto import bip32, hashlib, hmac

from apps.bitcoin.multisig import multisig_pubkey_index
from apps.bitcoin.writers import write_bytes_prefixed
from apps.common import seed
from apps.common.writers import (
    empty_bytearray,
    write_bitcoin_varint,
    write_bytes_fixed,
    write_uint8,
)

from . import common, scripts
from .verification import SignatureVerifier

if False:
    from typing import List, Optional, Tuple
    from trezor.messages.MultisigRedeemScriptType import MultisigRedeemScriptType
    from trezor.messages.TxInputType import EnumTypeInputScriptType
    from apps.common.coininfo import CoinInfo

# This module implements the SLIP-0019 proof of ownership format.

_VERSION_MAGIC = b"SL\x00\x19"
_FLAG_USER_CONFIRMED = 0x01
_OWNERSHIP_ID_LEN = 32
_OWNERSHIP_ID_KEY_PATH = [b"SLIP-0019", b"Ownership identification key"]


def generate_proof(
    node: bip32.HDNode,
    script_type: EnumTypeInputScriptType,
    multisig: MultisigRedeemScriptType,
    coin: CoinInfo,
    user_confirmed: bool,
    ownership_ids: List[bytes],
    script_pubkey: bytes,
    commitment_data: Optional[bytes],
) -> Tuple[bytes, bytes]:
    flags = 0
    if user_confirmed:
        flags |= _FLAG_USER_CONFIRMED

    proof = empty_bytearray(4 + 1 + 1 + len(ownership_ids) * _OWNERSHIP_ID_LEN)

    write_bytes_fixed(proof, _VERSION_MAGIC, 4)
    write_uint8(proof, flags)
    write_bitcoin_varint(proof, len(ownership_ids))
    for ownership_id in ownership_ids:
        write_bytes_fixed(proof, ownership_id, _OWNERSHIP_ID_LEN)

    sighash = hashlib.sha256(proof)
    sighash.update(script_pubkey)
    if commitment_data:
        sighash.update(commitment_data)
    signature = common.ecdsa_sign(node, sighash.digest())
    public_key = node.public_key()

    script_sig = scripts.input_derive_script(
        script_type, multisig, coin, common.SIGHASH_ALL, public_key, signature
    )
    if script_type in common.SEGWIT_INPUT_SCRIPT_TYPES:
        if multisig:
            # find the place of our signature based on the public key
            signature_index = multisig_pubkey_index(multisig, public_key)
            witness = scripts.witness_p2wsh(
                multisig, signature, signature_index, common.SIGHASH_ALL
            )
        else:
            witness = scripts.witness_p2wpkh(signature, public_key, common.SIGHASH_ALL)
    else:
        # Zero entries in witness stack.
        witness = b"\x00"

    write_bytes_prefixed(proof, script_sig)
    proof.extend(witness)
    return proof, signature


def verify_nonownership(
    proof: bytes,
    script_pubkey: bytes,
    commitment_data: bytes,
    keychain: seed.Keychain,
    coin: CoinInfo,
) -> bool:
    if not proof[:4] == _VERSION_MAGIC:
        raise wire.DataError("Unknown format of proof of ownership")

    flags = proof[4]
    if flags & 0b1111_1110:
        raise wire.DataError("Unknown flags in proof of ownership")

    # Extract signature and witness data from the proof.
    id_count, id_offset = scripts.read_bitcoin_varint(proof, 5)
    sig_offset = id_offset + id_count * _OWNERSHIP_ID_LEN
    script_sig_len, script_sig_offset = scripts.read_bitcoin_varint(proof, sig_offset)
    proof_body = proof[:sig_offset]
    script_sig = proof[script_sig_offset : script_sig_offset + script_sig_len]
    witness = proof[script_sig_offset + script_sig_len :]

    verify_proof_signature(
        proof_body, script_pubkey, commitment_data, script_sig, witness, coin
    )

    # Determine whether our ownership ID appears in the proof.
    ownership_id = get_identifier(script_pubkey, keychain)
    for _ in range(id_count):
        if proof[id_offset : id_offset + _OWNERSHIP_ID_LEN] == ownership_id:
            return False
        id_offset += _OWNERSHIP_ID_LEN
    return True


def verify_proof_signature(
    proof_body: bytes,
    script_pubkey: bytes,
    commitment_data: bytes,
    script_sig: bytes,
    witness: bytes,
    coin: CoinInfo,
) -> None:
    sighash = hashlib.sha256(proof_body)
    sighash.update(script_pubkey)
    sighash.update(commitment_data)

    verifier = SignatureVerifier(script_pubkey, script_sig, witness, coin)
    verifier.verify(sighash.digest())


def get_identifier(script_pubkey: bytes, keychain: seed.Keychain):
    # k = Key(m/"SLIP-0019"/"Ownership identification key")
    node = keychain.derive(_OWNERSHIP_ID_KEY_PATH)

    # id = HMAC-SHA256(key = k, msg = scriptPubKey)
    return hmac.Hmac(node.key(), script_pubkey, hashlib.sha256).digest()
