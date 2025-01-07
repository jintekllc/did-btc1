import sys
import os
import jcs

from buidl.mnemonic import secure_mnemonic
from buidl.hd import HDPrivateKey
from buidl.helper import sha256, encode_base58, decode_base58, encode_base58_checksum
from buidl.ecc import S256Point
from buidl.taproot import MuSigTapScript, TapRootMultiSig, P2PKTapScript

mnemonic = secure_mnemonic()

mnemonic = "offer apple busy alarm lawsuit fence deny marriage beauty divorce essay message task believe buyer error planet energy frozen gap bronze tissue umbrella access"
root_hdpriv = HDPrivateKey.from_mnemonic(mnemonic, network="signet")

print("Mnemonic : ", mnemonic)

beacon_advert = {
    "id": "SOMEBEACONID",
    "type": "SMTAggregatorBeacon",
    "cohort_size": 2,
    "btc_network": "signet",
    "frequency": "1 per month",
    "return_address": "SMT_Aggregator => Copy + Paste",
}

didkey_purpose = "11"

cohort_participation_sk = root_hdpriv.get_private_key(didkey_purpose, address_num=2)
cohort_participation_pk = cohort_participation_sk.point

print("Secp256k1 PrivateKey", cohort_participation_sk.hex())
print("Secp256k1 Public Key", cohort_participation_pk.__repr__())

hex_pubkey = cohort_participation_pk.sec().hex()

beacon_opt_in = {
    "advert_id": beacon_advert["id"],
    "participant_pubkey": hex_pubkey,
    # TODO: this could be a DID serviceEndpoint?
    "return_interact": "Alexis => Copy+Paste",
    # TODO: some authentication?
}

data = jcs.canonicalize(beacon_opt_in)

hash_data = sha256(data)
sig = cohort_participation_sk.sign_schnorr(hash_data)
sig.serialize()

print("Copy and Paste the below output into step B3 in the Aggregator notebook\n\n")
print(beacon_opt_in)

cohort_set_payload = {
    "advert_id": "SOMEBEACONID",
    "participant_pubkeys": [
        "0242f96da7b5a849b97044a9e494ac711f14fd5189e468b84fcc8fad4b007302d6",
        "02f0a96d61fd8451566b861bc78f2e2a34679b841dcd7397f2ed9af95225d8da72",
    ],
    "beacon_address": "tb1p8fx4cmaqt0hsrnw6kprqcjtrtrhkpjvclzwra58yz8klp4r7vv4qs3hpz5",
}
assert cohort_set_payload["advert_id"] == beacon_advert["id"]

cohort_hex_pks = cohort_set_payload["participant_pubkeys"]
assert hex_pubkey in cohort_hex_pks

musig = MuSigTapScript(cohort_pks)

tr_multisig = TapRootMultiSig(cohort_pks, len(cohort_pks))
internal_pubkey = tr_multisig.default_internal_pubkey
branch = tr_multisig.musig_tree()
tr_merkle_root = branch.hash()

network = beacon_advert["btc_network"]
p2tr_beacon_address = internal_pubkey.p2tr_address(tr_merkle_root, network=network)

assert cohort_set_payload["beacon_address"] == p2tr_beacon_address

print("Beacon Address Set : " + p2tr_beacon_address)


intermediate_did_doc = {}
intermediate_did_doc["@context"] = [
    "https://www.w3.org/ns/did/v1",
    # "<didbtc_context>"
]
initial_vm_privkey = root_hdpriv.get_private_key(didkey_purpose, address_num=4)
initial_vm_pubkey = initial_vm_privkey.point
initial_vm_privkey.wif(compressed=False)

verificationMethod = {}
verificationMethod["id"] = "#initialKey"
verificationMethod["type"] = "JsonWebKey"
x = initial_vm_pubkey.sec().hex()
d = initial_vm_privkey.hex()
kty = "EC"
crv = "secp256k1"
jwkObject = {"kty": kty, "crv": crv, "x": x}

verificationMethod["publicKeyJwk"] = jwkObject

intermediate_did_doc["verificationMethod"] = [verificationMethod]
print("verificationMethod : ", verificationMethod)

intermediate_did_doc["authentication"] = [verificationMethod["id"]]
intermediate_did_doc["assertionMethod"] = [verificationMethod["id"]]
intermediate_did_doc["capabilityInvocation"] = [verificationMethod["id"]]
intermediate_did_doc["capabilityDelegation"] = [verificationMethod["id"]]

services = []

single_beacon_private_key = root_hdpriv.get_private_key(didkey_purpose, address_num=3)
single_beacon_public_key = single_beacon_private_key.point

## Create Beacon address
# p2pkh
p2pkh_address = single_beacon_public_key.p2pkh_script().address(network=network)
# p2wpkh
p2wpkh_address = single_beacon_public_key.p2wpkh_address(network=network)
# p2tr
p2tr_address = single_beacon_public_key.p2tr_address(network=network)
