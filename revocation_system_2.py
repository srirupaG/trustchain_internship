import didkit
import asyncio
import json
from ast import literal_eval
from datetime import timedelta, datetime
from pyroaring import BitMap
import base64
import zlib

# Define a revocation list
revocation_list = set()

def print_verifiable_credential(credential):
    # print("Issued Verifiable Credential::::::::")
    print(json.dumps(credential, indent=2))

# Revoke the credential by adding it to the revocation list
def revoke_credential(credential):
    revocation_list.add(credential["id"])


# Check if the credential ID is in the revocation list
def is_credential_revoked(credential_id):
    return credential_id in revocation_list

def resolve_did(keydid):
    async def inner():
        return await didkit.resolve_did(keydid, "{}")

    return asyncio.run(inner())

def render_and_sign_credential(unsigned_vc: dict, jwk_issuer):
   
    async def inner():
        signed_vc = await didkit.issue_credential(
            json.dumps(unsigned_vc),
            '{"proofFormat": "ldp"}',
            jwk_issuer
        )
        return signed_vc

    return asyncio.run(inner())


def verify_credential(vc):
    # print("First VC", vc)

    async def inner():
        try:
            str_res = await didkit.verify_credential(vc, '{"proofFormat": "ldp"}')
        except:
            return False, "Invalid, corrupt, or tampered-with credential."
        res = literal_eval(str_res)
        ok = res["warnings"] == [] and res["errors"] == []
        return ok, str_res

    valid, reason = asyncio.run(inner())
    if not valid:
        return valid, reason

    vc = json.loads(vc)
    if "credentialStatus" in vc:
        vc_issuer = vc["credentialStatus"]["id"]  
        print("vc_issuer:::::", vc_issuer)
        if vc_issuer == "https://revocation.not.supported/":
            return True, "This credential does not support revocation"
        revocation_index = int(vc["credentialStatus"]["revocationBitmapIndex"])  
        issuer_did_document = json.loads(resolve_did(vc_issuer)) 
        issuer_revocation_list = issuer_did_document["service"][0]
        assert issuer_revocation_list["type"] == "RevocationBitmap2022"
        revocation_bitmap = BitMap.deserialize(zlib.decompress(base64.b64decode(issuer_revocation_list["serviceEndpoint"].rsplit(",")[1])))
        if revocation_index in revocation_bitmap:
            return False, "Credential has been revoked by the issuer"
    return True, "Credential passes all checks"



def revoke_verifiable_credential(credential, revocation_list_id):
    credential["credentialStatus"] = {
        "id": f"{revocation_list_id}#entry123",
        "type": "RevocationBitmap2022",
        "revocationListIndex": "entry123",
        "revocationListCredential": revocation_list_id,
    }

    return credential

def revoked_credential(signed_credential):

    # add the revoked credential (signed_credential) into the list
    revoke_credential(signed_credential)
    credential_id = signed_credential.get("id")
    # print("credential_id:", credential_id)


def test_for_valid_credential(signed_credential):
    if isinstance(signed_credential, str):
        # Convert the string to a dictionary if it's in JSON format
        signed_credential = json.loads(signed_credential)

    # Check if the credential is revoked
    is_revoked = is_credential_revoked(signed_credential.get("id"))
    # print("=======Test whether the credential is revoked or not ======")
    print("############# Test whether the credential is revoked or not ###################")

    if is_revoked:
        print("The credential is revoked:", is_revoked)
        print("revocation_list:::", revocation_list)
    else:
        print("The credential is not revoked and is valid:", is_revoked)



def issue_credential():
    issuer_did_jwk = didkit.generate_ed25519_key()
    issuer_did = didkit.key_to_did("key", issuer_did_jwk)
    subject_did_jwk2 = didkit.generate_ed25519_key()
    subject_did = didkit.key_to_did("key", subject_did_jwk2)

    expiration_date = datetime.utcnow() + timedelta(days=365)

    credential = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1",
        ],
        "id": "https://example.com/credentials/123",
        "type": ["VerifiableCredential", "ExampleCredential"],
        "issuer": issuer_did,
        "issuanceDate": datetime.utcnow().isoformat() + "Z",
        "expirationDate": expiration_date.isoformat() + "Z",
        "credentialSubject": {
            "id": subject_did,
            "degree": {"type": "BachelorDegree", "name": "Bachelor of Science"},
        },
    }

    signed_credential = render_and_sign_credential(
        credential,
        issuer_did_jwk,
    )

    print_verifiable_credential(json.loads(signed_credential))
    return signed_credential


if __name__ == "__main__":

    print("############# Issue Credential ###################")
    signed_credential = issue_credential()
    print("############# Verifies the credential ###################")
    verification_result = verify_credential(signed_credential)
    print_verifiable_credential(verification_result)

    test_for_valid_credential(signed_credential)

    print("############# The credential is revoked ###################")

    revocation_list_id = "https://example.com/revocation/list"

    verifiable_credential_with_status = revoke_verifiable_credential(json.loads(signed_credential), revocation_list_id)
    print_verifiable_credential(verifiable_credential_with_status)

    revoked_credential_result = revoked_credential(verifiable_credential_with_status)
    test_for_valid_credential(verifiable_credential_with_status)

    # print_verifiable_credential(revoked_credential_result)
    # print("################################")
    print("############# Verifies the revoked credential ###################")
    verification_result = verify_credential(verifiable_credential_with_status)
    # print("################################")
    print_verifiable_credential(verification_result)

    


    