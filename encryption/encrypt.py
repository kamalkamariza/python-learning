import boto3
import ujson as json 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


ssm = boto3.client('ssm')
parameter = ssm.get_parameter(Name='/data-anonymization/public', WithDecryption=True)
public_key = parameter["Parameter"]["Value"] 
parameter = ssm.get_parameter(Name='/data-anonymization/private', WithDecryption=True)
private_key = parameter["Parameter"]["Value"]

# public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDKSoG4dt3lfpYUQ6e3nTXfyMl0d6DpueePTqkUGhcYTJ+ubKUQib5q6s3qZUUroFXM5R/7EeLz1fe2etPwx6OJEqLCPUAEaE1q+140O+7f/mEsAUgWPVl/gFiU2RClZtWBO5hZRXHq2ZLM4FSzWv1kWuAmDC/uov6AM5WQGCHdh3yZqi0cu15TqYR9JFvt9spPBkLNpBGLQ3jKSo0evVr5PnSKrEzC9UXzsN0OYSrx2ueKVD+S4GMoQ9sCmV4sRGVoEg+x2GTi7aenaLZR9k5dvmJCCI3Uosv8QX6cRZZojGhkHAykPXY0CkUTpM4BHMuZMb54jdZwXtejQ9V0E/Ph noname"
# private_key = "-----BEGIN OPENSSH PRIVATE KEY-----b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcnNhAAAAAwEAAQAAAQEAykqBuHbd5X6WFEOnt50138jJdHeg6bnnj06pFBoXGEyfrmylEIm+aurN6mVFK6BVzOUf+xHi89X3tnrT8MejiRKiwj1ABGhNavteNDvu3/5hLAFIFj1Zf4BYlNkQpWbVgTuYWUVx6tmSzOBUs1r9ZFrgJgwv7qL+gDOVkBgh3Yd8maotHLteU6mEfSRb7fbKTwZCzaQRi0N4ykqNHr1a+T50iqxMwvVF87DdDmEq8drnilQ/kuBjKEPbApleLERlaBIPsdhk4u2np2i2UfZOXb5iQgiN1KLL/EF+nEWWaIxoZBwMpD12NApFE6TOARzLmTG+eI3WcF7Xo0PVdBPz4QAAA8DzThLi804S4gAAAAdzc2gtcnNhAAABAQDKSoG4dt3lfpYUQ6e3nTXfyMl0d6DpueePTqkUGhcYTJ+ubKUQib5q6s3qZUUroFXM5R/7EeLz1fe2etPwx6OJEqLCPUAEaE1q+140O+7f/mEsAUgWPVl/gFiU2RClZtWBO5hZRXHq2ZLM4FSzWv1kWuAmDC/uov6AM5WQGCHdh3yZqi0cu15TqYR9JFvt9spPBkLNpBGLQ3jKSo0evVr5PnSKrEzC9UXzsN0OYSrx2ueKVD+S4GMoQ9sCmV4sRGVoEg+x2GTi7aenaLZR9k5dvmJCCI3Uosv8QX6cRZZojGhkHAykPXY0CkUTpM4BHMuZMb54jdZwXtejQ9V0E/PhAAAAAwEAAQAAAQEAxYAi0Gd1U6fYfSZkrBcYT0morkZR23/+vWKuHwst+zJsQI6gRdpGB/sBWdTPyL08p9QX+jfHXgtMU2PuYsl3N8/zCjNkuijfVRDgM51EJnskgiMqL1RsedhkI8cdwm75CriVkKsFgqYz9kUbTRUMChvTdjI15gZK9f3nCw0Um0P7jHAblYqUTPaeWhuJ4cVhg4SSNP+ZQdFoSYmCCqYUvVVNqhmE6scUXSJGVn5wB6mOWkMzHdR9WacGXfsem4E4FZPfYiA1MXmuOGJYPM94gpmutDIfHk1vPIGMnLOaBg1X9nAaATvKAKPnjPOcxNETL/2ibCrzs/lwHyfprCkKxQAAAIEA4gEHqW/DNwPsJ2FCLZODBVAUZbccACPe2iY1eknK+bJIrDhdS1c32qGz6eIGG5OArEP+Ug1nuuJ9vERzW+9xZAd5pKXY/UNK7pEz7g42hGYcjObmVBT2xDVvCYzvCTY8ctQ8q7cHy8y6iOEvktravzFcklAmh/zX3rmDUZOzoBwAAACBAPd8sbE7BE3Tx20tBmCuaeHEqoQV3Xu+kjbRm9qX6Xa93DDuUflIvL4XX8oYAa95g8Q6S7gIJ2MQLR5hx38m0P7PWEqBzQGMshM/qIJAxcn6hKu6pVZ+GCiFfL7wtF54D7pd3DEGyxW0zFxwcwKGvbPrM5HRBYy+3XNriyfZRcE3AAAAgQDRP9QD6TZSqjWcAEt66rvGMmKq71l6gvLPAz/s0t548vyYpimTGFufU0QZ5Jf9TNPtWD66iKG557Mxg/yy6JCQtAlG7RQTqNEMRvDbNrUdbFW12WQ4GbyyNCE51XTK/sjwBlZTSzJCzvDdrOyUaVDqyvnzqGk8stlkR4A+39zfpwAAAAZub25hbWUBAgM=-----END OPENSSH PRIVATE KEY-----"
def encrypt_string_with_ssh_rsa_key(public_key_str, text_string):
    # Load the SSH-RSA public key from the string
    public_key = serialization.load_ssh_public_key(public_key_str.encode(), backend=default_backend())

    # Encrypt the text string using the public key
    encrypted_data = public_key.encrypt(
        text_string.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Return the base64-encoded encrypted data as a string
    return encrypted_data.hex()

def decrypt_data_with_ssh_rsa_key(private_key_str, encrypted_data):
    # Load the SSH-RSA private key from the string
    private_key = serialization.load_ssh_private_key(
        private_key_str.encode(),
        password=None,
        backend=default_backend()
    )

    # Decrypt the encrypted data using the private key
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Return the decrypted data as a string
    return decrypted_data.decode()

# Example usage

text_string = "Sifu CY"

encrypted_string = encrypt_string_with_ssh_rsa_key(public_key, text_string)
print(encrypted_string)

# encrypted_string = 'c9753d1f12837d235558f0177986e214406cd50f39ea6a982f386691d466a053be0e23ffad17eddf763bd079699e9e7c181250740c43111ff4182b5f215057d841deb9ed8e4a1d6179319e3e05dd07154e6c23536bdc1ec0cf2a1043dcac4d162902e8f3e5b090b28585906c1c9f91dd3a7f490c4848dda39c886f93b4b985c69367c748a8e3e915259eb7d4ee1ef28ca90a7db266cb2ef49456c2352468a8167b2403677cf5e1bfdc8e66f250e75ba7ce0f05574a82f83a0a93cc2fa960980098e5c3fa2e01da55b634ae40df4e0a6c14ff2549812dcfc5c54250df01ff2536244ccb5659d72615e5925713bfd14a3f1e9dd77987707c10af874413ad567f71'
# encrypted_string = '756d9fa57ca73483d22490c9435d4b6d9b0a4392df08c9f4d4c63f2fc8f644a05123368b11c0afe849f8a5660905c64db1a9aef3a99e5c07f8c1f398305994a66a65063e1bbfc773c86fdc0fa143c98c4b44e48cbe2bd53b66a3a21189a5970c885d7c1c86e118a7dbed09401247e0fcbe2f5fd882aa37981c37697624b03ea3c1b01b4d80573def989bf6f6f13d5f913b8945cb2537e64fc40cc61684a7e4b679e9359d19c9333ab178da678107773b54b55218412a1c01a7a5daa9c8c8349a3a62d12019c2474e29cebc9dbfe366a588189cfa51bd55f09ec0b2cbab9b7600f44747ba3032050be4cf0f7fbeb40475793fb39a5cdec488a34fd13db71cadeb'
# encrypted_string = 'be760894edf1bd7eddf70a0d96dfe11e0a79aeaf5710b6cef83e2b187faccb986eccdeee50061192b0bfbdb6f1d93677663deaeefa70898f389cfae7ef7f20191d0228cd7ee16e714d740b9712d72e705a434ba57dd54d97926a4a74c11248673a133d5f03b74595ada0b4d5a918d573a0b955a0108aea36bbcbff533b7349e92fd79a4672a95af1783bf98075deacf9d54744fc059a00a63c321462d0d91bba8b5683d6e9c37121f06f9b11f032206ff92ce1ea9a1939f503ddf312cfbd07eb7da9d911bfa0914d2363980a1b93543c633e2d8a4c62345bf05d752e2f7fbd1468ca138ffc71e5d4fdbc8aa5d3b6a4cb3b714ba8db90b59e4346d123078d3931'

encrypted_data = bytes.fromhex(encrypted_string)
decrypted_data = decrypt_data_with_ssh_rsa_key(private_key, encrypted_data)
print(decrypted_data)