from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# private key, serialize and to PEM format                                                   
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
# to sting                                                         
#print(f" Private key {private_key_pem.decode('utf-8')}")

#save to file 
with open ("keys/private.pem", "wb") as private_file :
    private_file.write(private_key_pem)



#public key, same logic 
public_key_ssh = public_key.public_bytes(
   encoding=serialization.Encoding.OpenSSH,
   format=serialization.PublicFormat.OpenSSH
)

with open("keys/public_key.pub", "wb") as public_file:
    public_file.write(public_key_ssh)
