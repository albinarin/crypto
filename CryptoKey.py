import binascii
import ecdsa
import hashlib
import codecs
import sertif_center as sc
import time
import requests
import time
import base64
import ecdsa
import base58
def PrivateKeyStr(private_key):
    return (binascii.hexlify(private_key.to_string()).decode('ascii').upper())
def PrivateKey():
     private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
     public_key = private_key.get_verifying_key()
     if (sc.check_write(PublicKeyStr(public_key)) != True):
        private_key=ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
     #print(binascii.hexlify(private_key.to_string()).decode('ascii').upper())
     #pstr = binascii.hexlify(private_key.to_string()).decode('ascii').upper()
     return private_key
def PublicKeyStr(public_key):
    pk = binascii.hexlify(public_key.to_string()).decode('ascii').upper()
    return pk
def PublicKey( private_key):
     public_key = private_key.get_verifying_key()

     #print(type(binascii.hexlify(public_key.to_string()).decode('ascii').upper()))
     pk = binascii.hexlify(public_key.to_string()).decode('ascii').upper()
     return  public_key
def Address(s):
    a=pubKeyToAddr(s)
    adr = ""

    for i in range(len(a)):
        if (a[i] != '1'):
            adr = adr + a[i]

    return adr.upper()

def pubKeyToAddr(s):
     ripemd160 = hashlib.new('ripemd160', s.encode('ascii')).hexdigest()
     #ripemd160.update(hashlib.sha256(s.encode('ascii')).digest())


     #print(ripemd160)
     return base58CheckEncode(0, ripemd160)
def privateKeyToPublicKey(private_key):
     pk = binascii.hexlify(private_key).decode('ascii')

     return ('\04' + pk).encode('ascii')
def privateKeyToPublicKey2(s):
    sk = ecdsa.SigningKey.from_string(s.decode('hex'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return ('\04' + sk.verifying_key.to_string()).encode('hex')
def base58CheckEncode(prefix, payload):
     s = chr(prefix) + payload

     checksum = hashlib.sha256(hashlib.sha256(codecs.encode(s.encode('ascii'), 'hex')).digest()).digest()[0:4]
     #print(type(codecs.encode(checksum, 'hex')))

     #print(checksum)
     f=hashlib.sha256(s.encode('ascii')).hexdigest()[0:4]

     result = s+f
    # result = s + checksum.encode('ascii')
     return '1' * countLeadingZeroes(result) + base58encode(base256decode(result))
def countLeadingZeroes(s):
     count = 0
     for c in s:
         if c == '\0':
             count += 1
         else:
             break
     return count

def base58encode(n):
     b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
     result = ''
     while n > 0:
         result = b58[int(n % 58)] + result
         n /= 58
     return result

 # Will be used to decode raw bytes and then encode them to the base58
def base256decode(s):
     result = 0
     for c in s:
         result = result * 256 + ord(c)
     return result
pk=PrivateKey()
p=PrivateKeyStr(pk)
k=PublicKey(pk)
a=Address(p)
print(p)
print(PublicKeyStr(k))
print(a)
def sign_ECDSA_msg(private_key , message):
    """Подписываем сообщение для отправки
    private ключ отправляем в виде p=PrivateKeyStr(pk)
    return
    signature: base58
    message: str
    """
    # получаем timestamp, округляем, переводим в строку и кодируем

    bmessage = message.encode()
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    signature = base58.b58encode(sk.sign(bmessage))
    #print(str(signature))
    return signature,message
# пример использования функции создания подписи
sig, mes=sign_ECDSA_msg(p, 'hello')

def validate_signature(public_key,signature,message):
    """Проверяем правильность подписи. Это используется для доказательства того, что это вы
    (а не кто-то еще), пытающийся совершить транзакцию за вас. Вызывается, когда пользователь
    пытается отправить новую транзакцию.
    public_key подается в виде строки с помощью функции PublicKeyStr(k)
    signature result sign_ECDSA_msg base58
    message result sign_ECDSA_msg
    """


    signature = base58.b58decode(signature)
    vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
    try:
        return(vk.verify(signature, message.encode()))
    except:
        return False

#пример использования функции валидации подписи
print(validate_signature(PublicKeyStr(k), sig,mes))
