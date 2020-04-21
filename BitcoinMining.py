import hashlib
import struct
import binascii
import random

ver = 0x20400000
prev_block = "00000000000000000006a4a234288a44e715275f1775b77b2fddb6c02eb6b72f"
mrkl_root = "2dc60c563da5368e0668b81bc4d8dd369639a1134f68e425a9a74e428801e5b8"
time_ = 0x5DB8AB5E
bits = 0x17148EDF

exp = bits >> 24
mant = bits & 0xffffff
target_hexstr = '%064x' % (mant * (1 << (8 * (exp - 3))))
target_str = binascii.unhexlify(target_hexstr)
hashVal = []

nonce1 = 3000000000
while nonce1 < 3100000000:
    header = (struct.pack("<L", ver) + binascii.unhexlify(prev_block)[::-1] +
              binascii.unhexlify(mrkl_root)[::-1] + struct.pack("<LLL", time_, bits, nonce1))
    hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()

    if nonce1 <= 3000000004:
        hashVal.append(binascii.hexlify(hash[::-1]))

    if hash[::-1] < target_str:
        print('Cazul 1:')
        print('Nonce1: ', nonce1)
        print('Block Hash: ', binascii.hexlify(hash[::-1]).decode('utf-8'))

        print('Primele 5 valori hash: ')
        for i in range (0,5):
            print(hashVal[i].decode('utf-8'))
        break
    nonce1 += 1

print('')
randomVal = random.randint(nonce1 + 1, nonce1 + 300000000)
nonce2 = randomVal
testsNo = 0
succes = 0
while testsNo < 100000000:
    header = (struct.pack("<L", ver) + binascii.unhexlify(prev_block)[::-1] +
              binascii.unhexlify(mrkl_root)[::-1] + struct.pack("<LLL", time_, bits, nonce2))
    hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()

    if hash[::-1] < target_str:
        succes = 1
        break
    testsNo += 1

print('Cazul 2:')
print('Nonce2 start: ', randomVal)
print('Numar testari: ', testsNo)
if succes == 0:
    print("Succes: NU");
    print('Nonce2: -')
    print('Hash2: -')
else:
    print("Succes: DA");
    print('Nonce2: ', nonce2)
    print('Hash2: ', binascii.hexlify(hash[::-1]).decode('utf-8'))
