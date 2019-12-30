"""
This file is part of DKMS.
DKMS is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published b
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
DKMS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with DKMS. If not, see <https://www.gnu.org/licenses/>.
"""

from flask import Flask, request, Response, jsonify
import ipfsapi
from umbral.cfrags import CapsuleFrag
from umbral.keys import UmbralPrivateKey, UmbralPublicKey
from umbral.params import UmbralParameters
from umbral.pre import Capsule
from umbral.kfrags import KFrag
from umbral import pre, keys, signing
from umbral.curve import Curve

import pymysql

import os, base64

from werkzeug.wrappers import json

app = Flask(__name__)

conn = pymysql.connect(host="localhost", user="XXX", database="XXX", charset="utf8")


@app.route('/hello', methods=['GET'])
def hello_world():
    return "hello world"


# KeyGen
@app.route('/keygen', methods=['POST'])
def keygen():
    if request.headers['Content-Type'] == 'application/json':
        keytype = request.json['type']
        account = request.json['account']
        role = request.json['role']
        res = {}

        alices_private_key = keys.UmbralPrivateKey.gen_key()
        alices_public_key = alices_private_key.get_pubkey()

        alices_signing_key = keys.UmbralPrivateKey.gen_key()
        alices_verifying_key = alices_signing_key.get_pubkey()
        alices_signer = signing.Signer(private_key=alices_signing_key)

        # Generate Umbral keys for Bob.
        bobs_private_key = keys.UmbralPrivateKey.gen_key()
        bobs_public_key = bobs_private_key.get_pubkey()

        if keytype == "ECC":
            if role == "sender":
                ecc_enc_sk = keys.UmbralPrivateKey.gen_key()
                ecc_enc_pk = ecc_enc_sk.get_pubkey()
                res['ecc_enc_sk'] = ecc_enc_sk.to_bytes().hex()
                res['ecc_enc_pk'] = ecc_enc_pk.to_bytes().hex()

                ecc_sig_sk = keys.UmbralPrivateKey.gen_key()
                ecc_sig_pk = ecc_sig_sk.get_pubkey()
                res['signing_key'] = ecc_sig_sk.to_bytes().hex()
                res['verifying_key'] = ecc_sig_pk.to_bytes().hex()

            elif role == "receiver":
                ecc_enc_sk = keys.UmbralPrivateKey.gen_key()
                ecc_enc_pk = ecc_enc_sk.get_pubkey()
                res['ecc_enc_sk'] = ecc_enc_sk.to_bytes().hex()
                res['ecc_enc_pk'] = ecc_enc_pk.to_bytes().hex()

            else:
                res['error'] = "Not invalid role."
            # # record in DB
            # cursor = conn.cursor()
            # sql = "insert into userkey(name, keytype, sk) values('%s', '%s', '%s')" % (keytype, account, ecc_sk.to_bytes().hex())
            # try:
            #     # Execute the SQL statement
            #     cursor.execute(sql)
            # except Exception as e:
            #     print("Error: ", e)
            # cursor.close()
            # return key
            return jsonify(res), {'Content-Type': 'application/json'}
        elif keytype == "AES":
            aes_key = base64.b64encode(os.urandom(48)).hex()
            res['aes_key'] = aes_key
            # # record in DB
            # cursor = conn.cursor()
            # sql = "insert into userkey(name, keytype, sk) values('%s', '%s', '%s')" % (keytype, account, aes_key)
            # try:
            #     # Execute the SQL statement
            #     cursor.execute(sql)
            # except Exception as e:
            #     print("Error: ", e)
            # cursor.close()
            # return key
            return jsonify(res), {'Content-Type': 'application/json'}
        elif keytype == "RSA":
            return "RSA is developing."
        else:
            return "unhandled crypto keyGEN."
    else:
        return "Only accept application/json."


# encrypt
@app.route('/encrypt', methods=['POST'])
def encrypt():
    api = ipfsapi.connect('127.0.0.1', 5001)
    res = {}
    if request.headers['Content-Type'] == 'application/json':
        plaintextstr = request.json['plaintext']
        b_plaintext = bytes(plaintextstr, encoding='utf-8')
        encryptkeyhex = request.json['public_key']
        b_encryptkey = bytes.fromhex(encryptkeyhex)
        enckey = UmbralPublicKey.from_bytes(b_encryptkey)
        ciphertext, capsule = pre.encrypt(enckey, b_plaintext)

        capsuleaddr = api.add_bytes(capsule.to_bytes())
        res = {"ciphertext": ciphertext.hex(), "capsule": capsuleaddr}
        return jsonify(res), {'Content-Type': 'application/json'}
    return


# kfraggen
@app.route('/kfraggen', methods=['POST'])
def kfraggen():
    api = ipfsapi.connect('127.0.0.1', 5001)
    addrs = list()
    if request.headers['Content-Type'] == 'application/json':
        account = request.json['account']
        # 所有的传入参数都是hex key
        delegatekey = request.json['delegatekey']
        b_delegatekey = bytes.fromhex(delegatekey)
        dk = UmbralPrivateKey.from_bytes(b_delegatekey)

        # signer参数就是传入alice的另一个sk
        signersk = request.json['signersk']
        b_signersk = bytes.fromhex(signersk)
        signk = UmbralPrivateKey.from_bytes(b_signersk)
        signer = signing.Signer(signk)

        publickey = request.json['publickey']
        b_publickey = bytes.fromhex(publickey)
        bpk = UmbralPublicKey.from_bytes(b_publickey)

        threshold = request.json['threshold']
        N = request.json['N']

        # 测试写入库 error
        # cursor = conn.cursor()
        # sql = "insert into saved(name, delekey, signingkey, receiverpk) values('%s', '%s', '%s', '%s')"
        #       % (account, delegatekey, signersk, publickey)
        # try:
        #     # Execute the SQL statement
        #     cursor.execute(sql)
        # except Exception as e:
        #     print("Error: ", e)
        # cursor.close()

        kfrags = pre.generate_kfrags(delegating_privkey=dk,
                                     signer=signer,
                                     receiving_pubkey=bpk,
                                     threshold=threshold,
                                     N=N)
        for kf in kfrags:
            addrs.append(api.add_bytes(kf.to_bytes()))
        # for addr in addrs:
        #     print(addr)
            # # ipfs地址读取bytes
            # biarray = api.cat(addr)
            # print(biarray)
            #
            # # bytes转key
            # kfragobj = KFrag.from_bytes(biarray)
            # print(kfragobj)
            #
            # # key转bytes
            # bye = kfragobj.to_bytes()
            # print(bye)
            #
            # # bytes转str
            # kfraghex = biarray.hex()
            # print(kfraghex)
            #
            # # str转bytes
            # d = bytes.fromhex(kfraghex)
            # print(d)
            # print("\n")

        # N个frag的ipfs地址写入数据库，带account。
        # cursor = conn.cursor()~~~
        # for addr in addrs:
            # sql = "insert into XXX(name, address) values('%s', '%s')" % (account, addr)
            # try:
            #     # Execute the SQL statement
            #     cursor.execute(sql)
            # except Exception as e:
            #     print("Error: ", e)
        # cursor.close()

        return jsonify(addrs), {'Content-Type': 'application/json'}
    return


# reencrypt
@app.route('/reencrypt', methods=['POST'])
def reencrypt():
    api = ipfsapi.connect('127.0.0.1', 5001)
    addrs = list()
    caddrs = list()
    res = {}
    if request.headers['Content-Type'] == 'application/json':
        account = request.json['account']
        # 所有的传入参数都是hex key
        threshold = request.json['threshold']
        capsulehex = request.json['capsule']
        b_capsule = api.cat(capsulehex)
        capsule = Capsule.from_bytes(b_capsule, UmbralParameters(Curve(714)))
        addrs = request.json['addresses']

        delegatinghex = request.json['delegating']
        b_delegating = bytes.fromhex(delegatinghex)
        delegating = UmbralPublicKey.from_bytes(b_delegating)
        receivinghex = request.json['receiving']
        b_receiving = bytes.fromhex(receivinghex)
        receiving = UmbralPublicKey.from_bytes(b_receiving)
        verifyinghex = request.json['verifying']
        b_verifying = bytes.fromhex(verifyinghex)
        verifying = UmbralPublicKey.from_bytes(b_verifying)
        if threshold > len(addrs):
            return "Not enough addresses."

        capsule.set_correctness_keys(delegating=delegating,
                                     receiving=receiving,
                                     verifying=verifying)

        cfrags = list()  # Receiver's cfrag collection
        # each kfrag is a rk segment
        for addr in addrs:
            rkseg = KFrag.from_bytes(api.cat(addr))
            # cfrag = pre.reencrypt(kfrag=kfrag, capsule=capsule)
            cfrag = pre.reencrypt(kfrag=rkseg, capsule=capsule)
            cfrags.append(cfrag)  # Receiver's collects a cfrag

        for cfrag in cfrags:
            caddrs.append(api.add_bytes(cfrag.to_bytes()))
        savedcap = capsule.to_bytes_all()
        # savedcap包括三块，basic为capsule，correctness为set的key，cfrag是append上去的东西，此时还为空
        print(type(savedcap))
        print(type(savedcap['basic']))

        print(savedcap['correctness'])
        delegating_key = savedcap['correctness']['delegating']
        receiving_key = savedcap['correctness']['receiving']
        verifying_key = savedcap['correctness']['verifying']

        b_delegating_key = delegating_key.to_bytes()
        b_receiving_key = receiving_key.to_bytes()
        b_verifying_key = verifying_key.to_bytes()

        print(b_delegating_key)
        print(b_receiving_key)
        print(b_verifying_key)

        sendbytes = savedcap['basic'] + b'ZAtech' + b_delegating_key + b'ZBtech' + b_receiving_key + b'ZBtech' + b_verifying_key

        print(sendbytes)

        savedcapaddr = api.add_bytes(sendbytes)

        res = {"caddrs": caddrs, "capsule": savedcapaddr}
        return jsonify(res), {'Content-Type': 'application/json'}
    return


# fetch
@app.route('/fetch', methods=['POST'])
def fetch():
    api = ipfsapi.connect('127.0.0.1', 5001)
    if request.headers['Content-Type'] == 'application/json':
        account = request.json['account']
        # 所有的传入参数都是hex key
        capsuleaddr = request.json['capsule']
        b_capsule_all = api.cat(capsuleaddr)
        splitarr1 = b_capsule_all.split(b'ZAtech')
        b_basic_capsule = splitarr1[0]
        capsule = Capsule.from_bytes(b_basic_capsule, UmbralParameters(Curve(714)))
        correctness_keys = splitarr1[1]
        splitarr2 = correctness_keys.split(b'ZBtech')
        delegating = UmbralPublicKey.from_bytes(splitarr2[0])
        receiving = UmbralPublicKey.from_bytes(splitarr2[1])
        verifying = UmbralPublicKey.from_bytes(splitarr2[2])
        # print(splitarr1[0])
        # print(splitarr1[1])
        # print(splitarr2[0])
        # print(splitarr2[1])
        # print(splitarr2[2])
        print(delegating)
        print(receiving)
        print(verifying)
        caddrs = request.json['addresses']

        # 用带入的参数capsule_all的各种byte，重现绑定correctness keys的capsule.
        capsule.set_correctness_keys(delegating=delegating,
                                     receiving=receiving,
                                     verifying=verifying)
        print(capsule.get_correctness_keys())

        cfrags = list()
        all_bytes = b''
        index = 0
        for addr in caddrs:
            index += 1
            b_cfrag = api.cat(addr)
            all_bytes += b_cfrag
            if index < len(caddrs):
                all_bytes += b'ZCtech'
            cfrags.append(CapsuleFrag.from_bytes(api.cat(addr)))

        for cfrag in cfrags:
            capsule.attach_cfrag(cfrag)

        # 再将append的内容写入capsule，然后就可以将解密单独拎出来。

        b_capsule_all += b'ZAtech' + all_bytes
        savedcapaddr = api.add_bytes(b_capsule_all)

        # splitarr = b_capsule_all.split(b'ZAtech')
        # splitarrmiddle = splitarr[1].split(b'ZBtech')
        # splitarrlast = splitarr[2].split(b'ZCtech')
        # print(len(cfrags))
        # for s in splitarrmiddle:
        #     print(s)
        # print(len(splitarrlast))
        # for s in splitarrlast:
        #     print(s)

        res = {"capsule": savedcapaddr}
        return jsonify(res), {'Content-Type': 'application/json'}

    return



# decrypt
@app.route('/decrypt', methods=['POST'])
def decrypt():
    api = ipfsapi.connect('127.0.0.1', 5001)
    res = {}
    cfrags = list()
    if request.headers['Content-Type'] == 'application/json':
        account = request.json['account']
        ciphertexthex = request.json['ciphertext']
        b_ciphertext = bytes.fromhex(ciphertexthex)
        decryptkey = request.json['decryptkey']
        b_decryptkey = bytes.fromhex(decryptkey)
        deckey = UmbralPrivateKey.from_bytes(b_decryptkey)
        capsuleaddr = request.json['capsule']
        b_capsule_all = api.cat(capsuleaddr)
        splitarr1 = b_capsule_all.split(b'ZAtech')
        b_basic_capsule = splitarr1[0]
        capsule = Capsule.from_bytes(b_basic_capsule, UmbralParameters(Curve(714)))
        print("0")
        correctness_keys = splitarr1[1]
        splitarr2 = correctness_keys.split(b'ZBtech')
        delegating = UmbralPublicKey.from_bytes(splitarr2[0])
        receiving = UmbralPublicKey.from_bytes(splitarr2[1])
        verifying = UmbralPublicKey.from_bytes(splitarr2[2])

        # 用带入的参数capsule_all的各种byte，重现绑定correctness keys的capsule.
        capsule.set_correctness_keys(delegating=delegating,
                                     receiving=receiving,
                                     verifying=verifying)
        print("1")

        b_cfrag_all = splitarr1[2].split(b'ZCtech')
        for b_cfrag in b_cfrag_all:
            cfrags.append(CapsuleFrag.from_bytes(b_cfrag))
        for cfrag in cfrags:
            capsule.attach_cfrag(cfrag)
        print("2")
        print(capsule)
        print(capsule.get_correctness_keys())
        print(cfrags)
        cleartext = pre.decrypt(ciphertext=b_ciphertext,
                                        capsule=capsule,
                                        decrypting_key=deckey)
        print("3")

        res = {"cleartext": cleartext.decode("utf-8")}
        print("\nbob_cleartext: ")
        print(cleartext)
        return jsonify(res), {'Content-Type': 'application/json'}
    return



# api.add_bytes
if __name__ == "__main__":
    app.run(host='0.0.0.0')
