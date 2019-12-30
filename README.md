# DKMS
DKMS provides distributed KMS service and authenticated data sharing via distributed storage as well as PRE techs.

# Pre-install
1. ipfs
Ipfs is a distributed storage network. Setup a private network by configuration of swarm-keys (link: https://github.com/ipfs/go-ipfs)
2. pyUmbral lib
Install pyUmbral lib by pip(pip3) is recommended. (link: https://github.com/nucypher/pyUmbral)

# RUN DKMS
RUN restful.py as backend service, then test the following APIs. (In fact, this repo provides various keygen algorithms, and the re-encryption phase can be ignored by simple enc/dec phases. Enhanced key management as well as updating are TODO)
1. KeyGen
POST /keygen { "type": "ECC", "account": "za", "role": "sender" or "receiver" }
2. Encrypt
POST /encrypt { "account":"za", "plaintext": "Why do we have to work on Monday?", "public_key": "038651bf113e8c426867e08623aebd9d6c3e92d59ca7e6e84e04eff213e4e0fdc3" }
3. Kfrag_Gen
POST /kfraggen { "account":"za", "delegatekey": "2c4327c627b261cb3732a496a852d9d53a9eececf5900e792501dbc44e43840f", "signersk": "2959b1718bd71bc36c2204def560b7a1708e74a6020410710ea191513928a291", "publickey": "028aaf62c8ae81054ebff5c70150a7a0cc0da43e1cec193f58da0929e62acfd584", "threshold": 3, "N": 5 }
4. Re-encrypt
POST /reencrypt { "account":"za", "addresses": [ "QmdVj3LyMPyVHcJ3886HFs594kQsGbBcZG84qneNnhpuR7", "QmW5SLEA7Cj7mhhmgVSjpa5X1LFxjmhR3zMu3oBbpjWak4", "QmZcaBJhNALcxmDPcAozP24vg88iKEHXkBpmBV8tNK3fDd" ], "capsule": "QmYsX5L2xpPSpCm7uLtnmLsW8DonzPUPUq1RJQzeTrv214", "delegating":"038651bf113e8c426867e08623aebd9d6c3e92d59ca7e6e84e04eff213e4e0fdc3", "receiving":"028aaf62c8ae81054ebff5c70150a7a0cc0da43e1cec193f58da0929e62acfd584", "verifying":"03291282cfefb940505aa8edb17046c5accfb9f8ca480fec1467835287ddf3c152", "threshold": 3 }
5. Fetch
POST /fetch { "account":"za", "capsule": "QmQgn1x3CQTBwzEXFYab6AYXH2XKKszmigt5CXgenPtZCg", "addresses": [ "QmTGF5YVxbSdmWhRxt8rDbKz3oX7DC7eQdGsaeF4g3BpoJ", "QmXuisb2meM4c2Ym3yAqSYFq9dMxS1szJoNk8SQPxRKizE", "QmdF7pvBMdHxJJmRgjiVm7gGg9cQtpDEwCVmD58Vhp3wVs" ] }
6. Decrypt
POST /decrypt { "account":"za", "capsule": "QmVUJDyNpyG8CXGFzKq28D6sPPm9gRAnFtwTTFRmEX4xtj", "ciphertext":"3e2a157a015349b5c1986105e115f7b43d1b87a4427bb43d6a589c417959eafda678adb6dc6fe98d5fb67b3eef3861c5ec04cf8485da368c3f2c1ab02b", "decryptkey":"ac391782c1e4ead3d5646bb7c343b7a52fd7b486d6e578765da2f94a70f81774" }

Based on thus backend service, we will soon provide an application that adopt DKMS to secure data sharing (TODO).
