---
layout: post
description: RSA signatures with TPM2.0 and OpenSSL
comments: true
redirect_from:
  - /RSA%20Signatures%20with%20TPM2.0/
date: 2016-03-10
last-update: 2022-10-26
---

What I am going to show applies to any Trusted Platform Module (TPM) implementing TPM2.0 specs. However, I wrote this article after spending two days trying to use the Minnowboard MAX firmware TPM (fTPM) for something useful in real life... I hope I can save you some time and many troubles [1].

_**I would love to hear your feedback!**_

Should you come across any mistake or if you want to leave a comment, please use the GitHub Discussion at the end of the document, or the Issue tracker available [here](https://github.com/dguerri/random-tech-stuff/issues).


## Table of contents

- [RSA signatures with TPM2.0 and OpenSSL](#rsa-signatures-with-tpm20-and-openssl)
  - [The problem](#the-problem)
  - [Generating an Endorsement Key (EK)](#generating-an-endorsement-key-ek)
  - [Generate an Attestation Identity Key (AIK)](#generate-an-attestation-identity-key-aik)
  - [Signing a document](#signing-a-document)
  - [Verifying a TPM2.0 RSA signature](#verifying-a-tpm20-rsa-signature)
  - [Conclusion](#conclusion)
  - [References](#references)

---

# RSA signatures with TPM2.0 and OpenSSL

## The problem

As it turns out, [tpm2-tools](https://github.com/01org/tpm2.0-tools) (the only TPM2.0 userland tools available on Linux that I am aware of) uses an output format for cryptographic operations like signatures, public keys export, hashing, etc…, which is incompatible with OpenSSL.

This is very annoying, as you can't directly use a TPM for useful stuff if the other party can not load those TPM data structures (e.g., using a tpm2-tools).

After spending quite a bit of time on the [TPM2.0 specs](http://www.trustedcomputinggroup.org/resources/tpm_library_specification) (a reading that I would recommend to anyone with a lot of time and masochistic personality) I came up with some procedures to convert RSA public keys and signatures.

In this article, I am going to generate an RSA key that we can use to identify a particular device using a TPM that implements TPM2.0 specification. The easiest way to achieve that is using an AIK.

But, let's start from the beginning...

## Generating an Endorsement Key (EK)

Before generating a new AIK, we need to generate an EK. As I am using a newly initialized TPM, I have no password configured, so I can just issue the following command:

```shell
~$ tpm2_getpubek -H 0x81010000 -g 0x01 -f ek.pub
```

That will generate a new RSA (hex code `0x01`) key, store it in the NVRAM of the TPM with handle `0x8101000` and export the public portion in a file named `ek.pub`.

Unfortunately, we can't use this key directly for what we need to do, so let's:

## Generate an Attestation Identity Key (AIK)

Similarly to what we have done to generate the EK, we can generate an AIK:

```shell
~$ tpm2_getpubak -E 0x81010000 -k 0x81010010 -f ak.pub -n ak.name
```

RSA is the default algorithm. The AIK is defined in the endorsement hierarchy, so it needs to be generated using an EK (`0x81010000` in this case). This new key is stored in the device NVRAM with handle `0x81010010`. The public bit is exported in `ak.pub`.

`ak.name` contains the cryptographically secure name of the key. We are not going to need it for now.

`ak.pub` is a TPMT_PUBLIC structure which, among other things, contains the RSA modulus. As we generated a 2048 bits key (default), the modulus is exactly 256 bytes.

It is important to note that `ak.pub` doesn't contain the RSA exponent (actually that field is present, but it is set to 0). For RSA, TPM2.0 assumes that the exponent is always $2^{16}+1 = 65537$ ([for good reasons](http://crypto.stackexchange.com/questions/3110/impacts-of-not-using-rsa-exponent-of-65537)).

All that being said, we can convert the key to an ASN.1 DER and/or PEM format.

The DER key is then defined as `<header><modulus><mid-header><exponent>`. We can use the following commands to compute all these elements:

- Extract the modulus (removing TPMT_PUBLIC header and padding)

```shell
~$ dd if=ak.pub of=modulus.bin bs=1 skip=102 count=256
```

- Define the fixed header used by OpenSSL to identify an RSA key

```shell
~$ echo 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA' | openssl base64 -a -d > header.bin
```

- Mid-header is always `0x02 0x03` i.e., DER serialised ASN.1 to say that the exponent is a 3 bytes (`0x03`) integer (`0x02`)

```shell
~$ echo -en '\x02\x03' > mid-header.bin
```

- Exponent is always `65537` ($2^{16}+1$) as we have already seen

```shell
~$ echo -ne '\x01\x00\x01' > exponent.bin
```

- Compose the DER key

```shell
~$ cat header.bin modulus.bin mid-header.bin exponent.bin > key.der
```

- If needed, you can easily convert the DER encoded key to PEM

```shell
~$ openssl pkey -inform der -outform pem -pubin -in key.der -out key.pem
```

If you want to see how the modulus and the exponent look like, just run:

```shell
~$ openssl rsa -in key.pem -pubin -noout -text

Modulus (2048 bit):

00:c7:2d:bd:f1:88:30:01:64:6a:0c:ae:61:52:23:
[stuff...]
87:a9

Exponent:
65537 (0x10001)
```

OK. It seems legit, doesn't it?

## Signing a document

In TPM1.2 an AIK cannot be used to sign objects that are external to the TPM. TPM2.0 extends this concept: to sign an object with a primary key, we have to prove to the TPM that the object has been generated by the TPM itself. To do so, TPM2.0 uses tickets.

The following command computes the sha256 hash of a text file and generate a TPM2.0 ticket (`0x00B` tells tpm2_hash to use SHA256.):

```shell
~$ tpm2_hash -H e -g 0x00B -I message.txt -o hash.bin -t ticket.bin
```

Let's sign the hash using ticket.bin as the authorization token and the AIK with persistent handle `0x81010010`:

```shell
~$ tpm2_sign -k 0x81010010 -g 0x000B -m message.txt -s sign.bin -t ticket.bin
```

`sign.bin` contains the signature, wrapped in a `TPMU_SIGNATURE` structure.

To get something, we can use with OpenSSL, let's extract the relevant bits (i.e., the raw signature):

```shell
~$ dd if=sign.bin of=sign.raw bs=1 skip=6 count=256

```

## Verifying a TPM2.0 RSA signature

This is easy because we have already got an RSA public key that can be used by OpenSSL and a raw signature:

```shell
~$ openssl dgst -verify key.pem -keyform pem -sha256 -signature sign.raw message.txt
```

If you get:

```shell
Verified OK
```

Congratulations, it worked!

## Conclusion

This is just an example of what we can do with a TPM. In one of the next articles (if any :P) I will explain how to decrypt a message encrypted with a public key generated by the TPM.

[Go to the Home Page]({{ '/' | absolute_url }})

---

## References

[1] To create a custom version of the UEFI firmware for the MBM and enable the fTPM I suggest you to read this excellent article: [Minnowboard Max: Enable the firmware (TXE) TPM 2.0](http://prosauce.org/blog/2016/1/11/minnowboard-max-enable-and-test-the-firmware-txe-tpm-20)
