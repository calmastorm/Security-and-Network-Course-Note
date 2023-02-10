# Public-Key Cryptography

## 1. Intro

**Cryptohraphy has four directions**

1. Confidentiality 保密性

2. Message Integrity 消息完整性

3. Sender Authentication 发送人认证

4. (Soft) Sender Undeniability (non-repudiation) 发件人不可否认性

**Kerckhoffs' Principle**

- A cryptographic system should be secure even if everything about the system, except the key, is public knowledge.
- Modern Applications demand even Tamper-Resistance. 防篡改

### 1.1 Symmetric Key Cryptography

This means the keys for encryption and decryption are identical. 

**But there is a problem**: each pair of people who transfer data needs a separate key.

If there are 1000 people, 1000*(999)/2 = 499500 keys are needed.

If we use public and private key, then there are only 2000 keys are needed in total.

### 1.2 Reduce Keys number

- Each person has two keys: one **public** and one **private**
- They keys are asymmetric: **related but not identical**
- Public Key is known to everyone, private key is kept secret

![public key encryption](pke.png)

Take home: Encryption using **receiver's public key**, decryption using **receiver's private key**.

### 1.3 Public Key authentication: Signatures

![pka-sig](pka-sig.png)

### 1.4 Public Key Infrastructure

![pki](pki.png)

## 2. Secure Key Exchange

Now, Alice and Bobx need to agree on a secret key. But how?

**MultiRound Solution**

Public parameter: two sided lock box

![multisound solution](multi-sol.png)

### **2.1 Diffie Hellman Key Exchange**

Parameters: Choose a prime *p* and a number *g < p* such that *gcd(g, p-1) = 1*

比如：*p = 19*, *g = 18*, *19* 和 *18-1 = 17* 的最大公约数为 *1*

Assumption: There is no polynomial time algorithm to compute *g<sup>ab</sup> mod p* from *g<sup>a</sup> mod p* and *g<sup>b</sup> mod p*.

[Secret Key Exchange (Diffie-Hellman) - Computerphile from YouTube](https://www.youtube.com/watch?v=NmM9HA2MQGI)

[Diffie Hellman -the Mathematics bit- Computerphile from YouTube](https://www.youtube.com/watch?v=Yjrfm_oRO0w)

![Diffie Hellman Key Exchange](dhke.png)

### **2.2 Man-in-the-Middle Attack**

MITM attack is a general term for when a perpetrator positions himself in conversation between a user and an application (or another user) -- either to eavesdrop(窃听) or to impersonate(扮演) one of the parties, making it appear as if a normal exchange of information is underway.

**How to solve?**

Basic idea: Authenticating Public Key

Requirement: Trusted Thrid Party: Certification Authority (CA).

## 3. RSA Encryption

RSA Encryption is the most popular function in public key cryptography.

Widely used in internet protocol like TLS, PKI.

### 3.1 Textbook RSA scheme

被称为裸加密

Three Algorithms (Gen, Enc, Dec)

- **Gen**: on input a <u>security parameter 𝜆</u>.

  Generate two distinct primes 𝑝 and 𝑞 of same bit-size 𝜆

  Compute 𝑁 = 𝑝𝑞 and 𝜙(𝑁) = ( 𝑝 − 1 )( 𝑞 − 1 )

  Choose at random an integer 𝑒 (1 < 𝑒 < 𝜙(𝑁)) such that gcd( 𝑒, 𝜙(𝑁) ) = 1

  Let ℤ<sub>N</sub><sup>*</sup>= {x | 0 < x <N and gcd(x, N)=1}

  Compute 𝑑 such that 𝑒 · 𝑑 ≡ 1 ( 𝑚𝑜𝑑 𝜙(𝑁) )

  Public key 𝑃𝐾 = (𝑒, 𝑁).   The private key 𝑆𝐾 = 𝑒, 𝑑, 𝑁

  **Example**:

  ![eg-gen](eg-gen.png)

- **Enc(PK, m)**: On input an element 𝑚 ∈ ℤ<sub>N</sub><sup>*</sup> and the public key 𝑃𝐾 = ( 𝑒, 𝑁 ) compute

  𝑐=𝑚<sup>e</sup> (𝑚𝑜𝑑 𝑁)

- **Dec(SK, c)**: On input an element 𝑐 ∈ ℤ<sub>N</sub><sup>*</sup> and the private key S𝐾 = (𝑒, 𝑑, 𝑁) compute

  𝑚=𝑐<sup>d</sup> (𝑚𝑜𝑑𝑁)

  **Examples:**

  ![eg-encdec](eg-encdec.png)

## 4. Digital Signatures

**Objectives**

1. Features of hand-written signatures in Digital World 手写签名在数据世界的特征
2. Ensure hardness of forgery 确保难以被伪造

> Explanation: When I want to send you something, I want to prove that it was me that sent it. To do that, I am going to use my private key to sign a digital signature. On your side, you are going to verify that signature, and verify that it was actually me that encrypted it.

### 4.1 Hand-written Signatures

- **Function**: bind a statement/message to its authors.
- Verification is public. (Against a prior authenticated one)

- **Properties**:
  - Correctness: A correct signature should always be verified true.
  - Security: Hard to forge.

[What are Digital Signatures? - Computerphile from YouTube](https://www.youtube.com/watch?v=s22eJ1eVLTU)

### 4.2 Signature Schemes

![Correctness](correctness.png)

![Unforgeability](unforgeability.png)

> Gen -> 生成了公钥和私钥。
>
> Sign -> 使用明文（文件/数据）生成 &alpha; (这是什么？)。
>
> Verify -> 使用明文和x（这是什么？）进行验证，如果该消息未请求签名，则视为伪造。

### 4.3 Signature Scheme Designs: RSA Full Domain Hash

- **Public Functions** A hash function H : {0, 1}<sup>\*</sup> --> Z<sub>N</sub><sup>*</sup>

- **Keygen** Run RSA.Keygen. *pk = (e, N), sk = (d, N).*
- **Sign** **Input** *sk, M.* **Output** *σ = RSA.Dec(sk, H(M)) = H(M)<sup>d</sup> mod N*

- **Verify** **Input** *pk,M,σ. If RSA.Enc(pk, σ) = H(M)* **Output** accept, else reject

- if σ<sup>e</sup> mod N = H(M), **output** accept, else reject.

> A hash function takes strings of arbitrary length as input and produces a fixed length output. For cryptographic hash functions, given a *z*, it is very expensive to find x such that *H(x) = z*.
> 哈希函数无论输入的字符串有多长，它的输出都一样长，因此难以根据输出破解输入。

## 5. Public-Key Cryptography in Practice

**Saving a Key**

Can we read and write the bytes of a key to a file? This is a bad idea.

We want to

1. protect read access to private keys
2. make sure the publics ones are read

### 5.1 KeyStores and Java keytool

- `KeyStore` provides password protected storage for keys.
- Most Java programs use existing keys rather than create keys themselves.
- The keytool command can be used to generate keys outside Java.

**KeyStore**

A `KeyStore` holds password protected private keys and public keys as certificates.

```
// Make keystores using the keytool e.g.
keytool -genkey -keyalg RSA
				-keypass password  -alias mykey
				-storepass storepass
				-keystore myKeyStore
```

