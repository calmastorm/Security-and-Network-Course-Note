# 1. Hashes, MACs and Authenticated Encryption

Now we know that symmetric encryption works if participants share a key, we also know that public key cryptography and key distribution protocols can ensure that key is shared and safe. However, **we still need to detect manipulation of ciphertext.** Fortunately, Hashes, MACs and Authenticated Encryption can address this problem.

## 1.1 Hashes

- A hash of any message is a short string generated from that message. 哈希本质上是一小串字符

- The hash of a message is always the same. 相同信息会产生相同哈希
- Any small change makes the hash totally different. 不同信息会生成完全不同的哈希
- Hash -x-> Message 从哈希破译信息非常困难

## 1.2	Uses of Hashing

- Verification of download of message
- Tying parts of a message together (hash the whole message)
- Hash the message, then sign the hash (for electronic signatures)
- Protect passwords: Store the hash instead of password

## 1.3 Attacks on hashes

- *Preimage attack* - Find a message for a given hash: very hard.
- *Collision attack* - Find two messages with the same hash.
- *Prefix collision attack* - A collision attack where the attacker can pick a prefix for the message.

## 1.4 The SHA Family of Hashes

SHA hashes are the most common and best hashes.

### 1.4.1 SHA-1 ❎

A birthday attack on SHA-1 should need 2<sup>80</sup> hash tests, but a 2<sup>63</sup> attack was found in 2005, thus it faded away.

### 1.4.2 SHA-2 ❎

Improved version of SHA-1: longer hash. It has 256 or 512 bits: also called SHA256, SHA512. Since it is from SHA-1, it has the same weakness, so cryptographers aren't happy.

### 1.4.3 The SHA-3 Competition ✅

Submissions opened on October 31, 2008. Winner was announced on October 2, 2012 as Keccak, (Daemen et al. the AES guy). And it was adopted as **NIST-standard** in 2015.

## 1.5 Merkle-Damgard Hashes (MD Hashes)



# 2. Access Control

