## Cryptography

- Cryptography describes how to transfer messages between participants without anyone else being able to read or modify them. (加密交流)
- Prerequisite for Computer Security.
- Before we start with Cryptography, we need to look at how to represent data.

## Codes vs. Ciphers

A **code** is any way to represent data, it will use bit strings (sequence of bits) to represent data.

- i.e. Morse Code, ASCII, Hex, Base64

A **cipher** is a code where it is difficult to derive data from code.

- Always uses a key.
- Data for a cipher usually called *plain text*, encoding called *cipher text*.
- **Encryption**: plain text --> cipher text
- **Decryption**: cipher text --> plain text



**Question** What is "27" encoded in binary?

| Binary              | Base          |
| ------------------- | ------------- |
| 0001 1011           | 27 as decimal |
| 0010 0111           | 27 as hex     |
| 110110 111011       | 27 as Base64  |
| 0011 0010 0011 0111 | 27 as ASCII   |

**Hex**

* Characters 0 to F encode 4 bits
* Easiest way to write down binary as text

**ASCII**

[ASCII table official website](https://www.asciitable.com/)

**Base64**

- Shortest way to write binary as printable characters
- Common for keys and crypto
- This module will use Hex

### Caesar Cipher

- CC replaces each letter of the alphbet with one three to the right, i.e.
  - a --> d
  - b --> e
  - z --> c

### Using a Key

These ciphers are easy to break because as soon as you know the scheme you can decrypt the message.

**Kerckhoffs's principle**: A cipher should be secure even if the attackers knows everything about it apart from the key.

- i.e. Caesar cipher using n rotations.

- But only 26 possible keys so you can just try them all (w/o key is 26 times harder than w/ it).

- Better scheme replaces each letter with another letter (26! ~= 4 * 10^26 possible keys).

### Frequency Analysis

Frequency analysis counts the number of times

- each symbol occurs
- each pair of symbols

...and tries to draw conclusions from this.



## Symmetric Cryptography

- Proper encryption schemes
- Assumption: All participants share common secret key (problematic!)
- Most important encryption scheme and possible attacks against them
- Modular arithmetic