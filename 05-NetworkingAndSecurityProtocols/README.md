# 1. The Internet and Socket

Before the internet, we used local networks, telephone line connections, and leased line. But the problem with leased lines is that: If A and D use the line, then B and C cannot.

![leased line](leasedline.png)

But if everyone just sends a small packet of data, they can both use the line at the same time.

![leasedline2](leasedline2.png)

## 1.1 Transmission Control Protocol

- TCP is a protocol that runs on top on IP, if an IP packet gets lost. It requests to re-sent.

- TCP/IP becomes standard and allows Inter network connections.

## 1.2 Domain Name Server (DNS)

- Remembering IP address is hard, so people associate names with addresses.
- news.bbc.com -> 212.58.226.141
- A hierarchy of servers list handle requests
- The route for most of Europe is RIPE based in Amsterdam.

> 由于记住那么多完整的IP地址很困难，所以DNS就像电话薄一样，通过输入相关名字，比如 google.com，浏览器就能直接将我们连接到其对应的IP地址。

## 1.3 Ports 端口

- To allow multiple connections TCP uses "ports"
- 一个 TCP Socket connection is defined by：dest IP, dest port, source IP, source port
- The dest port normally depends on the service: WWW runs on port 80, ssh on port 22, dns on 53...
- The source port is normally chosen at random

> Socket = (IP: port) Socket 的含义就是两个应用程序通过一个双向的通信连接实现数据的交换，连接的一段就是一个socket。实现一个socket连接通信至少需要两个sockets，一个运行在服务端（插孔），一个运行在客户端（插头）。
>
> 套接字用于描述IP地址和端口，是一个通信链的句柄。应用程序通过套接字向网络发出请求或应答网络请求。注意的是套接字既不是程序也不是协议，只是操作系统提供给通信层的一组抽象API接口。

## 1.4 Netcat

- Netcat is a tool to make Internet connections

- Syntax varies between OS. 不同的OS上使用不同语法
- listen on 1337: nc -l 1337
- connect to machine 127.0.0.1 on port 1337:
  - nc 127.0.0.1 1337

> [Netcat tutorial](https://www.freebuf.com/sectool/243115.html) in Chinese

## 1.5 Nmap

- Check if 1000 most common ports are open:
  - nmap 127.0.0.1
- Additionally send messages to ports to find out what the service is:
  - Map -A 127.0.0.1
- Scan all ports:
  - Map -p- 127.0.0.1

> 127.0.0.1 is a non-routable IP address that is defined as referring to the "local" computer. In other words, it is any computer you sit in front of right now.

## 1.6 The Internet Protocol Stack

互联网协议栈

- Internet communication uses a stack of protocols.
- Each protocol uses the protocol below it to sent data.

![internetstack](internetstack.png)

## 1.7 MAC and IP Address

- Every machine has a unique MAC address (media access control)
  - e.g. 48:d7:05:d6:7a:51
- Every computer on the Internet has an IP address
  - e.g. 147.188.193.15
- NAT address 10.\*.\*.\* and 192.168.\*.\* are not unique local address.

## 1.8 DHCP and ARP

- Dynamic Host Configuration Protocol 动态主机配置协议

  - Assigns an IP address to a new machine (MAC address). Not stored long term.

  > 用于集中对用户IP地址进行动态管理和配置

- Address Resolution Protocol (ARP) 地址解析协议

  - Lets router find out which IP address is being used by which machine.
  - ARP spoofing lets one machine steal the IP address of another on the same network.

  > 使得路由器可以找到哪台主机在用哪个IP地址

## 1.9 Wireshark

- A network protocol analyzer: It records all internet traffic, so it can then be viewed and analysed. Wireshark 是一个网络封包分析软件，可以实时从网络接口捕获数据包中的数据。
- Excellent for debugging protocols and network problems.
- See also tcpdump, which writes packets directly to disk.

> TCPDump 可以将网络中传送的数据包完全截获下来提供分析，它针对网络层、协议、主机、网络或端口的过滤。

## 1.10 Using the Stack to Send Data

![senddata](senddata.png)

从 Computer 1 发送数据到 Computer 2。首先数据经过 Transport 层，UDP 给每个数据包都添加了一个 header，其中包含发送和接收的端口，数据包的长度，以及 checksum 校验和。在 Network 层，为数据包打上 MAC 地址和 IP header，并拆分过大的数据。在 Link 层，打上该层的 header。

## 1.11 "The Attack Owns the Network"

- The Internet was not designed with security in mind
- Traffic may be monitored or altered
- All good security products assume that the attacker has complete control over the network (but can't break encryption)

# 2. Cryptographic Protocols

- Protocols in Alice and Bob notation
- Attacks on Protocols
- Forward Secrecy
- Goals and Protocols

## 2.1 A simple protocol

A sends a message m to B

`Alice -----"I'm Alice"-----> Bob`

written as: A --> B: "I'm Alice"

---

There are some rules: We write down protocols as a list of messages sent between principals, e.g.

1. A --> B: "Hello"
2. B --> A: "Offer"
3. A --> B: "Accept"

在上述的例子中`Alice -----"I'm Alice"-----> Bob`， 该信息`"I'm Alice"` 可以被攻击者读取。

就会变化成 `Alice     Elvis -----"I'm Alice"-----> Bob`

 写作 E(A) -> B: "I'm Alice"

---

`Alice -----{"I'm Alice"}Kab-----> Bob`

{_}Kab means symmetric key encryption

written as: A --> B: {"I'm Alice"}Kab

---

A --> B: {"I'm Alice"}Kab

E(A) --> B: {"I'm Alice"}Kab

- Attacker can intercept and replay messages.
- Assume the attacker "owns" the network.

## 2.2 A Nonce

Numbr that is only used once (often used in a challenge/response setting).

![nonce](nonce.png)



在第三条信息中，由于 N_a + 1 是使用和A公用的钥匙来加密的，因此B认为A肯定是想把钱转给Elvis。
