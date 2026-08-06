# Network Protocol Reversing and Penetration Testing

This reference covers reverse-engineering of network protocols, client-server communications, and authorized penetration testing against whitelisted network addresses. All activities assume explicit authorization, local lab environments, or sanctioned bug-bounty scope.

## Scope and Preconditions

This skill applies when the user mentions:
- Network protocols (TCP, UDP, HTTP, WebSocket, gRPC, custom binary protocols)
- Packet capture (pcap, pcapng, tcpdump, Wireshark)
- Client-server communication analysis
- API endpoint discovery and fuzzing
- Authentication/authorization bypass testing
- Encryption/crypto analysis in network traffic
- Whitelisted IP ranges or domains for testing
- Man-in-the-middle (MITM) testing in authorized labs

**Mandatory precondition:** The user must confirm they have explicit authorization to test the target network addresses. Treat any mention of "whitelist" as an indicator of authorized scope, but still log the assumption explicitly in the case notes.

## Workflow Integration

Network protocol reversing fits into the main workflow as follows:

1. **Intake**: Identify client binary, server endpoint, or packet capture. Record network environment (IP, port, protocol).
2. **Analysis**: Extract strings, endpoints, headers, and serialization patterns from client binaries or PCAPs.
3. **Reverse**: Recover protocol structure, message formats, state machines, and crypto mechanisms.
4. **Deep Reverse**: Build a protocol specification, map trust boundaries, identify injection points.
5. **Vulnerability Review**: Test for authentication bypass, authorization flaws, injection, replay, and crypto weaknesses.
6. **Delivery**: Produce a protocol reverse-engineering report and/or penetration test findings.

## Core Techniques

### Passive Traffic Analysis

1. Capture traffic between client and server using `tcpdump`, `Wireshark`, or `mitmproxy`.
2. Identify message boundaries: length prefixes, delimiters, fixed-size headers, magic bytes.
3. Map request-response pairs and state transitions.
4. Extract plaintext fields, flags, sequence numbers, timestamps, session IDs.
5. Identify encryption via entropy analysis (high entropy payloads) or TLS/SSL detection.

### Active Protocol Probing

1. Replay captured messages with modifications to observe server responses.
2. Fuzz length fields, type fields, sequence numbers, and checksums.
3. Test boundary conditions: out-of-range values, negative lengths, missing fields.
4. Inject unexpected messages to test state-machine robustness.
5. Test authentication bypass: replay tokens, manipulate session IDs, force downgrades.

### Client Binary Analysis

1. Locate network-related functions: `socket`, `connect`, `send`, `recv`, `SSL_read`, `SSL_write`.
2. Extract hardcoded endpoints, fallback domains, and API keys.
3. Identify serialization libraries (Protobuf, FlatBuffers, MessagePack, JSON, XML).
4. Trace data flow from user input to wire format.
5. Locate certificate pinning logic and bypass in lab environments.

### Crypto Analysis (Local Only)

1. Identify encryption libraries: OpenSSL, BoringSSL, libsodium, custom crypto.
2. Extract static keys, IVs, or seed values from client binaries.
3. Identify weak crypto: ECB mode, custom block ciphers, hardcoded passwords.
4. Test for reusing nonces/IVs across sessions.
5. Document the key derivation path and storage mechanism.

## Tool Selection by Phase

| Phase | Recommended Tools | Purpose |
|---|---|---|
| Passive capture | Wireshark, tcpdump, tshark | Packet capture and analysis |
| MITM testing | mitmproxy, Burp Suite, Echo Mirage | Intercept and modify traffic |
| Binary client analysis | Ghidra, radare2, Frida | Extract endpoints, crypto, serialization |
| Protocol fuzzing | boofuzz, Peach Fuzzer, AFL++ | Fuzz protocol fields |
| Replay/Modification | Scapy, Python sockets, netcat | Craft and send custom messages |
| Crypto analysis | CyberChef, Python cryptography libs | Decode, decrypt, identify algorithms |

## Safe Practices for Network Testing

1. **Authorization**: Confirm explicit written authorization before any active testing.
2. **Scope restriction**: Test only the specified IP ranges, domains, and ports.
3. **Rate limiting**: Use conservative request rates to avoid denial-of-service.
4. **Data handling**: Redact sensitive data from logs and reports (passwords, PII).
5. **No production impact**: Prefer test environments; if production is the only option, use read-only probes where possible.
6. **Documentation**: Record all commands, timestamps, and responses.
7. **Rollback**: Restore any modified client state after testing.
