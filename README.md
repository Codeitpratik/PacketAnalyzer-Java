# DPI Engine - Deep Packet Inspection System


This document explains **everything** about this project - from basic networking concepts to the complete code architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)
12. [Extending the Project](#12-extending-the-project)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?** 
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we should block all of them
- This is how we "track" conversations between computers

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first packet!

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │             │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

### Two Versions

| Version | File | Use Case |
|---------|------|----------|
| Simple (Single-threaded) | `MainWorking.java` | Learning, small captures |
| Multi-threaded | `DpiMt.java` | Production, large captures |

---

## 4. File Structure

```text
packet_analyzer/
├── src/
│   └── main/
│       └── java/
│           └── packetanalyzer/
│               ├── PcapReader.java          # PCAP file reading
│               ├── PacketParser.java        # Network protocol parsing
│               ├── SniExtractor.java        # TLS/HTTP inspection
│               ├── Types.java               # Data structures and app types
│               ├── RuleManager.java         # Blocking rules
│               ├── ConnectionTracker.java  # Flow tracking
│               ├── LoadBalancer.java        # Load balancer worker
│               ├── FastPathProcessor.java   # Fast-path worker
│               ├── ThreadSafeQueue.java     # Thread-safe queue
│               ├── DpiEngine.java           # Main orchestrator
│               ├── MainWorking.java         # ★ SIMPLE VERSION ★
│               └── DpiMt.java               # ★ MULTI-THREADED VERSION ★
│
├── generate_test_pcap.py      # Creates test data
├── test_dpi.pcap              # Sample capture with various traffic
├── output.pcap                # Processed capture
├── packet-analyzer-1.0.0.jar  # Packaged Java application
├── pom.xml                    # Maven build configuration
├── WINDOWS_SETUP.md           # Windows setup
└── README.md                  # This file!
```

---

## 5. The Journey of a Packet (Simple Version)

Let's trace a single packet through `MainWorking.java`:

### Step 1: Read PCAP File

```java
PcapReader reader = new PcapReader();
reader.open("capture.pcap");
```

**What happens:**
1. Open the file in binary mode
2. Read the 24-byte global header (magic number, version, etc.)
3. Verify it's a valid PCAP file

**PCAP File Format:**
```
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← Read once at start
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← Timestamp, length
│ Packet Data (variable)     │  ← Actual network bytes
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
├────────────────────────────┤
│ ... more packets ...       │
└────────────────────────────┘
```

### Step 2: Read Each Packet

```java
while (reader.readNextPacket(raw)) {
    // raw.data contains the packet bytes
    // raw.javaeader contains timestamp and length
}
```

**What happens:**
1. Read 16-byte packet header
2. Read N bytes of packet data (N = header.incl_len)
3. Return false when no more packets

### Step 3: Parse Protocol Headers

```java
PacketParser.parse(raw, parsed);
```

**What happens (in PacketParser.java):**

```
raw.data bytes:
[0-13]   Ethernet Header
[14-33]  IP Header  
[34-53]  TCP Header
[54+]    Payload

After parsing:
parsed.src_mac  = "00:11:22:33:44:55"
parsed.dest_mac = "aa:bb:cc:dd:ee:ff"
parsed.srcIp   = "192.168.1.100"
parsed.dest_ip  = "172.217.14.206"
parsed.srcPort = 54321
parsed.dest_port = 443
parsed.protocol = 6 (TCP)
parsed.javaas_tcp  = true
```

**Parsing the Ethernet Header (14 bytes):**
```
Bytes 0-5:   Destination MAC
Bytes 6-11:  Source MAC
Bytes 12-13: EtherType (0x0800 = IPv4)
```

**Parsing the IP Header (20+ bytes):**
```
Byte 0:      Version (4 bits) + Header Length (4 bits)
Byte 8:      TTL (Time To Live)
Byte 9:      Protocol (6=TCP, 17=UDP)
Bytes 12-15: Source IP
Bytes 16-19: Destination IP
```

**Parsing the TCP Header (20+ bytes):**
```
Bytes 0-1:   Source Port
Bytes 2-3:   Destination Port
Bytes 4-7:   Sequence Number
Bytes 8-11:  Acknowledgment Number
Byte 12:     Data Offset (header length)
Byte 13:     Flags (SYN, ACK, FIN, etc.)
```

### Step 4: Create Five-Tuple and Look Up Flow

```java
Types.FiveTuple tuple = new Types.FiveTuple();
tuple.srcIp = parseIp(parsed.srcIp);
tuple.dstIp = parseIp(parsed.dstIp);
tuple.srcPort = parsed.srcPort;
tuple.dstPort = parsed.dstPort;
tuple.protocol = parsed.protocol;

Flow flow = flows.computeIfAbsent(tuple, k -> new Flow());
```

**What happens:**
- The flow table is a hash map: `FiveTuple → Flow`
- If this 5-tuple exists, we get the existing flow
- If not, a new flow is created
- All packets with the same 5-tuple share the same flow

### Step 5: Extract SNI (Deep Packet Inspection)

```java
// For HTTPS traffic (port 443)
if (pkt.tuple.dstPort == 443 && pkt.payloadLength > 5) {
    Optional<String> sni = SniExtractor.extract(payload, payloadLength);
    if (sni.isPresent()) {
        flow.sni = sni.get();                 // "www.youtube.com"
        flow.appType = Types.sniToAppType(sni.get()); // AppType.YOUTUBE
    }
}
```

**What happens (in SniExtractor.java):**

1. **Check if it's a TLS Client Hello:**
   ```
   Byte 0: Content Type = 0x16 (Handshake) ✓
   Byte 5: Handshake Type = 0x01 (Client Hello) ✓
   ```

2. **Navigate to Extensions:**
   ```
   Skip: Version, Random, Session ID, Cipher Suites, Compression
   ```

3. **Find SNI Extension (type 0x0000):**
   ```
   Extension Type: 0x0000 (SNI)
   Extension Length: N
   SNI List Length: M
   SNI Type: 0x00 (hostname)
   SNI Length: L
   SNI Value: "www.youtube.com"  ← FOUND!
   ```

4. **Map SNI to App Type:**
   ```java
   // In Types.java
   if (sni.contains("youtube") != -1) {
       return AppType.YOUTUBE;
   }
   ```

### Step 6: Check Blocking Rules

```java
if (rules.isBlocked(tuple.srcIp, flow.appType, flow.sni)) {
    flow.blocked = true;
}
```

**What happens:**
```java
// Check IP blacklist
if (blockedIps.contains(srcIp)) return true;

// Check app blacklist
if (blockedApps.contains(app)) return true;

// Check domain blacklist (substring match)
for (String dom : blockedDomains) {
    if (sni.contains(dom)) return true;
}

return false;
```

### Step 7: Forward or Drop

```java
if (flow.blocked) {
    dropped++;
    // Don't write to output
} else {
    forwarded++;
    // Write packet to output file
    output.write(packetHeader);
    output.write(packetData);
}
```

### Step 8: Generate Report

After processing all packets:
```java
// Count apps
for (var entry : flows.entrySet()) {
    var tuple = entry.getKey();
    var flow = entry.getValue();
    appStats.merge(flow.appType, 1, Integer.sum);
}

// Print report
"YouTube: 150 packets (15%)"
"Facebook: 80 packets (8%)"
...
```

---

## 6. The Journey of a Packet (Multi-threaded Version)

The multi-threaded version (`DpiMt.java`) adds **parallelism** for high performance:

### Architecture Overview

```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      hash(5-tuple) % 2      │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread     │           │  LB1 Thread     │
    │  (Load Balancer)│           │  (Load Balancer)│
    └────────┬────────┘           └────────┬────────┘
             │                             │
      ┌──────┴──────┐               ┌──────┴──────┐
      │hash % 2     │               │hash % 2     │
      ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
│(Fast Path)│ │(Fast Path)│   │(Fast Path)│ │(Fast Path)│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
      │            │              │            │
      └────────────┴──────────────┴────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Output Queue        │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Output Writer Thread │
              │  (writes to PCAP)     │
              └───────────────────────┘
```

### Why This Design?

1. **Load Balancers (LBs):** Distribute work across FPs
2. **Fast Paths (FPs):** Do the actual DPI processing
3. **Consistent Hashing:** Same 5-tuple always goes to same FP

**Why consistent hashing matters:**
```
Connection: 192.168.1.100:54321 → 142.250.185.206:443

Packet 1 (SYN):         hash → FP2
Packet 2 (SYN-ACK):     hash → FP2  (same FP!)
Packet 3 (Client Hello): hash → FP2  (same FP!)
Packet 4 (Data):        hash → FP2  (same FP!)

All packets of this connection go to FP2.
FP2 can track the flow state correctly.
```

### Detailed Flow

#### Step 1: Reader Thread

```java
// Main thread reads PCAP
while (reader.readNextPacket(raw)) {
    Packet pkt = createPacket(raw);

    // Hash to select Load Balancer
    int lbIdx = Math.floorMod(pkt.tuple.javaashCode(), numLbs);

    // Push to LB's queue
    lbs.get(lbIdx).queue().push(pkt);
}
```

#### Step 2: Load Balancer Thread

```java
void run() throws InterruptedException {
    while (running) {
        // Pop from my input queue
        Packet pkt = inputQueue.pop();

        // Hash to select Fast Path
        int fpIdx = Math.floorMod(pkt.tuple.javaashCode(), numFps);

        // Push to FP's queue
        fps.get(fpIdx).queue().push(pkt);
    }
}
```

#### Step 3: Fast Path Thread

```java
void run() throws InterruptedException {
    while (running) {
        // Pop from my input queue
        Packet pkt = inputQueue.pop();

        // Look up flow (each FP has its own flow table)
        Flow flow = flows.computeIfAbsent(pkt.tuple, k -> new Flow());

        // Classify (SNI extraction)
        classifyFlow(pkt, flow);

        // Check rules
        if (rules.isBlocked(pkt.tuple.srcIp, flow.appType, flow.sni)) {
            stats.dropped++;
        } else {
            // Forward: push to output queue
            outputQueue.push(pkt);
        }
    }
}
```

#### Step 4: Output Writer Thread

```java
void outputThread() throws InterruptedException {
    while (running || outputQueue.size() > 0) {
        Packet pkt = outputQueue.pop();

        // Write to output file
        outputFile.write(pkt.javaeader);
        outputFile.write(pkt.data);
    }
}
```

### Thread-Safe Queue

The Java implementation uses `BlockingQueue` so producers and consumers can safely exchange packets between worker threads:

```java
class ThreadSafeQueue<T> {
    private final BlockingQueue<T> queue =
            new ArrayBlockingQueue<>(capacity);

    void push(T item) throws InterruptedException {
        queue.put(item);
    }

    T pop() throws InterruptedException {
        return queue.take();
    }
}
```

**How it works:**
- `push()`: Producer adds item, signals waiting consumers
- `pop()`: Consumer waits until item available, then takes it
- `BlockingQueue`: Provides thread-safe access between producers and consumers
- `put()` / `take()`: Efficiently wait for space or available packets without busy-looping

---

## 7. Deep Dive: Each Component

### PcapReader.java

**Purpose:** Read network captures saved by Wireshark

**Key structures:**
```java
static class PcapGlobalHeader {
    long magicNumber;   // 0xa1b2c3d4 identifies PCAP
    int versionMajor;   // Usually 2
    int versionMinor;   // Usually 4
    long snaplen;       // Max packet size captured
    long network;       // 1 = Ethernet
}

static class PcapPacketHeader {
    long tsSec;         // Timestamp (seconds)
    long tsUsec;        // Timestamp (microseconds)
    long inclLen;       // Bytes saved in file
    long origLen;       // Original packet size
}
```

**Key functions:**
- `open(filename)`: Open PCAP and validate the header
- `readNextPacket(raw)`: Read the next packet into a byte buffer
- `close()`: Release the file resource

### PacketParser.java

**Purpose:** Extract protocol fields from raw bytes

**Key function:**
```java
boolean parse(RawPacket raw, ParsedPacket parsed) {
    parseEthernet(raw.data(), parsed);  // Extract MACs, EtherType
    parseIPv4(raw.data(), parsed);      // Extract IPs, protocol, TTL

    if (parsed.protocol() == 6) {
        parseTCP(raw.data(), parsed);   // Extract ports, flags, sequence numbers
    } else if (parsed.protocol() == 17) {
        parseUDP(raw.data(), parsed);   // Extract ports
    }

    return true;
}
```

**Important concepts:**

*Network Byte Order:* Network protocols use big-endian (most significant byte first). Java can read these values directly using `ByteBuffer` configured for big-endian order:
```java
ByteBuffer buffer = ByteBuffer.wrap(data)
        .order(ByteOrder.BIG_ENDIAN);

int port = Short.toUnsignedInt(buffer.getShort(offset));
long seq = Integer.toUnsignedLong(buffer.getInt(offset));
```

### SniExtractor.java

**Purpose:** Extract domain names from TLS and HTTP

**For TLS (HTTPS):**
```java
Optional<String> extract(byte[] payload, int length) {
    // 1. Verify TLS record header
    // 2. Verify Client Hello handshake
    // 3. Skip to extensions
    // 4. Find SNI extension (type 0x0000)
    // 5. Extract hostname string
}
```

**For HTTP:**
```java
Optional<String> extractHttpHost(byte[] payload, int length) {
    // 1. Verify HTTP request (GET, POST, etc.)
    // 2. Search for "Host: " header
    // 3. Extract value until newline
}
```

### Types.java

**Purpose:** Define data structures used throughout

**FiveTuple:**
```java
static class FiveTuple {
    long srcIp;
    long dstIp;
    int srcPort;
    int dstPort;
    byte protocol;

    @Override
    public boolean equals(Object other) {
        // Compare all five fields
        return true;
    }
}
```

**AppType:**
```java
enum AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    GOOGLE,
    YOUTUBE,
    FACEBOOK,
    // ... more apps
}
```

**sniToAppType function:**
```java
AppType sniToAppType(String sni) {
    String value = sni.toLowerCase(Locale.ROOT);

    if (value.contains("youtube"))
        return AppType.YOUTUBE;

    if (value.contains("facebook"))
        return AppType.FACEBOOK;

    // ... more patterns
    return AppType.UNKNOWN;
}
```

---

## 8. How SNI Extraction Works

### The TLS Handshake

When you visit `https://www.youtube.com`:

```
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ ──── Client Hello ─────────────────────►│
     │      (includes SNI: www.youtube.com)    │
     │                                         │
     │ ◄─── Server Hello ───────────────────── │
     │      (includes certificate)             │
     │                                         │
     │ ──── Key Exchange ─────────────────────►│
     │                                         │
     │ ◄═══ Encrypted Data ══════════════════► │
     │      (from here on, everything is       │
     │       encrypted - we can't see it)      │
```

**We can only extract SNI from the Client Hello!**

### TLS Client Hello Structure

```
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  Version = 0x0301 (TLS 1.0)
Bytes 3-4:  Record Length

-- Handshake Layer --
Byte 5:     Handshake Type = 0x01 (Client Hello)
Bytes 6-8:  Handshake Length

-- Client Hello Body --
Bytes 9-10:  Client Version
Bytes 11-42: Random (32 bytes)
Byte 43:     Session ID Length (N)
Bytes 44 to 44+N: Session ID
... Cipher Suites ...
... Compression Methods ...

-- Extensions --
Bytes X-X+1: Extensions Length
For each extension:
    Bytes: Extension Type (2)
    Bytes: Extension Length (2)
    Bytes: Extension Data

-- SNI Extension (Type 0x0000) --
Extension Type: 0x0000
Extension Length: L
  SNI List Length: M
  SNI Type: 0x00 (hostname)
  SNI Length: K
  SNI Value: "www.youtube.com" ← THE GOAL!
```

### Our Extraction Code (Simplified)

```java
Optional<String> extract(byte[] payload, int length) {
    // Check TLS record header
    if (length < 6 || (payload[0] & 0xFF) != 0x16) {
        return Optional.empty();  // Not a TLS handshake
    }

    if ((payload[5] & 0xFF) != 0x01) {
        return Optional.empty();  // Not Client Hello
    }

    int offset = 43;  // Skip to session ID

    // Skip Session ID
    int sessionLen = Byte.toUnsignedInt(payload[offset]);
    offset += 1 + sessionLen;

    // Skip Cipher Suites
    int cipherLen = readUint16BE(payload, offset);
    offset += 2 + cipherLen;

    // Skip Compression Methods
    int compressionLen = Byte.toUnsignedInt(payload[offset]);
    offset += 1 + compressionLen;

    // Read Extensions Length
    int extensionsLen = readUint16BE(payload, offset);
    offset += 2;

    // Search for SNI extension
    int extensionsEnd = offset + extensionsLen;

    while (offset + 4 <= extensionsEnd) {
        int extensionType = readUint16BE(payload, offset);
        int extensionDataLen = readUint16BE(payload, offset + 2);
        offset += 4;

        if (extensionType == 0x0000) {
            // Parse SNI structure
            int sniLength = readUint16BE(payload, offset + 3);

            return Optional.of(
                new String(
                    payload,
                    offset + 5,
                    sniLength,
                    StandardCharsets.US_ASCII
                )
            );
        }

        offset += extensionDataLen;
    }

    return Optional.empty();  // SNI not found
}
```

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|----------------|
| IP | `192.168.1.50` | All traffic from this source |
| App | `YouTube` | All YouTube connections |
| Domain | `tiktok` | Any SNI containing "tiktok" |

### The Blocking Flow

```
Packet arrives
      │
      ▼
┌─────────────────────────────────┐
│ Is source IP in blocked list?  │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is app type in blocked list?   │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Does SNI match blocked domain? │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
            FORWARD
```

### Flow-Based Blocking

**Important:** We block at the *flow* level, not packet level.

```
Connection to YouTube:
  Packet 1 (SYN)           → No SNI yet, FORWARD
  Packet 2 (SYN-ACK)       → No SNI yet, FORWARD  
  Packet 3 (ACK)           → No SNI yet, FORWARD
  Packet 4 (Client Hello)  → SNI: www.youtube.com
                           → App: YOUTUBE (blocked!)
                           → Mark flow as BLOCKED
                           → DROP this packet
  Packet 5 (Data)          → Flow is BLOCKED → DROP
  Packet 6 (Data)          → Flow is BLOCKED → DROP
  ...all subsequent packets → DROP
```

**Why this approach?**
- We can't identify the app until we see the Client Hello
- Once identified, we block all future packets of that flow
- The connection will fail/timeout on the client

---

## 10. Building and Running

### Prerequisites

- **Windows, macOS, or Linux**
- **Java 17 or newer**
- **Maven 3.8+** (recommended for building)
- Python 3.x for generating the sample PCAP data
- No native libraries are required for the Java application

### Build Commands

**Maven build:**
```bash
mvn clean package
```

**Direct Java compilation:**
```bash
javac -encoding UTF-8 -source 17 -target 17 -d target/classes src/main/java/packetanalyzer/*.java
```

**Create the executable JAR:**
```bash
jar cfe packet-analyzer-1.0.0.jar packetanalyzer.Main -C target/classes .
```

### Running

**Basic usage:**
```bash
java -jar packet-analyzer-1.0.0.jar test_dpi.pcap output.pcap
```

**With blocking:**
```bash
java -jar packet-analyzer-1.0.0.jar test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

**Configure threads (multi-threaded only):**
```bash
java -jar packet-analyzer-1.0.0.jar input.pcap output.pcap --lbs 4 --fps 4
# Creates 4 LB workers × 4 FP workers = 16 processing workers
```

### Creating Test Data

```bash
python generate_test_pcap.py
# Creates test_dpi.pcap with sample traffic
```

---

## 11. Understanding the Output

### Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                 ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4        ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

[Reader] Processing packets...
[Reader] Done reading 77 packets

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                              ║
║ Total Bytes:                5738                              ║
║ TCP Packets:                  73                              ║
║ UDP Packets:                   4                              ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                    69                              ║
║ Dropped:                       8                              ║
╠══════════════════════════════════════════════════════════════╣
║ THREAD STATISTICS                                             ║
║   LB0 dispatched:             53                              ║
║   LB1 dispatched:             24                              ║
║   FP0 processed:              53                              ║
║   FP1 processed:               0                              ║
║   FP2 processed:               0                              ║
║   FP3 processed:              24                              ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########                     ║
║ Unknown              16  20.8% ####                           ║
║ YouTube               4   5.2% # (BLOCKED)                    ║
║ DNS                   4   5.2% #                              ║
║ Facebook              3   3.9%                                ║
║ ...                                                           ║
╚══════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - www.youtube.com . YouTube
  - www.facebook.com . Facebook
  - www.google.com . Google
  - github.com . GitHub
  ...
```

### What Each Section Means

| Section | Meaning |
|---------|---------|
| Configuration | Number of threads created |
| Rules | Which blocking rules are active |
| Total Packets | Packets read from input file |
| Forwarded | Packets written to output file |
| Dropped | Packets blocked (not written) |
| Thread Statistics | Work distribution across threads |
| Application Breakdown | Traffic classification results |
| Detected SNIs | Actual domain names found |

---

## 12. Extending the Project

### Ideas for Improvement

1. **Add More App Signatures**
   ```java
   // In Types.java
   if (sni.contains("twitch") != -1)
       return AppType.TWITCH;
   ```

2. **Add Bandwidth Throttling**
   ```java
   // Instead of DROP, delay packets
   if (shouldThrottle(flow)) {
       Thread.sleep(10);
   }
   ```

3. **Add Live Statistics Dashboard**
   ```java
   // Separate thread printing stats every second
   void statsThread() {
       while (running) {
           printStats();
           Thread.sleep(1000);
       }
   }
   ```

4. **Add QUIC/HTTP3 Support**
   - QUIC uses UDP on port 443
   - SNI is in the Initial packet (encrypted differently)

5. **Add Persistent Rules**
   - Save rules to file
   - Load on startup

---

## Summary

This DPI engine demonstrates:

1. **Network Protocol Parsing** - Understanding packet structure
2. **Deep Packet Inspection** - Looking inside encrypted connections
3. **Flow Tracking** - Managing stateful connections
4. **Multi-threaded Architecture** - Scaling with thread pools
5. **Producer-Consumer Pattern** - Thread-safe queues

The key insight is that even HTTPS traffic leaks the destination domain in the TLS handshake, allowing network operators to identify and control application usage.

---

## Sample Output

Run on a 77-packet capture (`test_dpi.pcap`), first without any rules, then with an IP block rule active.

**Run 1 — plain analysis:**
```
java -jar target/packet-analyzer-1.0.0.jar test_dpi.pcap output-new.pcap --verbose
```
```
=== DPI REPORT ===
Total packets: 77
Total bytes: 5738
Forwarded: 77
Dropped: 0
TCP: 73
UDP: 4
Connections tracked: 43

=== THREAD STATISTICS ===
LB0 dispatched=47
LB1 dispatched=30
FP26 processed=47 forwarded=47 dropped=0
FP17 processed=30 forwarded=30 dropped=0

=== APPLICATION BREAKDOWN ===
Unknown       55  71.4%
DNS            4   5.2%
Twitter/X      3   3.9%
HTTP           2   2.6%
Apple, Zoom, Discord, TikTok, GitHub, YouTube,
Telegram, Spotify, Google, Facebook, Amazon,
Instagram, Cloudflare      1 each (1.3%)

[Detected Domains/SNIs]
twitter.com, www.facebook.com, discord.com, github.com, zoom.us,
open.spotify.com, www.netflix.com, www.apple.com, api.twitter.com,
www.amazon.com, www.instagram.com, web.telegram.org,
www.cloudflare.com, www.google.com, www.youtube.com,
www.microsoft.com, example.com, www.tiktok.com, httpbin.org
```

**Run 2 — with an IP block rule active:**
```
java -jar target/packet-analyzer-1.0.0.jar test_dpi.pcap blocked-new.pcap --block-ip 142.250.185.206 --verbose
```
```
[RuleManager] Blocked IP: 142.250.185.206
[FP3] DROP packet 0 reason=IP 142.250.185.206
[FP3] DROP packet 1 reason=IP 142.250.185.206
[FP3] DROP packet 2 reason=IP 142.250.185.206
[FP3] DROP packet 3 reason=IP 142.250.185.206

=== DPI REPORT ===
Total packets: 77
Forwarded: 73
Dropped: 4
Connections tracked: 43
```

The two load balancers (`LB0`, `LB1`) split incoming packets by five-tuple hash across
the fast-path workers (`FP17`, `FP26`), and the blocked IP's packets are dropped by
whichever worker owns that connection — confirming the rule engine and the
multi-threaded dispatch both work correctly on real, mixed application traffic.

---

## Questions?

If you have questions about any part of this project, the code is well-commented and follows the same flow described in this document. Start with the simple version (`MainWorking.java`) to understand the concepts, then move to the multi-threaded version (`DpiMt.java`) to see how parallelism is added.

Happy learning! 🚀