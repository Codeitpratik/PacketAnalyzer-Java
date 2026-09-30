package packetanalyzer;


public final class PacketParser {
  private PacketParser() {}

  public static final class ParsedPacket {
    public long timestampSec, timestampUsec;
    public String srcMac = "", destMac = "", srcIp = "", destIp = "";
    public int etherType;
    public boolean hasIp, hasTcp, hasUdp;
    public int ipVersion, protocol, ttl, srcPort, destPort, tcpFlags;
    public long seqNumber, ackNumber;
    public int payloadLength, payloadOffset;
    public byte[] payloadData;
  }

  public static final int ICMP = 1, TCP = 6, UDP = 17;
  public static final int IPV4 = 0x0800, IPV6 = 0x86dd, ARP = 0x0806;

  static int u16(byte[] b, int o) {
    return ((b[o] & 255) << 8) | (b[o + 1] & 255);
  }

  static long u32(byte[] b, int o) {
    return ((long) (b[o] & 255) << 24)
        | ((long) (b[o + 1] & 255) << 16)
        | ((long) (b[o + 2] & 255) << 8)
        | (b[o + 3] & 255L);
  }

  public static long ipToLong(String s) {
    String[] a = s.split("\\.");
    long r = 0;
    for (int i = 0; i < 4; i++) r = (r << 8) | (Long.parseLong(a[i]) & 255L);
    return r;
  }

  public static String ipToString(long ip) {
    return ((ip >>> 24) & 255)
        + "."
        + ((ip >>> 16) & 255)
        + "."
        + ((ip >>> 8) & 255)
        + "."
        + (ip & 255);
  }

  public static String macToString(byte[] d, int o) {
    return String.format(
        "%02x:%02x:%02x:%02x:%02x:%02x",
        d[o] & 255, d[o + 1] & 255, d[o + 2] & 255, d[o + 3] & 255, d[o + 4] & 255, d[o + 5] & 255);
  }

  public static String protocolToString(int p) {
    return p == 6 ? "TCP" : p == 17 ? "UDP" : p == 1 ? "ICMP" : "Unknown";
  }

  public static String tcpFlagsToString(int f) {
    StringBuilder s = new StringBuilder();
    if ((f & 1) != 0) s.append("FIN ");
    if ((f & 2) != 0) s.append("SYN ");
    if ((f & 4) != 0) s.append("RST ");
    if ((f & 8) != 0) s.append("PSH ");
    if ((f & 16) != 0) s.append("ACK ");
    if ((f & 32) != 0) s.append("URG ");
    return s.toString().trim();
  }

  public static ParsedPacket parse(PcapReader.RawPacket raw) {
    byte[] d = raw.data;
    if (d.length < 14) return null;
    ParsedPacket p = new ParsedPacket();
    p.timestampSec = raw.header.tsSec;
    p.timestampUsec = raw.header.tsUsec;
    p.destMac = macToString(d, 0);
    p.srcMac = macToString(d, 6);
    p.etherType = u16(d, 12);
    if (p.etherType != IPV4) return p;
    p.hasIp = true;
    int off = 14;
    if (d.length < off + 20) return p;
    int vihl = d[off] & 255;
    p.ipVersion = vihl >>> 4;
    int ihl = (vihl & 15) * 4;
    if (p.ipVersion != 4 || ihl < 20 || off + ihl > d.length) return p;
    p.ttl = d[off + 8] & 255;
    p.protocol = d[off + 9] & 255;
    p.srcIp = ipToString(u32(d, off + 12));
    p.destIp = ipToString(u32(d, off + 16));
    off += ihl;
    p.payloadOffset = off;
    if (p.protocol == TCP) {
      if (d.length < off + 20) return p;
      p.hasTcp = true;
      p.srcPort = u16(d, off);
      p.destPort = u16(d, off + 2);
      p.seqNumber = u32(d, off + 4);
      p.ackNumber = u32(d, off + 8);
      int h = ((d[off + 12] & 255) >>> 4) * 4;
      p.tcpFlags = d[off + 13] & 255;
      if (h < 20 || off + h > d.length) return p;
      off += h;
      p.payloadOffset = off;
    } else if (p.protocol == UDP) {
      if (d.length < off + 8) return p;
      p.hasUdp = true;
      p.srcPort = u16(d, off);
      p.destPort = u16(d, off + 2);
      off += 8;
      p.payloadOffset = off;
    }
    p.payloadLength = Math.max(0, d.length - off);
    p.payloadData =
        p.payloadLength == 0 ? new byte[0] : java.util.Arrays.copyOfRange(d, off, d.length);
    return p;
  }
}
