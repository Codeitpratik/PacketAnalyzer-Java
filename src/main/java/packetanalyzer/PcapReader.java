package packetanalyzer;

import java.io.*;

public final class PcapReader implements Closeable {
  public static class GlobalHeader {
    public long magic;
    public int versionMajor, versionMinor, snaplen, network;
    public boolean littleEndian;
  }

  public static class PacketHeader {
    public long tsSec, tsUsec, inclLen, origLen;
  }

  public static class RawPacket {
    public PacketHeader header;
    public byte[] data;

    RawPacket(PacketHeader h, byte[] d) {
      header = h;
      data = d;
    }
  }

  private DataInputStream in;
  private GlobalHeader gh;
  private boolean little;

  public boolean open(String file) {
    try {
      in = new DataInputStream(new BufferedInputStream(new FileInputStream(file)));
      byte[] h = new byte[24];
      in.readFully(h);
      long m = read32(h, 0, false);
      if (m == 0xa1b2c3d4L || m == 0xa1b23c4dL) {
        little = (m == 0xa1b2c3d4L);
      } else {
        long ml = read32(h, 0, true);
        if (ml != 0xa1b2c3d4L && ml != 0xa1b23c4dL) throw new IOException("Unsupported PCAP magic");
        little = true;
      }
      gh = new GlobalHeader();
      gh.magic = m;
      gh.littleEndian = little;
      gh.versionMajor = (int) read16(h, 4, little);
      gh.versionMinor = (int) read16(h, 6, little);
      gh.snaplen = (int) read32(h, 16, little);
      gh.network = (int) read32(h, 20, little);
      return true;
    } catch (Exception e) {
      System.err.println("PCAP open error: " + e.getMessage());
      return false;
    }
  }

  private static long read16(byte[] b, int o, boolean le) {
    return le ? ((b[o] & 255) | ((b[o + 1] & 255) << 8)) : (((b[o] & 255) << 8) | (b[o + 1] & 255));
  }

  private static long read32(byte[] b, int o, boolean le) {
    if (le)
      return (b[o] & 255L)
          | ((b[o + 1] & 255L) << 8)
          | ((b[o + 2] & 255L) << 16)
          | ((b[o + 3] & 255L) << 24);
    return ((b[o] & 255L) << 24)
        | ((b[o + 1] & 255L) << 16)
        | ((b[o + 2] & 255L) << 8)
        | (b[o + 3] & 255L);
  }

  public RawPacket readNextPacket() {
    if (in == null) return null;
    try {
      byte[] h = new byte[16];
      in.readFully(h);
      PacketHeader p = new PacketHeader();
      p.tsSec = read32(h, 0, little);
      p.tsUsec = read32(h, 4, little);
      p.inclLen = read32(h, 8, little);
      p.origLen = read32(h, 12, little);
      if (p.inclLen < 0 || p.inclLen > 100_000_000) throw new IOException("Invalid packet length");
      byte[] d = new byte[(int) p.inclLen];
      in.readFully(d);
      return new RawPacket(p, d);
    } catch (EOFException e) {
      return null;
    } catch (Exception e) {
      System.err.println("PCAP read error: " + e.getMessage());
      return null;
    }
  }

  public GlobalHeader getGlobalHeader() {
    return gh;
  }

  public boolean isLittleEndian() {
    return little;
  }

  public void close() {
    try {
      if (in != null) in.close();
    } catch (IOException ignored) {
    }
  }

  public static void writeU16(DataOutputStream o, long v, boolean le) throws IOException {
    if (le) {
      o.write((int) (v & 255));
      o.write((int) ((v >>> 8) & 255));
    } else {
      o.write((int) ((v >>> 8) & 255));
      o.write((int) (v & 255));
    }
  }

  public static void writeU32(DataOutputStream o, long v, boolean le) throws IOException {
    if (le) {
      o.write((int) v & 255);
      o.write((int) (v >>> 8) & 255);
      o.write((int) (v >>> 16) & 255);
      o.write((int) (v >>> 24) & 255);
    } else {
      o.write((int) (v >>> 24) & 255);
      o.write((int) (v >>> 16) & 255);
      o.write((int) (v >>> 8) & 255);
      o.write((int) v & 255);
    }
  }

  public static void writeGlobalHeader(DataOutputStream o, GlobalHeader g) throws IOException {
    boolean le = g == null || g.littleEndian;
    writeU32(o, 0xa1b2c3d4L, le);
    writeU16(o, g == null ? 2 : g.versionMajor, le);
    writeU16(o, g == null ? 4 : g.versionMinor, le);
    writeU32(o, 0, le);
    writeU32(o, 0, le);
    writeU32(o, g == null ? 65535 : g.snaplen, le);
    writeU32(o, g == null ? 1 : g.network, le);
  }
}
