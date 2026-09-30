package packetanalyzer;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;

public final class SniExtractor {
  private SniExtractor() {}

  static int u16(byte[] b, int o) {
    return ((b[o] & 255) << 8) | (b[o + 1] & 255);
  }

  static int u24(byte[] b, int o) {
    return ((b[o] & 255) << 16) | ((b[o + 1] & 255) << 8) | (b[o + 2] & 255);
  }

  public static boolean isTLSClientHello(byte[] p) {
    return p != null
        && p.length >= 9
        && (p[0] & 255) == 0x16
        && u16(p, 1) >= 0x0300
        && u16(p, 1) <= 0x0304
        && (p[5] & 255) == 1;
  }

  public static Optional<String> extract(byte[] p) {
    if (!isTLSClientHello(p)) return Optional.empty();
    int off = 9;
    int hs = u24(p, 6);
    if (off + 34 > p.length) return Optional.empty();
    off += 2 + 32;
    if (off >= p.length) return Optional.empty();
    int sid = p[off++] & 255;
    if (off + sid > p.length) return Optional.empty();
    off += sid;
    if (off + 2 > p.length) return Optional.empty();
    int cs = u16(p, off);
    off += 2;
    if (off + cs > p.length) return Optional.empty();
    off += cs;
    if (off >= p.length) return Optional.empty();
    int comp = p[off++] & 255;
    if (off + comp > p.length) return Optional.empty();
    off += comp;
    if (off + 2 > p.length) return Optional.empty();
    int ext = u16(p, off);
    off += 2;
    int end = Math.min(p.length, off + ext);
    while (off + 4 <= end) {
      int type = u16(p, off), len = u16(p, off + 2);
      off += 4;
      if (off + len > end) break;
      if (type == 0 && len >= 5) {
        int q = off;
        int list = u16(p, q);
        q += 2;
        int qend = Math.min(off + len, q + list);
        while (q + 3 <= qend) {
          int kind = p[q++] & 255;
          int n = u16(p, q);
          q += 2;
          if (q + n > qend) break;
          if (kind == 0) return Optional.of(new String(p, q, n, StandardCharsets.US_ASCII));
          q += n;
        }
      }
      off += len;
    }
    return Optional.empty();
  }

  public static List<Map.Entry<Integer, String>> extractExtensions(byte[] p) {
    return List.of();
  }

  public static boolean isHttpRequest(byte[] p) {
    if (p == null || p.length < 4) return false;
    String s = new String(p, 0, Math.min(16, p.length), StandardCharsets.US_ASCII);
    return s.matches("(?s)^(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS)\\s+.*");
  }

  public static Optional<String> extractHttpHost(byte[] p) {
    if (!isHttpRequest(p)) return Optional.empty();
    String s = new String(p, StandardCharsets.ISO_8859_1);
    Matcher m = Pattern.compile("(?im)^Host:\\s*([^\\r\\n]+)").matcher(s);
    if (!m.find()) return Optional.empty();
    String h = m.group(1).trim();
    int c = h.indexOf(':');
    return Optional.of(c > 0 ? h.substring(0, c) : h);
  }

  public static boolean isDnsQuery(byte[] p) {
    return p != null && p.length >= 12 && (p[2] & 0x80) == 0 && u16(p, 4) > 0;
  }

  public static Optional<String> extractDnsQuery(byte[] p) {
    if (!isDnsQuery(p)) return Optional.empty();
    int o = 12;
    StringBuilder d = new StringBuilder();
    while (o < p.length) {
      int n = p[o++] & 255;
      if (n == 0) break;
      if (n > 63 || o + n > p.length) break;
      if (d.length() > 0) d.append('.');
      d.append(new String(p, o, n, StandardCharsets.US_ASCII));
      o += n;
    }
    return d.length() == 0 ? Optional.empty() : Optional.of(d.toString());
  }

  public static boolean isQuicInitial(byte[] p) {
    return p != null && p.length >= 5 && (p[0] & 0x80) != 0;
  }

  public static Optional<String> extractQuic(byte[] p) {
    if (!isQuicInitial(p)) return Optional.empty();
    for (int i = 0; i + 50 < p.length; i++) {
      if ((p[i] & 255) == 1 && i >= 5) {
        byte[] x = java.util.Arrays.copyOfRange(p, i - 5, p.length);
        Optional<String> s = extract(x);
        if (s.isPresent()) return s;
      }
    }
    return Optional.empty();
  }
}
