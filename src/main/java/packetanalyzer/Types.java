package packetanalyzer;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

public final class Types {
  private Types() {}

  public enum AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE
  }

  public enum ConnectionState {
    NEW,
    ESTABLISHED,
    CLASSIFIED,
    BLOCKED,
    CLOSED
  }

  public enum PacketAction {
    FORWARD,
    DROP,
    INSPECT,
    LOG_ONLY
  }

  public static String appTypeToString(AppType t) {
    if (t == null) return "Unknown";
    return switch (t) {
      case UNKNOWN -> "Unknown";
      case HTTP -> "HTTP";
      case HTTPS -> "HTTPS";
      case DNS -> "DNS";
      case TLS -> "TLS";
      case QUIC -> "QUIC";
      case GOOGLE -> "Google";
      case FACEBOOK -> "Facebook";
      case YOUTUBE -> "YouTube";
      case TWITTER -> "Twitter/X";
      case INSTAGRAM -> "Instagram";
      case NETFLIX -> "Netflix";
      case AMAZON -> "Amazon";
      case MICROSOFT -> "Microsoft";
      case APPLE -> "Apple";
      case WHATSAPP -> "WhatsApp";
      case TELEGRAM -> "Telegram";
      case TIKTOK -> "TikTok";
      case SPOTIFY -> "Spotify";
      case ZOOM -> "Zoom";
      case DISCORD -> "Discord";
      case GITHUB -> "GitHub";
      case CLOUDFLARE -> "Cloudflare";
    };
  }

  public static AppType sniToAppType(String sni) {
    if (sni == null || sni.isBlank()) return AppType.UNKNOWN;
    String s = sni.toLowerCase(Locale.ROOT);
    if (s.contains("google")
        || s.contains("gstatic")
        || s.contains("googleapis")
        || s.contains("ggpht")
        || s.contains("gvt1")) return AppType.GOOGLE;
    if (s.contains("youtube")
        || s.contains("ytimg")
        || s.contains("youtu.be")
        || s.contains("yt3.ggpht")) return AppType.YOUTUBE;
    if (s.contains("facebook")
        || s.contains("fbcdn")
        || s.contains("fb.com")
        || s.contains("fbsbx")
        || s.contains("meta.com")) return AppType.FACEBOOK;
    if (s.contains("instagram") || s.contains("cdninstagram")) return AppType.INSTAGRAM;
    if (s.contains("whatsapp") || s.contains("wa.me")) return AppType.WHATSAPP;
    if (s.contains("twitter") || s.contains("twimg") || s.contains("x.com") || s.contains("t.co"))
      return AppType.TWITTER;
    if (s.contains("netflix") || s.contains("nflxvideo") || s.contains("nflximg"))
      return AppType.NETFLIX;
    if (s.contains("amazon")
        || s.contains("amazonaws")
        || s.contains("cloudfront")
        || s.contains("aws")) return AppType.AMAZON;
    if (s.contains("microsoft")
        || s.contains("msn.com")
        || s.contains("office")
        || s.contains("azure")
        || s.contains("live.com")
        || s.contains("outlook")
        || s.contains("bing")) return AppType.MICROSOFT;
    if (s.contains("apple")
        || s.contains("icloud")
        || s.contains("mzstatic")
        || s.contains("itunes")) return AppType.APPLE;
    if (s.contains("telegram") || s.contains("t.me")) return AppType.TELEGRAM;
    if (s.contains("tiktok")
        || s.contains("tiktokcdn")
        || s.contains("musical.ly")
        || s.contains("bytedance")) return AppType.TIKTOK;
    if (s.contains("spotify") || s.contains("scdn.co")) return AppType.SPOTIFY;
    if (s.contains("zoom")) return AppType.ZOOM;
    if (s.contains("discord") || s.contains("discordapp")) return AppType.DISCORD;
    if (s.contains("github") || s.contains("githubusercontent")) return AppType.GITHUB;
    if (s.contains("cloudflare") || s.contains("cf-")) return AppType.CLOUDFLARE;
    return AppType.HTTPS;
  }

  public record FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
    public FiveTuple reverse() {
      return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    public String toString() {
      return PacketParser.ipToString(srcIp)
          + ":"
          + srcPort
          + " -> "
          + PacketParser.ipToString(dstIp)
          + ":"
          + dstPort
          + " ("
          + (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?")
          + ")";
    }
  }

  public static class Connection {
    public FiveTuple tuple;
    public ConnectionState state = ConnectionState.NEW;
    public AppType appType = AppType.UNKNOWN;
    public String sni = "";
    public long packetsIn, packetsOut, bytesIn, bytesOut;
    public Instant firstSeen = Instant.now(), lastSeen = firstSeen;
    public PacketAction action = PacketAction.FORWARD;
    public boolean synSeen, synAckSeen, finSeen;
  }

  public static class PacketJob {
    public int packetId;
    public FiveTuple tuple;
    public byte[] data;
    public int ethOffset, ipOffset, transportOffset, payloadOffset, payloadLength, tcpFlags;
    public long tsSec, tsUsec;

    public PacketJob(int id, FiveTuple t, byte[] d) {
      packetId = id;
      tuple = t;
      data = d;
    }

    public byte[] payload() {
      return payloadLength <= 0
          ? new byte[0]
          : Arrays.copyOfRange(
              data, payloadOffset, Math.min(data.length, payloadOffset + payloadLength));
    }
  }

  public static class Stats {
    public final AtomicLong totalPackets = new AtomicLong(),
        totalBytes = new AtomicLong(),
        forwardedPackets = new AtomicLong(),
        droppedPackets = new AtomicLong(),
        tcpPackets = new AtomicLong(),
        udpPackets = new AtomicLong(),
        otherPackets = new AtomicLong(),
        activeConnections = new AtomicLong();
    public final Map<AppType, AtomicLong> appCounts =
        new java.util.concurrent.ConcurrentHashMap<>();
    public final Set<String> detectedSnis = java.util.concurrent.ConcurrentHashMap.newKeySet();

    public void app(AppType a) {
      appCounts.computeIfAbsent(a, k -> new AtomicLong()).incrementAndGet();
    }
  }
}
