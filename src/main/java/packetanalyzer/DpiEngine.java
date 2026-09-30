package packetanalyzer;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

public class DpiEngine {
  public static class Config {
    public int numLoadBalancers = 2, fpsPerLb = 2, queueSize = 10000;
    public boolean verbose;
    public String rulesFile = "";
  }

  private final Config cfg;
  private final RuleManager rules = new RuleManager();
  private final List<FastPathProcessor> fps = new ArrayList<>();
  private final List<LoadBalancer> lbs = new ArrayList<>();
  private final Types.Stats stats = new Types.Stats();
  private final List<Types.PacketJob> forwarded = Collections.synchronizedList(new ArrayList<>());

  public DpiEngine(Config c) {
    cfg = c;
  }

  public void blockIP(String x) {
    rules.blockIP(x);
  }

  public void blockApp(String x) {
    for (var a : Types.AppType.values())
      if (Types.appTypeToString(a).equalsIgnoreCase(x)) {
        rules.blockApp(a);
        return;
      }
    throw new IllegalArgumentException("Unknown app: " + x);
  }

  public void blockDomain(String x) {
    rules.blockDomain(x);
  }

  public boolean loadRules(String x) {
    return rules.loadRules(x);
  }

  public RuleManager rules() {
    return rules;
  }

  public boolean process(String in, String out) {
    return processFile(in, out);
  }

  public boolean processFile(String in, String out) {
    if (!new File(in).isFile()) {
      System.err.println("Input not found: " + in);
      return false;
    }
    PcapReader reader = new PcapReader();
    if (!reader.open(in)) return false;
    fps.clear();
    lbs.clear();
    forwarded.clear();
    List<ThreadSafeQueue<Types.PacketJob>> qs = new ArrayList<>();
    FastPathProcessor.OutputCallback cb =
        (j, a, c) -> {
          stats.forwardedPackets.incrementAndGet();
          stats.app(c.appType);
          if (c.sni != null && !c.sni.isEmpty()) stats.detectedSnis.add(c.sni);
          forwarded.add(j);
        };
    for (int i = 0; i < cfg.numLoadBalancers * cfg.fpsPerLb; i++) {
      var f = new FastPathProcessor(i, rules, cb, cfg.queueSize);
      fps.add(f);
      qs.add(f.queue());
    }
    for (int i = 0; i < cfg.numLoadBalancers; i++) {
      lbs.add(
          new LoadBalancer(
              i,
              new ArrayList<>(qs.subList(i * cfg.fpsPerLb, (i + 1) * cfg.fpsPerLb)),
              cfg.queueSize));
    }
    fps.forEach(FastPathProcessor::start);
    lbs.forEach(LoadBalancer::start);
    PcapReader.RawPacket raw;
    int id = 0;
    while ((raw = reader.readNextPacket()) != null) {
      stats.totalPackets.incrementAndGet();
      stats.totalBytes.addAndGet(raw.data.length);
      var p = PacketParser.parse(raw);
      if (p == null || !p.hasIp || (!p.hasTcp && !p.hasUdp)) {
        stats.otherPackets.incrementAndGet();
        continue;
      }
      if (p.hasTcp) stats.tcpPackets.incrementAndGet();
      else if (p.hasUdp) stats.udpPackets.incrementAndGet();
      var t =
          new Types.FiveTuple(
              PacketParser.ipToLong(p.srcIp),
              PacketParser.ipToLong(p.destIp),
              p.srcPort,
              p.destPort,
              p.protocol);
      var j = new Types.PacketJob(id++, t, raw.data);
      j.payloadOffset = p.payloadOffset;
      j.payloadLength = p.payloadLength;
      j.tcpFlags = p.tcpFlags;
      j.ipOffset = 14;
      j.transportOffset = p.payloadOffset - p.payloadLength;
      j.tsSec = raw.header.tsSec;
      j.tsUsec = raw.header.tsUsec;
      int lb = Math.floorMod(t.hashCode(), lbs.size());
      try {
        lbs.get(lb).input().push(j);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        break;
      }
    }
    reader.close();
    for (var l : lbs) l.stop();
    for (var f : fps) f.stop();
    long forwardedCount = stats.forwardedPackets.get();
    stats.droppedPackets.set(stats.totalPackets.get() - forwardedCount);
    stats.activeConnections.set(fps.stream().mapToLong(f -> f.tracker().activeCount()).sum());
    return writeOutput(out, reader.getGlobalHeader());
  }

  private boolean writeOutput(String file, PcapReader.GlobalHeader gh) {
    try (DataOutputStream o =
        new DataOutputStream(new BufferedOutputStream(new FileOutputStream(file)))) {
      boolean le = gh == null || gh.littleEndian;
      PcapReader.writeGlobalHeader(o, gh);
      synchronized (forwarded) {
        for (var j : forwarded) {
          PcapReader.writeU32(o, j.tsSec, le);
          PcapReader.writeU32(o, j.tsUsec, le);
          PcapReader.writeU32(o, j.data.length, le);
          PcapReader.writeU32(o, j.data.length, le);
          o.write(j.data);
        }
      }
      return true;
    } catch (IOException e) {
      System.err.println("Output error: " + e.getMessage());
      return false;
    }
  }

  public String report() {
    StringBuilder s = new StringBuilder("\n=== DPI REPORT ===\n");
    s.append("Total packets: ")
        .append(stats.totalPackets)
        .append('\n')
        .append("Total bytes: ")
        .append(stats.totalBytes)
        .append('\n')
        .append("Forwarded: ")
        .append(stats.forwardedPackets)
        .append('\n')
        .append("Dropped: ")
        .append(stats.droppedPackets)
        .append('\n')
        .append("TCP: ")
        .append(stats.tcpPackets)
        .append('\n')
        .append("UDP: ")
        .append(stats.udpPackets)
        .append('\n')
        .append("Other: ")
        .append(stats.otherPackets)
        .append('\n')
        .append("Connections tracked: ")
        .append(stats.activeConnections)
        .append('\n');
    s.append("\n=== THREAD STATISTICS ===\n");
    for (int i = 0; i < lbs.size(); i++)
      s.append("LB").append(i).append(" dispatched=").append(lbs.get(i).dispatched()).append("\n");
    for (var f : fps)
      s.append("FP")
          .append(f.tracker().activeCount())
          .append(" processed=")
          .append(f.processed())
          .append(" forwarded=")
          .append(f.forwarded())
          .append(" dropped=")
          .append(f.dropped())
          .append('\n');
    s.append("\n=== APPLICATION BREAKDOWN ===\n");
    stats.appCounts.entrySet().stream()
        .sorted((a, b) -> Long.compare(b.getValue().get(), a.getValue().get()))
        .forEach(
            e -> {
              double pct =
                  stats.totalPackets.get() == 0
                      ? 0
                      : 100.0 * e.getValue().get() / stats.totalPackets.get();
              s.append(
                  String.format(
                      Locale.ROOT,
                      "%-15s %8d %5.1f%% %s%n",
                      Types.appTypeToString(e.getKey()),
                      e.getValue().get(),
                      pct,
                      "#".repeat(Math.max(0, (int) (pct / 5)))));
            });
    if (!stats.detectedSnis.isEmpty()) {
      s.append("\n[Detected Domains/SNIs]\n");
      for (String x : stats.detectedSnis) s.append("  - ").append(x).append('\n');
    }
    return s.toString();
  }
}
