package packetanalyzer;

import java.io.*;
import java.util.*;
import java.util.concurrent.locks.*;

public class RuleManager {
  public record BlockReason(String type, String detail) {}

  private final Set<Long> ips = new HashSet<>(), ports = new HashSet<>();
  private final Set<Types.AppType> apps = new HashSet<>();
  private final Set<String> domains = new HashSet<>();
  private final List<String> patterns = new ArrayList<>();
  private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

  public static long parseIP(String s) {
    return PacketParser.ipToLong(s);
  }

  public static String ipToString(long x) {
    return PacketParser.ipToString(x);
  }

  public void blockIP(String s) {
    blockIP(parseIP(s));
  }

  public void blockIP(long x) {
    w(() -> ips.add(x));
    System.out.println("[RuleManager] Blocked IP: " + ipToString(x));
  }

  public void unblockIP(String s) {
    unblockIP(parseIP(s));
  }

  public void unblockIP(long x) {
    w(() -> ips.remove(x));
  }

  public boolean isIPBlocked(long x) {
    return r(() -> ips.contains(x));
  }

  public List<String> getBlockedIPs() {
    return r(() -> ips.stream().map(RuleManager::ipToString).toList());
  }

  public void blockApp(Types.AppType a) {
    w(() -> apps.add(a));
    System.out.println("[RuleManager] Blocked app: " + Types.appTypeToString(a));
  }

  public void unblockApp(Types.AppType a) {
    w(() -> apps.remove(a));
  }

  public boolean isAppBlocked(Types.AppType a) {
    return r(() -> apps.contains(a));
  }

  public List<Types.AppType> getBlockedApps() {
    return r(() -> new ArrayList<>(apps));
  }

  public void blockDomain(String d) {
    w(
        () -> {
          if (d.contains("*")) patterns.add(d);
          else domains.add(d);
        });
    System.out.println("[RuleManager] Blocked domain: " + d);
  }

  public void unblockDomain(String d) {
    w(
        () -> {
          domains.remove(d);
          patterns.remove(d);
        });
  }

  public boolean isDomainBlocked(String d) {
    if (d == null || d.isEmpty()) return false;
    return r(
        () -> {
          if (domains.contains(d)) return true;
          String x = d.toLowerCase(Locale.ROOT);
          for (String p : patterns) if (match(x, p.toLowerCase(Locale.ROOT))) return true;
          return false;
        });
  }

  private static boolean match(String d, String p) {
    if (p.startsWith("*.")) {
      String s = p.substring(1);
      return d.endsWith(s) || d.equals(p.substring(2));
    }
    return false;
  }

  public void blockPort(int p) {
    w(() -> ports.add((long) p));
    System.out.println("[RuleManager] Blocked port: " + p);
  }

  public void unblockPort(int p) {
    w(() -> ports.remove((long) p));
  }

  public boolean isPortBlocked(int p) {
    return r(() -> ports.contains((long) p));
  }

  public Optional<BlockReason> shouldBlock(
      long src, long dstIp, int dst, Types.AppType app, String domain) {
    if (isIPBlocked(src)) return Optional.of(new BlockReason("IP", ipToString(src)));
    if (isIPBlocked(dstIp)) return Optional.of(new BlockReason("IP", ipToString(dstIp)));
    if (isPortBlocked(dst)) return Optional.of(new BlockReason("PORT", String.valueOf(dst)));
    if (isAppBlocked(app)) return Optional.of(new BlockReason("APP", Types.appTypeToString(app)));
    if (isDomainBlocked(domain)) return Optional.of(new BlockReason("DOMAIN", domain));
    return Optional.empty();
  }

  public boolean saveRules(String f) {
    try (PrintWriter o = new PrintWriter(f)) {
      o.println("[BLOCKED_IPS]");
      for (String x : getBlockedIPs()) o.println(x);
      o.println("\n[BLOCKED_APPS]");
      for (var x : getBlockedApps()) o.println(Types.appTypeToString(x));
      o.println("\n[BLOCKED_DOMAINS]");
      for (String x : r(() -> new ArrayList<>(domains))) o.println(x);
      for (String x : r(() -> new ArrayList<>(patterns))) o.println(x);
      o.println("\n[BLOCKED_PORTS]");
      for (long x : r(() -> new ArrayList<>(ports))) o.println(x);
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  public boolean loadRules(String f) {
    try (BufferedReader b = new BufferedReader(new FileReader(f))) {
      String sec = "", line;
      while ((line = b.readLine()) != null) {
        line = line.trim();
        if (line.isEmpty()) continue;
        if (line.startsWith("[")) {
          sec = line;
          continue;
        }
        switch (sec) {
          case "[BLOCKED_IPS]" -> blockIP(line);
          case "[BLOCKED_APPS]" -> {
            for (var a : Types.AppType.values())
              if (Types.appTypeToString(a).equals(line)) {
                blockApp(a);
                break;
              }
          }
          case "[BLOCKED_DOMAINS]" -> blockDomain(line);
          case "[BLOCKED_PORTS]" -> blockPort(Integer.parseInt(line));
        }
      }
      return true;
    } catch (Exception e) {
      System.err.println("[RuleManager] Rules load error: " + e.getMessage());
      return false;
    }
  }

  public void clearAll() {
    w(
        () -> {
          ips.clear();
          ports.clear();
          apps.clear();
          domains.clear();
          patterns.clear();
        });
  }

  private void w(Runnable x) {
    lock.writeLock().lock();
    try {
      x.run();
    } finally {
      lock.writeLock().unlock();
    }
  }

  private <T> T r(java.util.function.Supplier<T> x) {
    lock.readLock().lock();
    try {
      return x.get();
    } finally {
      lock.readLock().unlock();
    }
  }
}
