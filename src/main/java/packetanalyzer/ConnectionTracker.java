package packetanalyzer;

import java.time.*;
import java.util.*;
import java.util.concurrent.locks.*;

public class ConnectionTracker {
  private final Map<Types.FiveTuple, Types.Connection> map = new HashMap<>();
  private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
  private final int max;
  private long totalSeen, classified, blocked;

  public ConnectionTracker(int id, int max) {
    this.max = max;
  }

  public Types.Connection getOrCreate(Types.FiveTuple t) {
    lock.writeLock().lock();
    try {
      var c = map.get(t);
      if (c != null) return c;
      if (map.size() >= max) evictOldest();
      c = new Types.Connection();
      c.tuple = t;
      c.firstSeen = Instant.now();
      c.lastSeen = c.firstSeen;
      map.put(t, c);
      totalSeen++;
      return c;
    } finally {
      lock.writeLock().unlock();
    }
  }

  public void update(Types.Connection c, int bytes, boolean out, int flags) {
    lock.writeLock().lock();
    try {
      if (out) {
        c.packetsOut++;
        c.bytesOut += bytes;
      } else {
        c.packetsIn++;
        c.bytesIn += bytes;
      }
      c.lastSeen = Instant.now();
      if ((flags & 2) != 0) c.synSeen = true;
      if ((flags & 18) == 18) c.synAckSeen = true;
      if ((flags & 1) != 0) c.finSeen = true;
      if (c.synSeen && c.synAckSeen) c.state = Types.ConnectionState.ESTABLISHED;
    } finally {
      lock.writeLock().unlock();
    }
  }

  public void classify(Types.Connection c, Types.AppType a, String s) {
    lock.writeLock().lock();
    try {
      c.appType = a;
      c.sni = s == null ? "" : s;
      c.state = Types.ConnectionState.CLASSIFIED;
      classified++;
    } finally {
      lock.writeLock().unlock();
    }
  }

  public void block(Types.Connection c) {
    lock.writeLock().lock();
    try {
      if (c.state != Types.ConnectionState.BLOCKED) blocked++;
      c.state = Types.ConnectionState.BLOCKED;
      c.action = Types.PacketAction.DROP;
    } finally {
      lock.writeLock().unlock();
    }
  }

  public int activeCount() {
    return map.size();
  }

  public List<Types.Connection> all() {
    lock.readLock().lock();
    try {
      return new ArrayList<>(map.values());
    } finally {
      lock.readLock().unlock();
    }
  }

  private void evictOldest() {
    map.entrySet().stream()
        .min(Comparator.comparing(e -> e.getValue().lastSeen))
        .ifPresent(e -> map.remove(e.getKey()));
  }

  public long totalSeen() {
    return totalSeen;
  }

  public long classified() {
    return classified;
  }

  public long blocked() {
    return blocked;
  }
}
