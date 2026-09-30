package packetanalyzer;

import java.util.concurrent.atomic.*;

public class FastPathProcessor implements Runnable {
  public interface OutputCallback {
    void handle(Types.PacketJob j, Types.PacketAction a, Types.Connection c);
  }

  private final int id;
  private final ThreadSafeQueue<Types.PacketJob> queue;
  private final RuleManager rules;
  private final OutputCallback output;
  private final ConnectionTracker tracker;
  private final AtomicBoolean running = new AtomicBoolean();
  private Thread thread;
  private final AtomicLong processed = new AtomicLong(),
      forwarded = new AtomicLong(),
      dropped = new AtomicLong(),
      sniHits = new AtomicLong(),
      classHits = new AtomicLong();

  public FastPathProcessor(int id, RuleManager r, OutputCallback o, int size) {
    this.id = id;
    rules = r;
    output = o;
    queue = new ThreadSafeQueue<>(size);
    tracker = new ConnectionTracker(id, 100000);
  }

  public void start() {
    if (running.compareAndSet(false, true)) {
      thread = new Thread(this, "FP-" + id);
      thread.start();
    }
  }

  public void stop() {
    queue.shutdown();
    if (thread != null)
      try {
        thread.join(5000);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    running.set(false);
  }

  public void run() {
    try {
      while (running.get() || !queue.isShutdown() || queue.size() > 0) {
        var j = queue.pop();
        if (j == null) break;
        process(j);
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  private void process(Types.PacketJob j) {
    processed.incrementAndGet();
    var c = tracker.getOrCreate(j.tuple);
    tracker.update(c, j.data.length, false, j.tcpFlags);
    byte[] p = j.payload();
    String domain = c.sni;
    Types.AppType app = c.appType;
    if (app == Types.AppType.UNKNOWN) {
      if (j.tuple.dstPort() == 443 || j.tuple.srcPort() == 443) {
        var s = SniExtractor.extract(p);
        if (s.isEmpty() && j.tuple.dstPort() == 443) s = SniExtractor.extractQuic(p);
        if (s.isPresent()) {
          domain = s.get();
          app = Types.sniToAppType(domain);
          sniHits.incrementAndGet();
          tracker.classify(c, app, domain);
          classHits.incrementAndGet();
        } else app = Types.AppType.TLS;
      } else if (j.tuple.dstPort() == 80 || j.tuple.srcPort() == 80) {
        var h = SniExtractor.extractHttpHost(p);
        if (h.isPresent()) {
          domain = h.get();
          app = Types.AppType.HTTP;
          tracker.classify(c, app, domain);
          classHits.incrementAndGet();
        }
      } else if (j.tuple.dstPort() == 53 || j.tuple.srcPort() == 53) {
        var d = SniExtractor.extractDnsQuery(p);
        if (d.isPresent()) {
          domain = d.get();
          app = Types.AppType.DNS;
          tracker.classify(c, app, domain);
          classHits.incrementAndGet();
        }
      } else if (j.tuple.dstPort() == 443 || j.tuple.srcPort() == 443) {
        app = Types.AppType.HTTPS;
      }
    }
    var reason =
        rules.shouldBlock(j.tuple.srcIp(), j.tuple.dstIp(), j.tuple.dstPort(), app, domain);
    if (reason.isPresent()) {
      tracker.block(c);
      dropped.incrementAndGet();
      System.out.println(
          "[FP"
              + id
              + "] DROP packet "
              + j.packetId
              + " reason="
              + reason.get().type()
              + " "
              + reason.get().detail());
    } else {
      forwarded.incrementAndGet();
      output.handle(j, Types.PacketAction.FORWARD, c);
    }
  }

  public ThreadSafeQueue<Types.PacketJob> queue() {
    return queue;
  }

  public ConnectionTracker tracker() {
    return tracker;
  }

  public long processed() {
    return processed.get();
  }

  public long forwarded() {
    return forwarded.get();
  }

  public long dropped() {
    return dropped.get();
  }

  public long sniHits() {
    return sniHits.get();
  }

  public long classHits() {
    return classHits.get();
  }
}
