package packetanalyzer;

import java.util.*;
import java.util.concurrent.atomic.*;

public class LoadBalancer implements Runnable {
  private final int id;
  private final ThreadSafeQueue<Types.PacketJob> input;
  private final List<ThreadSafeQueue<Types.PacketJob>> outputs;
  private final AtomicBoolean running = new AtomicBoolean();
  private final AtomicLong dispatched = new AtomicLong();
  private Thread thread;

  public LoadBalancer(int id, List<ThreadSafeQueue<Types.PacketJob>> o, int size) {
    this.id = id;
    outputs = o;
    input = new ThreadSafeQueue<>(size);
  }

  public void start() {
    if (running.compareAndSet(false, true)) {
      thread = new Thread(this, "LB-" + id);
      thread.start();
    }
  }

  public void stop() {
    input.shutdown();
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
      while (running.get() || !input.isShutdown() || input.size() > 0) {
        var j = input.pop();
        if (j == null) break;
        int idx = Math.floorMod(j.tuple.hashCode(), outputs.size());
        outputs.get(idx).push(j);
        dispatched.incrementAndGet();
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  public ThreadSafeQueue<Types.PacketJob> input() {
    return input;
  }

  public long dispatched() {
    return dispatched.get();
  }
}
