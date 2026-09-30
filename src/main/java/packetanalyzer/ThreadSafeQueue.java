package packetanalyzer;

import java.util.concurrent.*;

public class ThreadSafeQueue<T> {
  private final ArrayBlockingQueue<T> q;
  private volatile boolean shutdown;

  public ThreadSafeQueue(int n) {
    q = new ArrayBlockingQueue<>(n);
  }

  public void push(T x) throws InterruptedException {
    if (!shutdown) q.put(x);
  }

  public boolean tryPush(T x) {
    return !shutdown && q.offer(x);
  }

  public T pop() throws InterruptedException {
    while (true) {
      T x = q.poll(200, TimeUnit.MILLISECONDS);
      if (x != null) return x;
      if (shutdown && q.isEmpty()) return null;
    }
  }

  public T pop(long ms) throws InterruptedException {
    return q.poll(ms, TimeUnit.MILLISECONDS);
  }

  public void shutdown() {
    shutdown = true;
  }

  public boolean isShutdown() {
    return shutdown;
  }

  public int size() {
    return q.size();
  }
}
