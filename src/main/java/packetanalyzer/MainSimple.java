package packetanalyzer;

/** Entry point for the simple (single-threaded) version of the DPI engine. */
public final class MainSimple {
  private MainSimple() {}

  public static void main(String[] args) {
    AnalyzerCli.run(args);
  }
}
