package packetanalyzer;

/** Entry point for the multi-threaded (load-balanced) version of the DPI engine. */
public final class DpiMt {
  private DpiMt() {}

  public static void main(String[] args) {
    AnalyzerCli.run(args);
  }
}
