package packetanalyzer;

/** Entry point for the standard DPI (Deep Packet Inspection) engine. */
public final class MainDpi {
  private MainDpi() {}

  public static void main(String[] args) {
    AnalyzerCli.run(args);
  }
}
