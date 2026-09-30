package packetanalyzer;

/** Command-line entry point and argument handling for the analyzer. */
public final class AnalyzerCli {
  private AnalyzerCli() {}

  public static void run(String[] args) {
    if (args.length < 2) {
      printUsage();
      return;
    }

    String input = args[0];
    String output = args[1];
    DpiEngine.Config config = new DpiEngine.Config();
    DpiEngine engine = new DpiEngine(config);

    try {
      for (int i = 2; i < args.length; i++) {
        switch (args[i]) {
          case "--block-ip" -> engine.blockIP(args[++i]);
          case "--block-app" -> engine.blockApp(args[++i]);
          case "--block-domain" -> engine.blockDomain(args[++i]);
          case "--block-port" -> engine.rules().blockPort(Integer.parseInt(args[++i]));
          case "--rules" -> config.rulesFile = args[++i];
          case "--lbs" -> config.numLoadBalancers = Math.max(1, Integer.parseInt(args[++i]));
          case "--fps" -> config.fpsPerLb = Math.max(1, Integer.parseInt(args[++i]));
          case "--verbose" -> config.verbose = true;
          default -> throw new IllegalArgumentException("Unknown option: " + args[i]);
        }
      }

      if (!config.rulesFile.isEmpty() && !engine.loadRules(config.rulesFile)) {
        throw new IllegalArgumentException("Could not load rules file: " + config.rulesFile);
      }
      if (!engine.process(input, output)) {
        throw new IllegalStateException("Packet analysis failed");
      }
      System.out.println(engine.report());
      System.out.println("Output written to: " + output);
    } catch (Exception ex) {
      System.err.println("Error: " + ex.getMessage());
      System.exit(1);
    }
  }

  private static void printUsage() {
    System.out.println("Packet Analyzer / DPI Engine - Java 17+");
    System.out.println(
        "Usage: java -jar packet-analyzer-1.0.0.jar <input.pcap> <output.pcap> [options]");
    System.out.println("  --block-ip <ip>");
    System.out.println("  --block-app <app>");
    System.out.println("  --block-domain <domain|*.domain>");
    System.out.println("  --block-port <port>");
    System.out.println("  --lbs <n>");
    System.out.println("  --fps <n>");
    System.out.println("  --rules <file>");
    System.out.println("  --verbose");
  }
}
