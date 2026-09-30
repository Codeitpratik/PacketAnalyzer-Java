package packetanalyzer;

public final class Platform {
  private Platform() {}

  public static final boolean WINDOWS =
      System.getProperty("os.name", "").toLowerCase().contains("win");
  public static final String OS = System.getProperty("os.name");
  public static final String ARCH = System.getProperty("os.arch");
}
