# Windows Setup - Java Version

## 1. Install Java
Install JDK 17 or newer and verify:

```powershell
java -version
javac -version
```

## 2. Build without Maven
```powershell
Remove-Item -Recurse -Force .\target -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force .\target\classes | Out-Null
javac -d .\target\classes .\src\main\java\packetanalyzer\*.java
jar cfe .\target\packet-analyzer-1.0.0.jar packetanalyzer.Main -C .\target\classes .
```

## 3. Run
```powershell
java -jar .\target\packet-analyzer-1.0.0.jar .\test_dpi.pcap .\output.pcap --verbose
```

Maven is optional.
