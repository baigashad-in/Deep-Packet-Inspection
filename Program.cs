using Deep_Packet_Analyzer.Engine;
using Deep_Packet_Analyzer.Types;

if (args.Length < 2 || args.Any(a => a == "--help" || a == "-h" || a == "/?"))
{
    Console.WriteLine("Usage: PacketAnalyzer <input.pcap> <output.pcap> [options]");
    Console.WriteLine();
    Console.WriteLine("Options:");
    Console.WriteLine(" --block-ip <ip> Block traffic from source IP");
    Console.WriteLine(" --block-app <app> Block application (YouTube, Facebook, etc.)");
    Console.WriteLine(" --block-domain <dom> Block domain (*.tiktok.com)");
    Console.WriteLine(" --block-port <port> Block destination port");
    Console.WriteLine();
    Console.WriteLine("Examples:");
    Console.WriteLine(" DeepPacketAnalyzer capture.pcap filtered.pcap");
    Console.WriteLine(" DeepPacketAnalyzer capture.pcap filtered.pcap --block-app YouTube");
    Console.WriteLine(" DeepPacketAnalyzer capture.pcap filtered.pcap --block-domain \"*.tiktok.com\"");
    return 1;
}

string inputFile = args[0];
string outputFile = args[1];

if (!File.Exists(inputFile))
{
    Console.WriteLine($"Input file not found: {inputFile}");
    return 1;
}

if (Path.GetFullPath(inputFile) == Path.GetFullPath(outputFile))
{
    Console.WriteLine("Input and output files must differ");
    return 1;
}

var config = new DpiEngineConfig
{
    NumLoadBalancers = 2,
    FpsPerLb = 2
};

var engine = new DpiEngine(config);
engine.Initialize();

try
{
    for (int i = 2; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "--block-ip" when i + 1 < args.Length:
                engine.Rules.BlockIp(args[++i]);
                break;

            case "--block-app" when i + 1 < args.Length:
                string appName = args[++i];
                bool found = false;
                foreach (AppType app in Enum.GetValues<AppType>())
                {
                    if (AppClassifier.AppTypeToString(app)
                        .Equals(appName, StringComparison.OrdinalIgnoreCase))
                    {
                        engine.Rules.BlockApp(app);
                        found = true;
                        break;
                    }
                }
                if (!found)
                {
                    Console.Error.WriteLine($"Unknown app: '{appName}'");
                    Console.Error.WriteLine("Available apps: " + string.Join(", ",
                        Enum.GetValues<AppType>()
                            .Where(a => a != AppType.Unknown)
                            .Select(a => AppClassifier.AppTypeToString(a))));
                }
                break;

            case "--block-domain" when i + 1 < args.Length:
                engine.Rules.BlockDomain(args[++i]);
                break;

            case "--block-port" when i + 1 < args.Length:
                string portStr = args[++i];
                if (!ushort.TryParse(portStr, out ushort port))
                    Console.Error.WriteLine($"Invalid port number: '{portStr}'");
                else
                    engine.Rules.BlockPort(port);
                break;

            default:
                if (args[i].StartsWith("--"))
                    Console.Error.WriteLine($"Unknown option: '{args[i]}'");
                break;

        }
    }
}

catch (Exception ex)
{
    Console.Error.WriteLine($"Error parsing arguments: {ex.Message}");
    return 1;
}

var cts = new CancellationTokenSource();

Console.CancelKeyPress += (sender, e) =>
{
    Console.WriteLine("\n[Ctrl+C] Shutting down gracefully...");
    e.Cancel = true;
    cts.Cancel();
};

var stopwatch = System.Diagnostics.Stopwatch.StartNew();

try
{
    engine.ProcessFile(inputFile, outputFile, cts.Token);
}
catch(Exception ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    return 1;
}

stopwatch.Stop();
double seconds = stopwatch.Elapsed.TotalSeconds;
long packets = engine.Stats.TotalPackets;
long bytes = engine.Stats.TotalBytes;

Console.WriteLine($"\n═══ Performance ═══");
Console.WriteLine($"Time:         {seconds:F2} seconds");
if (seconds > 0)
{
    Console.WriteLine($"Packets/sec:  {packets / seconds:F0}");
    Console.WriteLine($"Throughput:   {(bytes * 8) / seconds / 1_000_000:F2} Mbps");
}

Console.WriteLine($"\nOutput written to: {outputFile}");
return 0;

