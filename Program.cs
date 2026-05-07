using Deep_Packet_Analyzer.Engine;
using Deep_Packet_Analyzer.Types;

if (args.Length < 2)
{
    Console.WriteLine("Usage: PacketAnalyzer <input.pcap> <output.pcap> [options]");
    Console.WriteLine();
    Console.WriteLine("Options:");
    Console.WriteLine(" --block-ip <ip> Block traffic from source IP");
    Console.WriteLine(" --block-app <app> Block application (YouTube, Facebook, etc.)");
    Console.WriteLine(" --block-domain <dom> Block domain (*.tiktok.com)");
    Console.WriteLine(" --block-port <port> Block destinatin port");
    Console.WriteLine();
    Console.WriteLine("Examples:");
    Console.WriteLine(" DeepPacketAnalyzer capture.pcap filtered.pcap");
    Console.WriteLine(" DeepPacketAnalyzer capture.pcap filtered.pcap --block-app YouTube");
    Console.WriteLine(" DeepPacketAnalyzer capture.pcap filtered.pcap --block-domain \"*.tiktok.com\"");
    return 1;
}

string inputFile = args[0];
string outputFile = args[1];

var config = new DpiEngineConfig
{
    NumLoadBalancers = 2,
    FpsPerLb = 2
};

var engine = new DpiEngine(config);
engine.Initialize();

for (int i = 2; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--block-ip" when i + 1 < args.Length:
            engine.Rules.BlockIp(args[++i]);
            break;

        case "--block-app" when i + 1 < args.Length:
            string appName = args[++i];
            foreach (AppType app in Enum.GetValues<AppType>())
            {
                if (AppClassifier.AppTypeToString(app)
                    .Equals(appName, StringComparison.OrdinalIgnoreCase))
                {
                    engine.Rules.BlockApp(app);
                    break;
                }
            }
            break;

        case "--block-domain" when i + 1 < args.Length:
            engine.Rules.BlockDomain(args[++i]);
            break;

        case "--block-port" when i + 1 < args.Length:
            if (ushort.TryParse(args[++i], out ushort port))
                engine.Rules.BlockPort(port);
            break;
    }
}

engine.ProcessFile(inputFile, outputFile);

Console.WriteLine($"\nOutput written to: {outputFile}");
return 0;

