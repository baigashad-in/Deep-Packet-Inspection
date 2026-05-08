using Deep_Packet_Analyzer.Types;
using Deep_Packet_Analyzer.IO;
using Deep_Packet_Analyzer.Parsing;
using Deep_Packet_Analyzer.Threading;
using Deep_Packet_Analyzer.Processing;
using Deep_Packet_Analyzer.Rules;
using System.Text;

namespace Deep_Packet_Analyzer.Engine
{
    public class DpiEngineConfig
    {
        public int NumLoadBalancers { get; set; } = 2;
        public int FpsPerLb { get; set; } = 2;
        public bool Verbose { get; set; }
    }

    public class DpiEngine
    {
        private readonly DpiEngineConfig _config;
        private readonly RuleManager _ruleManager = new();
        private readonly DpiStats _stats = new();

        private FastPathProcessor[] _fps = [];
        private LoadBalancer[] _lbs = [];
        private ThreadSafeQueue<PacketJob>? _outputQueue;

        private volatile bool _running;
        private Thread? _outputThread;

        private BinaryWriter? _outputWriter;
        private readonly object _outputLock = new();

        public DpiEngine(DpiEngineConfig config)
        {
            _config = config;
            int totalFps = config.NumLoadBalancers * config.FpsPerLb;

            Console.WriteLine("╔════════════════════════════════════════╗");
            Console.WriteLine("║           DPI ENGINE v1.0 (C#)         ║");
            Console.WriteLine("╠════════════════════════════════════════╣");
            Console.WriteLine($"║ Load Balancers:    {config.NumLoadBalancers,3}                 ║");
            Console.WriteLine($"║ FPs per LB:        {config.FpsPerLb,3}                 ║");
            Console.WriteLine($"║ Total FP threads:  {totalFps,3}                 ║");
            Console.WriteLine("╚════════════════════════════════════════╝");
        }

        public RuleManager Rules => _ruleManager;

        public bool Initialize()
        {
            int totalFps = _config.NumLoadBalancers * _config.FpsPerLb;
            _outputQueue = new ThreadSafeQueue<PacketJob>(10000);

            void OutputCallback(PacketJob job, PacketAction action)
            {
                if (action == PacketAction.Drop)
                {
                    _stats.IncrementDropped();
                    return;
                }
                _stats.IncrementForwarded();
                _outputQueue.Push(job);
            }

            _fps = new FastPathProcessor[totalFps];
            for (int i = 0; i < totalFps; i++)
                _fps[i] = new FastPathProcessor(i, _ruleManager, OutputCallback);

            _lbs = new LoadBalancer[_config.NumLoadBalancers];
            for (int lb = 0; lb < _config.NumLoadBalancers; lb++)
            {
                int fpStart = lb * _config.FpsPerLb;
                var fpQueues = new ThreadSafeQueue<PacketJob>[_config.FpsPerLb];
                for (int i = 0; i < _config.FpsPerLb; i++)
                    fpQueues[i] = _fps[fpStart + i].InputQueue;

                _lbs[lb] = new LoadBalancer(lb, fpQueues);
            }

            Console.WriteLine("[DPIEngine] Initialized");
            return true;
        }

        public bool ProcessFile(string inputFile, string outputFile)
        {
            Console.WriteLine($"\n[DPIEngine] Processing: {inputFile}");
            Console.WriteLine($"[DPIEngine] Output to: {outputFile}\n");

            _outputWriter = new BinaryWriter(File.Create(outputFile));

            _running = true;
            _outputThread = new Thread(OutputThreadFunc) { IsBackground = true };
            _outputThread.Start();

            foreach (var fp in _fps) fp.Start();
            foreach (var lb in _lbs) lb.Start();

            ReadPackets(inputFile);

            Thread.Sleep(500);

            foreach (var lb in _lbs) lb.Stop();
            foreach (var fp in _fps) fp.Stop();

            _running = false;
            _outputQueue?.Shutdown();
            _outputThread?.Join(TimeSpan.FromSeconds(5));

            _outputWriter?.Dispose();

            Console.WriteLine(GenerateReport());
            Console.WriteLine(GenerateClassificationReport());

            return true;
        }

        private void ReadPackets(string inputFile)
        {
            using var reader = new PcapReader();
            if (!reader.Open(inputFile)) return;

            WriteOutputHeader(reader.GlobalHeader);

            uint packetId = 0;

            while (reader.ReadNextPacket(out var raw))
            {
                var parsed = new ParsedPacket
                {
                    TimestampSec = raw.Header.TsSec,
                    TimestampUsec = raw.Header.TsUsec
                };

                if (!PacketParser.Parse(raw.Data, parsed)) continue;
                if (!parsed.HasIp || (!parsed.HasTcp && !parsed.HasUdp)) continue;

                var job = new PacketJob
                {
                    PacketId = packetId++,
                    TsSec = raw.Header.TsSec,
                    TsUsec = raw.Header.TsUsec,
                    Data = raw.Data,
                    TcpFlags = parsed.TcpFlags,
                    TupleObj = new FiveTuple
                    {
                        SrcIp = RuleManager.ParseIp(parsed.SrcIp),
                        DstIp = RuleManager.ParseIp(parsed.DstIp),
                        SrcPort = parsed.SrcPort,
                        DstPort = parsed.DstPort,
                        Protocol = parsed.Protocol
                    }
                };

                job.IpOffset = 14;
                if (raw.Data.Length > 14)
                {
                    int ipIhl = raw.Data[14] & 0x0F;
                    job.TransportOffset = 14 + ipIhl * 4;

                    if (parsed.HasTcp && raw.Data.Length > job.TransportOffset + 12)
                    {
                        int tcpOff = (raw.Data[job.TransportOffset + 12] >> 4) & 0x0F;
                        job.PayloadOffset = job.TransportOffset + tcpOff * 4;
                    }
                    else if (parsed.HasUdp)
                    {
                        job.PayloadOffset = job.TransportOffset + 8;
                    }

                    if (job.PayloadOffset < raw.Data.Length)
                        job.PayloadLength = raw.Data.Length - job.PayloadOffset;
                }

                _stats.IncrementTotalPackets();
                _stats.AddTotalBytes(raw.Data.Length);
                if (parsed.HasTcp) _stats.IncrementTcp();
                else if (parsed.HasUdp) _stats.IncrementUdp();

                int lbIndex = Math.Abs(job.TupleObj.GetHashCode()) % _lbs.Length;
                _lbs[lbIndex].InputQueue.Push(job);
            }

            Console.WriteLine($"[Reader] Finished: {packetId} packets");
        }

        private void OutputThreadFunc()
        {
            while (_running || !(_outputQueue?.IsEmpty ?? true))
            {
                var job = _outputQueue?.PopWithTimeout(TimeSpan.FromMilliseconds(100));
                if (job is not null)
                    WriteOutputPacket(job);
            }
        }

        private void WriteOutputHeader(PcapGlobalHeader h)
        {
            lock (_outputLock)
            {
                if (_outputWriter is null) return;
                _outputWriter.Write(h.MagicNumber);
                _outputWriter.Write(h.VersionMajor);
                _outputWriter.Write(h.VersionMinor);
                _outputWriter.Write(h.ThisZone);
                _outputWriter.Write(h.SigFigs);
                _outputWriter.Write(h.SnapLen);
                _outputWriter.Write(h.Network);
            }
        }

        private void WriteOutputPacket(PacketJob job)
        {
            lock (_outputLock)
            {
                if (_outputWriter is null) return;
                _outputWriter.Write(job.TsSec);
                _outputWriter.Write(job.TsUsec);
                _outputWriter.Write((uint)job.Data.Length);
                _outputWriter.Write((uint)job.Data.Length);
                _outputWriter.Write(job.Data);
            }
        }

        public string GenerateReport()
        {
            var sb = new StringBuilder();
            sb.AppendLine("\n╔════════════════════════════════════════╗");
            sb.AppendLine("║         DPI ENGINE STATISTICS          ║");
            sb.AppendLine("╠════════════════════════════════════════╣");
            sb.AppendLine($"║ Total Packets:   {_stats.TotalPackets,12}          ║");
            sb.AppendLine($"║ Total Bytes:     {_stats.TotalBytes,12}          ║");
            sb.AppendLine($"║ TCP Packets:     {_stats.TcpPackets,12}          ║");
            sb.AppendLine($"║ UDP Packets:     {_stats.UdpPackets,12}          ║");
            sb.AppendLine($"║ Forwarded:       {_stats.ForwardedPackets,12}          ║");
            sb.AppendLine($"║ Dropped:         {_stats.DroppedPackets,12}          ║");

            long totalFpProcessed = _fps.Sum(fp => fp.PacketsProcessed);
            long totalFpForwarded = _fps.Sum(fp => fp.PacketsForwarded);
            long totalFpDropped = _fps.Sum(fp => fp.PacketsDropped);

            sb.AppendLine("╠════════════════════════════════════════╣");
            sb.AppendLine($"║ FP Processed:    {totalFpProcessed,12}          ║");
            sb.AppendLine($"║ FP Forwarded:    {totalFpForwarded,12}          ║");
            sb.AppendLine($"║ FP Dropped:      {totalFpDropped,12}         ║");
            sb.AppendLine("╚════════════════════════════════════════╝");

            return sb.ToString();
        }

        public string GenerateClassificationReport()
        {
            var appCounts = new Dictionary<AppType, int>();
            foreach (var fp in _fps)
            {
                fp.ConnTracker.ForEach(conn =>
                {
                    if (!appCounts.ContainsKey(conn.AppTypeObj))
                        appCounts[conn.AppTypeObj] = 0;
                    appCounts[conn.AppTypeObj]++;
                });
            }

            var sb = new StringBuilder();
            sb.AppendLine("\n╔════════════════════════════════════════╗");
            sb.AppendLine("║      APPLICATION CLASSIFICATION        ║");
            sb.AppendLine("╠════════════════════════════════════════╣");

            int total = appCounts.Values.Sum();
            foreach (var kv in appCounts.OrderByDescending(kv => kv.Value))
            {
                double pct = total > 0 ? 100.0 * kv.Value / total : 0;
                string name = AppClassifier.AppTypeToString(kv.Key);
                sb.AppendLine($"║ {name,-15} {kv.Value,6} ({pct,5:F1}%)       ║");
            }

            sb.AppendLine("╚════════════════════════════════════════╝");
            return sb.ToString();
        }

    }
}
