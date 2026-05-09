using Deep_Packet_Analyzer.Types;
using Deep_Packet_Analyzer.Threading;
using Deep_Packet_Analyzer.Tracking;
using Deep_Packet_Analyzer.Rules;
using Deep_Packet_Analyzer.Extractors;
using Deep_Packet_Analyzer.Parsing;

namespace Deep_Packet_Analyzer.Processing
{
    public delegate void PacketOutputCallback(PacketJob job, PacketAction action);
    public class FastPathProcessor
    {
        private readonly int _fpId;
        private readonly ThreadSafeQueue<PacketJob> _inputQueue;
        private readonly ConnectionTracker _connTracker;
        private readonly RuleManager _ruleManager;
        private readonly PacketOutputCallback _outputCallback;

        private long _packetsProcessed;
        private long _packetsForwarded;
        private long _packetsDropped;
        private long _sniExtractions;

        private volatile bool _running;
        private Thread? _thread;

        public FastPathProcessor(int fpId, RuleManager ruleManager, PacketOutputCallback outputCallback)
        {
            _fpId = fpId;
            _inputQueue = new ThreadSafeQueue<PacketJob>(10000);
            _connTracker = new ConnectionTracker(fpId);
            _ruleManager = ruleManager;
            _outputCallback = outputCallback;
        }

        public ThreadSafeQueue<PacketJob> InputQueue => _inputQueue;
        public ConnectionTracker ConnTracker => _connTracker;

        public void Start()
        {
            if (_running) return;
            _running = true;

            _thread = new Thread(Run)
            {
                Name = $"FP-{_fpId}",
                IsBackground = true
            };
            _thread.Start();

            Console.WriteLine($"[FP{_fpId}] Started");
        }

        public void Stop()
        {
            if (!_running) return;
            _running = false;
            _inputQueue.Shutdown();

            _thread?.Join(TimeSpan.FromSeconds(5));
            Console.WriteLine($"[FP{_fpId}] Stopped ({_packetsProcessed} packets)");
        }

        private void Run()
        {
            while (_running)
            {
                var job = _inputQueue.PopWithTimeout(TimeSpan.FromMilliseconds(100));

                    if (job is null)
                {
                    _connTracker.CleanupStale(TimeSpan.FromMinutes(5));
                    continue;
                }

                Interlocked.Increment(ref _packetsProcessed);

                try
                {
                    PacketAction action = ProcessPacket(job);

                    _outputCallback(job, action);

                    if (action == PacketAction.Drop)
                        Interlocked.Increment(ref _packetsDropped);
                    else
                        Interlocked.Increment(ref _packetsForwarded);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[FP{_fpId}] Error processing packet #{job.PacketId}: {ex.Message}");
                    Interlocked.Increment(ref _packetsForwarded);
                    _outputCallback(job, PacketAction.Forward);
                }
                
            }
        }

        private PacketAction ProcessPacket(PacketJob job)
        {
            Connection conn = _connTracker.GetOrCreateConnection(job.TupleObj);

            _connTracker.UpdateConnection(conn, job.Data.Length, isOutbound: true);

            if (job.TupleObj.Protocol == ProtocolConstants.TCP)
                UpdateTcpState(conn, job.TcpFlags);

            if (conn.StateObj == ConnectionState.Blocked)
                return PacketAction.Drop;

            if (conn.StateObj != ConnectionState.Classified && job.PayloadLength > 0)
                InspectPayload(job, conn);

            return CheckRules(job, conn);
        }

        private void InspectPayload(PacketJob job, Connection conn)
        {
            if (job.PayloadLength == 0 || job.PayloadOffset >= job.Data.Length)
                return;

            if (TryExtractSni(job, conn)) return;

            if (TryExtractHttpHost(job, conn)) return;

            if (job.TupleObj.DstPort == 53 || job.TupleObj.SrcPort == 53)
            {
                var domain = DnsExtractor.ExtractQuery(
                    job.Data, job.PayloadOffset, job.PayloadLength);
                if (domain is not null)
                {
                    _connTracker.ClassifyConnection(conn, AppType.DNS, domain);
                    return;
                }
            }

            if (job.TupleObj.DstPort == 80)
                _connTracker.ClassifyConnection(conn, AppType.HTTP, "");
            else if (job.TupleObj.DstPort == 443)
                _connTracker.ClassifyConnection(conn, AppType.HTTPS, "");
        }

        private bool TryExtractSni(PacketJob job, Connection conn)
        {
            if (job.TupleObj.DstPort != 443 && job.PayloadLength < 50)
                return false;

            var sni = SniExtractor.Extract(job.Data, job.PayloadOffset, job.PayloadLength);
            if (sni is not null)
            {
                Interlocked.Increment(ref _sniExtractions);
                AppType app = AppClassifier.SniToAppType(sni);
                _connTracker.ClassifyConnection(conn, app, sni);
                return true;
            }
            return false;
        }

        private bool TryExtractHttpHost(PacketJob job, Connection conn)
        {
            if (job.TupleObj.DstPort != 80) return false;

            var host = HttpHostExtractor.Extract(
                job.Data, job.PayloadOffset, job.PayloadLength);
            if (host is not null)
            {
                AppType app = AppClassifier.SniToAppType(host);
                _connTracker.ClassifyConnection(conn, app, host);
                return true;
            }
            return false;
        }

        private PacketAction CheckRules(PacketJob job, Connection conn)
        {
            var reason = _ruleManager.ShouldBlock(
                job.TupleObj.SrcIp, job.TupleObj.DstPort, conn.AppTypeObj, conn.SniObj);

            if (reason is not null)
            {
                Console.WriteLine($"FP{_fpId} BLOCKED: {reason.Type} {reason.Detail}");
                _connTracker.BlockConnection(conn);
                return PacketAction.Drop;
            }
            return PacketAction.Forward;
        }

        private void UpdateTcpState(Connection conn, byte flags)
        {
            if ((flags & ProtocolConstants.SYN) != 0)
            {

                if ((flags & ProtocolConstants.ACK) != 0)
                    conn.SynAckSeen = true;
                else
                    conn.SynSeen = true;

            }


            if (conn.SynSeen && conn.SynAckSeen && (flags & ProtocolConstants.ACK) != 0)
            {
                if (conn.StateObj == ConnectionState.New)
                    conn.StateObj = ConnectionState.Established;
            }

            if ((flags & ProtocolConstants.FIN) != 0) conn.FinSeen = true;
            if ((flags & ProtocolConstants.RST) != 0) conn.StateObj = ConnectionState.Closed;
            if (conn.FinSeen && (flags & ProtocolConstants.ACK) != 0)
                conn.StateObj = ConnectionState.Closed;
        }

        public long PacketsProcessed => Interlocked.Read(ref _packetsProcessed);
        public long PacketsForwarded => Interlocked.Read(ref _packetsForwarded);
        public long PacketsDropped => Interlocked.Read(ref _packetsDropped);
    }
}
