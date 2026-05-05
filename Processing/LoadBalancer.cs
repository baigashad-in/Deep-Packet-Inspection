using Deep_Packet_Analyzer.Types;
using Deep_Packet_Analyzer.Threading;

namespace Deep_Packet_Analyzer.Processing
{
    public class LoadBalancer
    {
        private readonly int _lbId;
        private readonly ThreadSafeQueue<PacketJob> _inputQueue;
        private readonly ThreadSafeQueue<PacketJob>[] _fpQueues;

        private long _packetsReceived;
        private long _packetsDispatched;

        private volatile bool _running;
        private Thread? _thread;

        public LoadBalancer(int lbId, ThreadSafeQueue<PacketJob>[] fpQueues)
        {
            _lbId = lbId;
            _fpQueues = fpQueues;
            _inputQueue = new ThreadSafeQueue<PacketJob>(10000);
        }

        public ThreadSafeQueue<PacketJob> InputQueue => _inputQueue;

        public void Start()
        {
            if (_running) return;
            _running = true;

            _thread = new Thread(Run)
            {
                Name = $"LB-{_lbId}",
                IsBackground = true
            };
            _thread.Start();

            Console.WriteLine($"[LB{_lbId}] Started (serving {_fpQueues.Length} FPs)");
        }

        public void Stop()
        {
            if (!_running) return;
            _running = false;
            _inputQueue.Shutdown();

            _thread?.Join(TimeSpan.FromSeconds(5));
            Console.WriteLine($"[LB{_lbId}] Stopped");
        }

        private void Run()
        {
            while (_running)
            {
                var job = _inputQueue.PopWithTimeout(TimeSpan.FromMilliseconds(100));
                if (job is null) continue;

                Interlocked.Increment(ref _packetsReceived);

                int fpIndex = SelectFp(job.TupleObj);
                _fpQueues[fpIndex].Push(job);

                Interlocked.Increment(ref _packetsDispatched);
            }
        }

        private int SelectFp(FiveTuple tuple)
        {
            return Math.Abs(tuple.GetHashCode()) % _fpQueues.Length;
        }

        public long PacketsReceived => Interlocked.Read(ref _packetsReceived);
    }
}
