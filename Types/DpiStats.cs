using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Deep_Packet_Analyzer.Types
{
    public class DpiStats
    // Global statistics shared across all threads.
    // Multiple threads update these simultaneously, so we need thread safety.
    {
        private long _totalPackets;
        private long _totalBytes;
        private long _forwardedPackets;
        private long _droppedPackets;
        private long _tcpPackets;
        private long _udpPackets;
        public void IncrementTotalPackets() => Interlocked.Increment(ref _totalPackets); // Interlocked.Increment atomically does: read value, add 1, write back.
        // "ref" passes the field by reference so Interlocked can modify it directly.
        // No other thread can read a half-written value or lose an increment.
        public void AddTotalBytes(long bytes) => Interlocked.Add(ref _totalBytes, bytes); // Interlocked.Add atomically adds an arbitrary amount.
        public void IncrementForwarded() => Interlocked.Increment(ref _forwardedPackets);
        public void IncrementDropped() => Interlocked.Increment(ref _droppedPackets);
        public void IncrementTcp() => Interlocked.Increment(ref _tcpPackets);
        public void IncrementUdp() => Interlocked.Increment(ref _udpPackets);
        public long TotalPackets => Interlocked.Read(ref _totalPackets); // Interlocked.Read guarantees we get a consistent 64-bit value.
        // On 32-bit systems, reading a 64-bit value isn't atomic — you could
        // read the low 32 bits from before an update and the high 32 bits from after.
        // Interlocked.Read prevents this "torn read" problem.


        public long TotalBytes => Interlocked.Read(ref _totalBytes);
        public long ForwardedPackets => Interlocked.Read(ref _forwardedPackets);

        public long DroppedPackets => Interlocked.Read(ref _droppedPackets);
        public long TcpPackets => Interlocked.Read(ref _tcpPackets);
        public long UdpPackets => Interlocked.Read(ref _udpPackets);
    }
}
