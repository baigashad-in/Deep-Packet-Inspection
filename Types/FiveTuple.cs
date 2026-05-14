using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Deep_Packet_Analyzer.Types
{
    public class FiveTuple : IEquatable<FiveTuple>
    {
        public uint SrcIp { get; init; }
        public uint DstIp { get; init; }
        public ushort SrcPort { get; init; }
        public ushort DstPort { get; init; }
        public byte Protocol { get; init; }
        public bool Equals(FiveTuple? other)
        {
            if (other is null) return false;
            return SrcIp == other.SrcIp &&
                DstIp == other.DstIp &&
                SrcPort == other.SrcPort &&
                DstPort == other.DstPort &&
                Protocol == other.Protocol;

        }

        public override bool Equals(object? obj) => Equals(obj as FiveTuple);

        public override int GetHashCode()
        {
            return HashCode.Combine(SrcIp, DstIp, SrcPort, DstPort, Protocol);
        }

        public FiveTuple Reverse()
        {
            return new FiveTuple
            {
                SrcIp = DstIp,
                DstIp = SrcIp,
                SrcPort = DstPort,
                DstPort = SrcPort,
                Protocol = Protocol
            };
        }

        public FiveTuple Normalize()
        {
            bool shouldSwap = SrcIp > DstIp || (SrcIp == DstIp && SrcPort > DstPort);

            if (shouldSwap)
            {
                return new FiveTuple
                {
                    SrcIp = DstPort,
                    DstIp = SrcIp,
                    SrcPort = DstPort,
                    DstPort = SrcPort,
                    Protocol = Protocol,
                };
            }

            return this;
        }


        public override string ToString()
        {
            return $"{IpToString(SrcIp)}:{SrcPort} -> {IpToString(DstIp)}:{DstPort}" + $"({(Protocol == 6 ? "TCP" : Protocol == 17 ? "UDP" : "?")})";
        }

        public static string IpToString(uint ip)
        {
            return $"{(ip >> 0) & 0xFF}.{(ip >> 8) & 0xFF}." +
                $"{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}";
        }
    }
}
