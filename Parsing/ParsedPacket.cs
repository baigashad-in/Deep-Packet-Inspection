using Deep_Packet_Analyzer.Types;

namespace Deep_Packet_Analyzer.Parsing
{
    public class ParsedPacket
    {
        public uint TimestampSec { get; set; }
        public uint TimestampUsec { get; set; }

        public string SrcMac { get; set; } = "";
        public string DstMac { get; set; } = "";
        public ushort EtherType { get; set; }

        public bool HasIp { get; set; }
        public byte IpVersion { get; set; }
        public string SrcIp { get; set; } = "";
        public string DstIp { get; set; } = "";
        public byte Protocol { get; set; }
        public byte Ttl { get; set; }

        public bool HasTcp { get; set; }
        public bool HasUdp { get; set; }
        public ushort SrcPort { get; set; }
        public ushort DstPort { get; set; }
        public TcpFlags TcpFlags { get; set; }
        public uint SeqNumber { get; set; }
        public uint AckNumber { get; set; }

        public int PayloadOffset { get; set; }
        public int PayloadLength { get; set; }
    }
}