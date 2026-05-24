using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Deep_Packet_Analyzer.Types
{
    public class PacketJob
    {
        public uint PacketId {  get; set; } // A sequential counter assigned by the reader thread. First packet = 0, second = 1, etc.
        public FiveTuple TupleObj { get; init; } = new(); // five-tuple extracted from this packet's IP and transport headers.
        public byte[] Data { get; init; } = []; // The complete raw packet bytes — the entire Ethernet frame as it appeared in the PCAP file.
        public int EthOffset { get; set; } //  byte offset where the Ethernet header starts in the Data array.
        public int IpOffset { get; set; } // byte offset where the IP header starts.
        public int TransportOffset { get; set; } // byte offset where the TCP or UDP header starts.
        public int PayloadOffset { get; set; } // byte offset where the application payload starts - the actual data the app sent.
        public int PayloadLength { get; set; } // How many bytes of application payload are in this packet.
        public TcpFlags TcpFlags { get; set; } // TCP flags byte extracted from the TCP header during parsing.


        //The original capture timestamps from the PCAP file.
        public uint TsSec { get; set; }
        public uint TsUsec { get; set; }
    }
}
