using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Deep_Packet_Analyzer.Types
{
    public class Connection
    {
        public FiveTuple TupleObj { get; init; } = new(); // five-tuple that identifies which connection this object belongs to.

        public ConnectionState StateObj { get; set; } = ConnectionState.New; // Where this connection is in its lifecycle.

        public AppType AppTypeObj { get; set; } = AppType.Unknown; //Which application this traffic belongs to, as determined by DPI.

        public string SniObj { get; set; } = string.Empty; // The actual hostname extracted from the packet. For example "www.youtube.com".

        //Count how many packets and bytes have flowed in each direction.
        public ulong PacketsIn { get; set; }
        public ulong PacketsOut { get; set; }
        public ulong BytesIn { get; set; }
        public ulong BytesOut { get; set; }
        public DateTime FirstSeen { get; set; } = DateTime.UtcNow; // When the first packet of this connection arrived.
        public DateTime LastSeen { get; set; } // When the most recent packet arrived. Updated on every packet.
        public PacketAction ActionObj { get; set; } = PacketAction.Forward; // Default action to Forward. Because the default policy is "allow unless a rule says otherwise."

        // TCP handshake tracking
        public bool SynSeen { get; set; } // Has the client's SYN packet been seen?
        public bool SynAckSeen { get; set; } // Has the server's SYN+ACK response been seen?
        public bool FinSeen { get; set; } // Has either side sent a FIN (finish) packet?

    }
}
