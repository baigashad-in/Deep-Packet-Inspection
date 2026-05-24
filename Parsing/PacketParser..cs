using Deep_Packet_Analyzer.Types;
using System.Buffers.Binary;


namespace Deep_Packet_Analyzer.Parsing
{
    public static class ProtocolConstants
    {
        public const byte ICMP = 1;
        public const byte TCP = 6;
        public const byte UDP = 17;

        public const ushort EtherTypeIPv4 = 0x0800;
    }

    public static class PacketParser
    {
        public static bool Parse(byte[] data, ParsedPacket parsed)
        {
            int offset = 0;

            if (!ParseEthernet(data, parsed, ref offset))
                return false;

            if (parsed.EtherType == ProtocolConstants.EtherTypeIPv4)
            {
                if (!ParseIPv4(data, parsed, ref offset))
                    return false;
                if (parsed.Protocol == ProtocolConstants.TCP)
                {
                    if (!ParseTcp(data, parsed, ref offset))
                        return false;
                }
                else if (parsed.Protocol == ProtocolConstants.UDP)
                {
                    if (!ParseUdp(data, parsed, ref offset))
                        return false;
                }
            }

            if (offset < data.Length)
            {
                parsed.PayloadOffset = offset;
                parsed.PayloadLength = data.Length - offset;
            }

            return true;
        }

        private static bool ParseEthernet(byte[] data, ParsedPacket parsed, ref int offset)
        {
            const int ETH_HEADER_LEN = 14;
            if (data.Length < ETH_HEADER_LEN)
                return false;

            parsed.DstMac = MacToString(data, 0);
            parsed.SrcMac = MacToString(data, 6);
            parsed.EtherType = BinaryPrimitives.ReadUInt16BigEndian(
                data.AsSpan(12, 2));

            offset = ETH_HEADER_LEN;
            return true;
        }

        private static bool ParseIPv4(byte[] data, ParsedPacket parsed, ref int offset)
        {
            const int MIN_IP_HEADER_LEN = 20;
            if (data.Length < offset + MIN_IP_HEADER_LEN)
                return false;
            byte versionIhl = data[offset];
            parsed.IpVersion = (byte)((versionIhl >> 4) & 0x0F);
            byte ihl = (byte)(versionIhl & 0x0F);

            if (parsed.IpVersion != 4) return false;

            int ipHeaderLen = ihl * 4;
            if (ipHeaderLen < MIN_IP_HEADER_LEN || data.Length < offset + ipHeaderLen)
                return false;

            parsed.Ttl = data[offset + 8];
            parsed.Protocol = data[offset + 9];
            parsed.SrcIp = IpBytesToString(data, offset + 12);
            parsed.DstIp = IpBytesToString(data, offset + 16);

            parsed.HasIp = true;
            offset += ipHeaderLen;
            return true;
        }


        private static bool ParseTcp(byte[] data, ParsedPacket parsed, ref int offset)
        {
            const int MIN_TCP_HEADER_LEN = 20;
            if (data.Length < offset + MIN_TCP_HEADER_LEN)
                return false;

            parsed.SrcPort = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset, 2));
            parsed.DstPort = BinaryPrimitives.ReadUInt16BigEndian(
                data.AsSpan(offset + 2, 2));
            parsed.SeqNumber = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset + 4, 4));
            parsed.AckNumber = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset + 8, 4));

            byte dataOffset = (byte)((data[offset + 12] >> 4) & 0x0F);
            int tcpHeaderLen = dataOffset * 4;

            parsed.TcpFlags = (TcpFlags)data[offset + 13];

            if (tcpHeaderLen < MIN_TCP_HEADER_LEN || data.Length < offset + tcpHeaderLen)
                return false;

            parsed.HasTcp = true;
            offset += tcpHeaderLen;
            return true;
        }

        private static bool ParseUdp(byte[] data, ParsedPacket parsed, ref int offset)
        {
            const int UDP_HEADER_LEN = 8;
            if (data.Length < offset + UDP_HEADER_LEN)
                return false;

            parsed.SrcPort = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset, 2));
            parsed.DstPort = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset + 2, 2));

            parsed.HasUdp = true;
            offset += UDP_HEADER_LEN;
            return true;
        }
        public static string MacToString(byte[] data, int offset)
        {
            return $"{data[offset]:x2}:{data[offset+1]:x2}:{data[offset+2]:x2}:" +
                $"{data[offset+3]:x2}:{data[offset+4]:x2}:{data[offset+5]:x2}";
        }

        public static string IpBytesToString(byte[] data, int offset)
        {
            return $"{data[offset]}.{data[offset+1]}.{data[offset+2]}.{data[offset+3]}";
        }

        public static string IpToString(uint ip)
        {
            return $"{(ip >> 0) & 0xFF}.{(ip >> 8) & 0xFF}." +
                $"{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}";
        }

        public static string ProtocolToString(byte protocol)
        {
            return protocol switch
            {
                ProtocolConstants.ICMP => "ICMP",
                ProtocolConstants.TCP => "TCP",
                ProtocolConstants.UDP => "UDP",
                _ => $"Unknown({protocol})"
            };
        }

        public static string TcpFlagsToString(TcpFlags flags)
        {
            if (flags == TcpFlags.None) return "none";
            return flags.ToString();
        }
    }
}
