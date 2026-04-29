using System.Buffers.Binary;


namespace Deep_Packet_Analyzer.IO
{
    public struct PcapGlobalHeader
    {
        public uint MagicNumber;
        public ushort VersionMajor;
        public ushort VersionMinor;
        public int ThisZone;
        public uint SigFigs;
        public uint SnapLen;
        public uint Network;
    }

    public struct PcapPacketHeader
    {
        public uint TsSec;
        public uint TsUsec;
        public uint InclLen;
        public uint OrigLen;
    }

    public class RawPacket
    {
        public PcapPacketHeader Header;
        public byte[] Data = [];
    }

    public class PcapReader : IDisposable
    {
        private BinaryReader? _reader;
        private PcapGlobalHeader _header;
        private bool _needsByteSwap;

        private const uint PCAP_MAGIC_NATIVE = 0xa1b2c3d4;
        private const uint PCAP_MAGIC_SWAPPED = 0xd4c3b2a1;

        public bool Open(string filename)
        {
            try
            {
                _reader = new BinaryReader(File.OpenRead(filename));

                _header.MagicNumber = _reader.ReadUInt32();
                _header.VersionMajor = _reader.ReadUInt16();
                _header.VersionMinor = _reader.ReadUInt16();
                _header.ThisZone = _reader.ReadInt32();
                _header.SigFigs = _reader.ReadUInt32();
                _header.SnapLen = _reader.ReadUInt32();
                _header.Network = _reader.ReadUInt32();

                if (_header.MagicNumber == PCAP_MAGIC_NATIVE)
                {
                    _needsByteSwap = false;
                }
                else if (_header.MagicNumber == PCAP_MAGIC_SWAPPED)
                {
                    _needsByteSwap = true;
                    _header.VersionMajor = BinaryPrimitives.ReverseEndianness(_header.VersionMajor);
                    _header.VersionMinor = BinaryPrimitives.ReverseEndianness(_header.VersionMinor);
                    _header.SnapLen = BinaryPrimitives.ReverseEndianness(_header.SnapLen);
                    _header.Network = BinaryPrimitives.ReverseEndianness(_header.Network);
                }
                else
                {
                    Console.Error.WriteLine($"Invalid PCAP magic: 0x{_header.MagicNumber:X8}");
                    return false;
                }

                Console.WriteLine($"Opened PCAP: {filename}");
                Console.WriteLine($" Version: {_header.VersionMajor}.{_header.VersionMinor}");
                Console.WriteLine($" SnapLen: {_header.SnapLen} bytes");
                Console.WriteLine($" Link type: {_header.Network}" + (_header.Network == 1 ? " (Ethernet)" : ""));

                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error opening PCAP: {ex.Message}");
                return false;
            }
        }

        public bool ReadNextPacket(out RawPacket packet)
        {
            packet = new RawPacket();

            if (_reader is null) return false;

            try
            {
                packet.Header.TsSec = MaybeSwap32(_reader.ReadUInt32());
                packet.Header.TsUsec = MaybeSwap32(_reader.ReadUInt32());
                packet.Header.InclLen = MaybeSwap32(_reader.ReadUInt32());
                packet.Header.OrigLen = MaybeSwap32(_reader.ReadUInt32());

                if (packet.Header.InclLen > _header.SnapLen || packet.Header.InclLen > 65535)
                {
                    Console.Error.WriteLine($"Invalid packet length: {packet.Header.InclLen}");
                    return false;
                }

                packet.Data = _reader.ReadBytes((int)packet.Header.InclLen);

                if (packet.Data.Length < (int)packet.Header.InclLen)
                    return false;

                return true;
            }
            catch (EndOfStreamException)
            {
                return false;
            }
        }

        public PcapGlobalHeader GlobalHeader => _header;

        private uint MaybeSwap32(uint value)
        {
            return _needsByteSwap
                ? BinaryPrimitives.ReverseEndianness(value)
                : value;
        }

        public void Dispose()
        {
            _reader?.Dispose();
            _reader = null;
        }

    }
}