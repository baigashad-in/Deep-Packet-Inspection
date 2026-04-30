using System.Buffers.Binary;
using System.Text;

namespace Deep_Packet_Analyzer.Extractors
{
    public static class SniExtractor
    {
        private const byte CONTENT_TYPE_HANDSHAKE = 0x16;
        private const byte HANDSHAKE_CLIENT_HELLO = 0x01;
        private const ushort EXTENSION_SNI = 0x0000;
        private const byte SNI_TYPE_HOSTNAME = 0x00;

        public static bool IsTlsClientHello(byte[] payload, int offset, int length)
        {
            if (length < 9) return false;
            if (payload[offset] != CONTENT_TYPE_HANDSHAKE) return false;

            ushort version = BinaryPrimitives.ReadUInt16BigEndian(
                payload.AsSpan(offset + 1, 2));
            if (version < 0x0300 || version > 0x0304) return false;

            if (payload[offset + 5] != HANDSHAKE_CLIENT_HELLO) return false;

            return true;
        }

        public static string? Extract(byte[] payload, int offset, int length)
        {
            if (!IsTlsClientHello(payload, offset, length)) return null;

            int pos = offset + 5;
            pos += 4;
            pos += 2;
            pos += 32;

            if (pos >= offset + length) return null;
            byte sessionIdLen = payload[pos];
            pos += 1 + sessionIdLen;

            if (pos + 2 > offset + length) return null;
            ushort cipherSuitesLen = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(pos, 2));
            pos += 2 + cipherSuitesLen;


            if (pos >= offset + length) return null;
            byte compressionLen = payload[pos];
            pos += 1 + compressionLen;

            if (pos + 2 > offset + length) return null;
            ushort extensionsLen = BinaryPrimitives.ReadUInt16BigEndian(
                payload.AsSpan(pos, 2));
            pos += 2;

            int extensionsEnd = pos + extensionsLen;
            if (extensionsEnd > offset + length)
                extensionsEnd = offset + length;

            while (pos + 4 <= extensionsEnd)
            {
                ushort extType = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(pos, 2));
                ushort extLen = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(pos + 2, 2));
                pos += 4;

                if (pos + extLen > extensionsEnd) break;

                if (extType == EXTENSION_SNI)
                {
                    if (extLen < 5) break;

                    byte sniType = payload[pos + 2];
                    ushort sniLen = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(pos + 3, 2));

                    if (sniType != SNI_TYPE_HOSTNAME) break;
                    if (sniLen > extLen - 5) break;

                    return Encoding.ASCII.GetString(payload, pos + 5, sniLen);
                }
                pos += extLen;
            }
            return null;
        }
    }

    public static class HttpHostExtractor
    {
        private static readonly string[] HttpMethods = { "GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI" };

        public static bool IsHttpRequest(byte[] payload, int offset, int length)
        {
            if (length < 4) return false;
            string start = Encoding.ASCII.GetString(payload, offset, 4);
            return HttpMethods.Any(m => start.StartsWith(m));
        }

        public static string? Extract(byte[] payload, int offset, int length)
        {
            if (!IsHttpRequest(payload, offset, length)) return null;
            
            string text = Encoding.ASCII.GetString(payload, offset, Math.Min(length, 2048));

            int hostIdx = text.IndexOf("Host:", StringComparison.OrdinalIgnoreCase);
            if (hostIdx < 0) return null;

            int start = hostIdx + 5;
            while (start < text.Length && (text[start] == ' ' || text[start] == '\t'))
                start++;

            int end = text.IndexOfAny(new[] { '\r', '\n' }, start);
            if (end < 0) end = text.Length;

            string host = text[start..end];

            int colonIdx = host.IndexOf(':');
            if (colonIdx > 0) host = host[..colonIdx];

            return host;
        }
    }

    public static class DnsExtractor
    {
        public static bool IsDnsQuery(byte[] payload, int offset, int length)
        {
            if (length < 12) return false;
            if ((payload[offset + 2] & 0x80) != 0) return false;

            ushort qdcount = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(offset + 4, 2));
            return qdcount > 0;
        }

        public static string? ExtractQuery(byte[] payload, int offset, int length)
        {
            if (!IsDnsQuery(payload, offset, length)) return null;

            int pos = offset + 12;
            var domain = new StringBuilder();
            
            while (pos < offset + length)
            {
                byte labelLen = payload[pos];

                if (labelLen == 0) break;
                if (labelLen > 63) break;

                pos++;
                if (pos + labelLen > offset + length) break;

                if (domain.Length > 0) domain.Append('.');
                domain.Append(Encoding.ASCII.GetString(payload, pos, labelLen));
                pos += labelLen;
            }
            return domain.Length > 0 ? domain.ToString() : null;
        }
    }

}
