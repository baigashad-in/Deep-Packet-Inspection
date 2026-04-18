using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Deep_Packet_Analyzer.Types
{
    public enum AppType
    {
        Unknown = 0,
        HTTP,
        HTTPS,
        DNS,
        TLS,
        QUIC,
        Google,
        Facebook,
        YouTube,
        Twitter,
        Instagram,
        Netflix,
        Amazon,
        Microsoft,
        Apple,
        WhatsApp,
        Telegram,
        TikTok,
        Spotify,
        Zoom,
        Discord,
        GitHub,
        Cloudflare
    }

    public enum ConnectionState
    {
        New,
        Established,
        Classified,
        Blocked,
        Closed
    }

    public enum PacketAction
    {
        Forward,
        Drop,
        Inspect,
        LogOnly
    }
}
