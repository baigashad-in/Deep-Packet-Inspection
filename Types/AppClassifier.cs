using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Deep_Packet_Analyzer.Types
{
    public static class AppClassifier
    // Maps domain names(from SNI or HTTP Host headers) to AppType enums.
    {

        private static readonly Dictionary<AppType, string[]> AppDomains = new()
        {
            [AppType.YouTube] = new[]
            {
                "youtube.com", "ytimg.com", "youtu.be",
                "googlevideo.com", "yt3.ggpht.com"
            },
            [AppType.Google] = new[]
            {
                "google.com", "gstatic.com", "googleapis.com",
                "google.co.in", "gvt1.com", "googlesyndication.com",
                "googleadservices.com", "googleusercontent.com",
                "doubleclick.net"
            },
            [AppType.Instagram] = new[]
            {
                "instagram.com", "cdninstagram.com"
            },
            [AppType.WhatsApp] = new[]
            {
                "whatsapp.net", "whatsapp.com", "wa.me"
            },
            [AppType.Facebook] = new[]
            {
                "facebook.com", "fbcdn.net", "fb.com", "meta.com"
            },
            [AppType.Twitter] = new[]
            {
                "twitter.com", "twimg.com", "x.com", "t.co"
            },
            [AppType.Netflix] = new[]
            {
                "netflix.com", "nflxvideo.net"
            },
            [AppType.Amazon] = new[]
            {
                "amazon.com", "amazonaws.com", "cloudfront.net"
            },
            [AppType.Microsoft] = new[]
            {
                "microsoft.com", "azure.com", "office.com",
                "live.com", "office365.com"
            },
            [AppType.Apple] = new[]
            {
                "apple.com", "icloud.com"
            },
            [AppType.TikTok] = new[]
            {
                "tiktok.com", "bytedance.com", "tiktokcdn.com"
            },
            [AppType.Spotify] = new[]
            {
                "spotify.com", "scdn.co"
            },
            [AppType.Discord] = new[]
            {
                "discord.com", "discordapp.com", "discord.gg"
            },
            [AppType.GitHub] = new[]
            {
                "github.com", "githubusercontent.com"
            },
            [AppType.Telegram] = new[]
            {
                "telegram.org", "t.me"
            },
            [AppType.Zoom] = new[]
            {
                "zoom.us", "zoom.com"
            },
            [AppType.Cloudflare] = new[]
            {
                "cloudflare.com", "cloudflare.net"
            }
        };


        // Order matters: check specific apps before their parent companies
        private static readonly AppType[] LookupOrder = new[]
        {
            AppType.YouTube,     // Before Google (YouTube is Google subsidiary)
            AppType.Google,
            AppType.Instagram,   // Before Facebook (Instagram is Meta subsidiary)
            AppType.WhatsApp,    // Before Facebook (WhatsApp is Meta subsidiary)
            AppType.Facebook,
            AppType.Twitter,
            AppType.Netflix,
            AppType.Amazon,
            AppType.Microsoft,
            AppType.Apple,
            AppType.TikTok,
            AppType.Spotify,
            AppType.Discord,
            AppType.GitHub,
            AppType.Telegram,
            AppType.Zoom,
            AppType.Cloudflare
        };

        private static bool MatchesDomain(string host, string domain)
        {
            return host.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                   host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);
        }

        public static string AppTypeToString(AppType type)
        {
            return type switch
            {
                AppType.Unknown => "Unknown",
                AppType.Other => "Other",
                AppType.HTTP => "HTTP",
                AppType.HTTPS => "HTTPS",
                AppType.DNS => "DNS",
                AppType.TLS => "TLS",
                AppType.QUIC => "QUIC",
                AppType.Google => "Google",
                AppType.Facebook => "Facebook",
                AppType.YouTube => "YouTube",
                AppType.Twitter => "Twitter/X",
                AppType.Instagram => "Instagram",
                AppType.Netflix => "Netflix",
                AppType.Amazon => "Amazon",
                AppType.Microsoft => "Microsoft",
                AppType.Apple => "Apple",
                AppType.WhatsApp => "WhatsApp",
                AppType.Telegram => "Telegram",
                AppType.TikTok => "TikTok",
                AppType.Spotify => "Spotify",
                AppType.Zoom => "Zoom",
                AppType.Discord => "Discord",
                AppType.GitHub => "GitHub",
                AppType.Cloudflare => "Cloudflare",
                _ => "Unknown"
            };
        }

        public static AppType SniToAppType(string sni)
        // Classify an SNI hostname into an app category.
        // Called every time we extract an SNI from a TLS Client Hello.
        {
            if (string.IsNullOrEmpty(sni)) return AppType.Unknown;

            foreach (var appType in LookupOrder)
            {
                foreach (var domain in AppDomains[appType])
                {
                    if (MatchesDomain(sni, domain))
                        return appType;
                }
            }

            return AppType.Other;
            // If SNI is present but doesn't match any known pattern,
            // we at least know it's HTTPS traffic (it had a TLS Client Hello).
        }

        public static bool IsMoreSpecific(AppType newType, AppType currentType)
        {
            if (IsAppSpecific(currentType)) return false;
            return IsAppSpecific(newType);
        }

        public static bool IsAppSpecific(AppType type)
        {
            return type switch
            {
                AppType.Unknown => false,
                AppType.Other => false,
                AppType.HTTP => false,
                AppType.HTTPS => false,
                AppType.DNS => false,
                AppType.TLS => false,
                AppType.QUIC => false,
                _ => true
            };
        }
    }
}
