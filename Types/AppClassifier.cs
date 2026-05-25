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
        public static string AppTypeToString(AppType type)
        // Convert enum to display name.
        {
            return type switch
            {
                AppType.Unknown => "Other",
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
                _ => "Unknown" // _ is the discard pattern — matches anything not listed above.

            };
        }

        private static bool MatchesDomain(string host, string domain)
        {
            return host.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                   host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);
        }

        public static AppType SniToAppType(string sni)
        // Classify an SNI hostname into an app category.
        // Called every time we extract an SNI from a TLS Client Hello.
        {
            if (string.IsNullOrEmpty(sni)) return AppType.Unknown;

            // YouTube (check before Google — YouTube is a Google subsidiary)
            if (MatchesDomain(sni, "youtube.com") || MatchesDomain(sni, "ytimg.com") ||
                MatchesDomain(sni, "youtu.be") || MatchesDomain(sni, "googlevideo.com") ||
                MatchesDomain(sni, "yt3.ggpht.com"))
                return AppType.YouTube;

            // Google
            if (MatchesDomain(sni, "google.com") || MatchesDomain(sni, "gstatic.com") ||
                MatchesDomain(sni, "googleapis.com") || MatchesDomain(sni, "google.co.in") ||
                MatchesDomain(sni, "gvt1.com") || MatchesDomain(sni, "googlesyndication.com") ||
                MatchesDomain(sni, "googleadservices.com") || MatchesDomain(sni, "googleusercontent.com") ||
                MatchesDomain(sni, "doubleclick.net"))
                return AppType.Google;

            // Instagram (check before Facebook — owned by Meta)
            if (MatchesDomain(sni, "instagram.com") || MatchesDomain(sni, "cdninstagram.com"))
                return AppType.Instagram;

            // WhatsApp (check before Facebook — owned by Meta)
            if (MatchesDomain(sni, "whatsapp.net") || MatchesDomain(sni, "whatsapp.com") ||
                MatchesDomain(sni, "wa.me"))
                return AppType.WhatsApp;

            // Facebook / Meta
            if (MatchesDomain(sni, "facebook.com") || MatchesDomain(sni, "fbcdn.net") ||
                MatchesDomain(sni, "fb.com") || MatchesDomain(sni, "meta.com"))
                return AppType.Facebook;

            // Twitter / X
            if (MatchesDomain(sni, "twitter.com") || MatchesDomain(sni, "twimg.com") ||
                MatchesDomain(sni, "x.com") || MatchesDomain(sni, "t.co"))
                return AppType.Twitter;

            // Netflix
            if (MatchesDomain(sni, "netflix.com") || MatchesDomain(sni, "nflxvideo.net"))
                return AppType.Netflix;

            // Amazon
            if (MatchesDomain(sni, "amazon.com") || MatchesDomain(sni, "amazonaws.com") ||
                MatchesDomain(sni, "cloudfront.net"))
                return AppType.Amazon;

            // Microsoft
            if (MatchesDomain(sni, "microsoft.com") || MatchesDomain(sni, "azure.com") ||
                MatchesDomain(sni, "office.com") || MatchesDomain(sni, "live.com") ||
                MatchesDomain(sni, "office365.com"))
                return AppType.Microsoft;

            // Apple
            if (MatchesDomain(sni, "apple.com") || MatchesDomain(sni, "icloud.com"))
                return AppType.Apple;

            // TikTok
            if (MatchesDomain(sni, "tiktok.com") || MatchesDomain(sni, "bytedance.com") ||
                MatchesDomain(sni, "tiktokcdn.com"))
                return AppType.TikTok;

            // Spotify
            if (MatchesDomain(sni, "spotify.com") || MatchesDomain(sni, "scdn.co"))
                return AppType.Spotify;

            // Discord
            if (MatchesDomain(sni, "discord.com") || MatchesDomain(sni, "discordapp.com") ||
                MatchesDomain(sni, "discord.gg"))
                return AppType.Discord;

            // GitHub
            if (MatchesDomain(sni, "github.com") || MatchesDomain(sni, "githubusercontent.com"))
                return AppType.GitHub;

            // Telegram
            if (MatchesDomain(sni, "telegram.org") || MatchesDomain(sni, "t.me"))
                return AppType.Telegram;

            // Zoom
            if (MatchesDomain(sni, "zoom.us") || MatchesDomain(sni, "zoom.com"))
                return AppType.Zoom;

            // Cloudflare
            if (MatchesDomain(sni, "cloudflare.com") || MatchesDomain(sni, "cloudflare.net"))
                return AppType.Cloudflare;

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
