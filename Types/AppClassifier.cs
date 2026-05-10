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
                AppType.Unknown => "Unknown",
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
        public static AppType SniToAppType(string sni)
        // Classify an SNI hostname into an app category.
        // Called every time we extract an SNI from a TLS Client Hello.
        {
            if (string.IsNullOrEmpty(sni)) return AppType.Unknown;
            // Guard clause — empty string means no SNI was found.
            string lower = sni.ToLowerInvariant();
            // Normalize to lowercase. DNS names are case-insensitive per RFC 4343.
            if (lower.Contains("youtube") || lower.Contains("ytimg") || lower.Contains("youtu.be"))
                return AppType.YouTube;
            // Contains() does a substring search.
            if (lower.Contains("google") || lower.Contains("gstatic") || lower.Contains("googleapis"))
                return AppType.Google;
            if (lower.Contains("instagram") || lower.Contains("cdninstagram"))
                return AppType.Instagram;
            if (lower.Contains("whatsapp") || lower.Contains("wa.me"))
                return AppType.WhatsApp;
            if (lower.Contains("facebook") || lower.Contains("fbcdn") || lower.Contains("fb.com") || lower.Contains("meta.com"))
                return AppType.Facebook;
            if (lower.Contains("twitter") || lower.Contains("twimg") || lower.Contains("x.com") || lower.Contains("t.co"))
                return AppType.Twitter;
            if (lower.Contains("netflix") || lower.Contains("nflxvideo"))
                return AppType.Netflix;
            if (lower.Contains("amazon") || lower.Contains("amazonaws") || lower.Contains("cloudfront"))
                return AppType.Amazon;
            if (lower.Contains("microsoft") || lower.Contains("azure") || lower.Contains("office") || lower.Contains("live.com"))
                return AppType.Microsoft;
            if (lower.Contains("apple") || lower.Contains("icloud"))
                return AppType.Apple;
            if (lower.Contains("tiktok") || lower.Contains("bytedance"))
                return AppType.TikTok;
            if (lower.Contains("spotify") || lower.Contains("scdn.co"))
                return AppType.Spotify;
            if (lower.Contains("discord") || lower.Contains("discordapp"))
                return AppType.Discord;
            if (lower.Contains("github") || lower.Contains("githubusercontent"))
                return AppType.GitHub;
            if (lower.Contains("telegram") || lower.Contains("t.me"))
                return AppType.Telegram;
            if (lower.Contains("zoom"))
                return AppType.Zoom;
            if (lower.Contains("cloudflare"))
                return AppType.Cloudflare;

            return AppType.HTTPS;
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
