using Deep_Packet_Analyzer.Types;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Net;

namespace Deep_Packet_Analyzer.Rules
{

    public record BlockReason(string Type, string Detail);
    public class RuleManager
    {
        private readonly ReaderWriterLockSlim _ipLock = new();
        private readonly HashSet<uint> _blockedIps = new();

        private readonly ReaderWriterLockSlim _appLock = new();
        private readonly HashSet<AppType> _blockedApps = new();

        private readonly ReaderWriterLockSlim _domainLock = new();
        private readonly HashSet<string> _blockedDomains = new();
        private readonly List<string> _domainPatterns = new();

        private readonly ReaderWriterLockSlim _portLock = new();
        private readonly HashSet<ushort> _blockedPorts = new();

        public void BlockIp(string ip)
        {
            if (!IPAddress.TryParse(ip, out _))
            {
                Console.Error.WriteLine($"[RuleManager] Invalid IP, not blocking: {ip}");
                return;
            }
            uint parsed = ParseIp(ip);
            _ipLock.EnterWriteLock();
            try { _blockedIps.Add(parsed); }
            finally { _ipLock.ExitWriteLock(); }
            Console.WriteLine($"[RuleManager] Blocked IP: {ip}");
        }

        public void UnblockIp(string ip)
        {
            if (!IPAddress.TryParse(ip, out _))
            {
                Console.Error.WriteLine($"[RuleManager] Invalid IP, cannot unblock: {ip}");
                return;
            }
            uint parsed = ParseIp(ip);
            _ipLock.EnterWriteLock();
            try { _blockedIps.Remove(parsed); }
            finally { _ipLock.ExitWriteLock(); }
        }

        public bool IsIpBlocked(uint ip)
        {
            _ipLock.EnterReadLock();
            try { return _blockedIps.Contains(ip); }
            finally { _ipLock.ExitReadLock(); }
        }

        public void BlockApp(AppType app)
        {
            _appLock.EnterWriteLock();
            try { _blockedApps.Add(app); }
            finally { _appLock.ExitWriteLock(); }
            Console.WriteLine($"[RuleManager] Blocked app: {AppClassifier.AppTypeToString(app)}");
        }

        public bool IsAppBlocked(AppType app)
        {
            _appLock.EnterReadLock();
            try { return _blockedApps.Contains(app); }
            finally { _appLock.ExitReadLock(); }
        }

        public void BlockDomain(string domain)
        {
            _domainLock.EnterWriteLock();
            try
            {
                if (domain.Contains('*'))
                    _domainPatterns.Add(domain);
                else
                    _blockedDomains.Add(domain);
            }
            finally { _domainLock.ExitWriteLock(); }
            Console.WriteLine($"[RuleManager] Blocked domain: {domain}");
        }

        public bool IsDomainBlocked(string domain)
        {
            _domainLock.EnterReadLock();
            try
            {
                if (_blockedDomains.Contains(domain)) return true;

                string lower = domain.ToLowerInvariant();
                foreach (var pattern in _domainPatterns)
                {
                    if (DomainMatchesPattern(lower, pattern.ToLowerInvariant()))
                        return true;
                }
                return false;
            }
            finally { _domainLock.ExitReadLock(); }
        }

        private static bool DomainMatchesPattern(string domain, string pattern)
        {
            if (pattern.Length >= 2 && pattern[0] == '*' && pattern[1] == '.')
            {
                string suffix = pattern[1..];
                if (domain.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                    return true;
                if (domain.Equals(pattern[2..], StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        public void BlockPort(ushort port)
        {
            _portLock.EnterWriteLock();
            try { _blockedPorts.Add(port); }
            finally { _portLock.ExitWriteLock(); }
        }

        public bool IsPortBlocked(ushort port)
        {
            _portLock.EnterReadLock();
            try { return _blockedPorts.Contains(port); }
            finally { _portLock.ExitReadLock(); }
        }

        public BlockReason? ShouldBlock(uint srcIp, ushort dstPort, AppType app, string domain)
        {
            if (IsIpBlocked(srcIp))
                return new BlockReason("IP", FiveTuple.IpToString(srcIp));

            if (IsPortBlocked(dstPort))
                return new BlockReason("Port", dstPort.ToString());

            if (IsAppBlocked(app))
                return new BlockReason("App", AppClassifier.AppTypeToString(app));

            if (!string.IsNullOrEmpty(domain) && IsDomainBlocked(domain))
                return new BlockReason("Domain", domain);

            return null;
        }

        public static uint ParseIp(string ip)
        {
            if (!IPAddress.TryParse(ip, out var addr))
            {
                Console.Error.WriteLine($"[RuleManager] Invalid IP address: {ip}");
                return 0;
            }

            byte[] bytes = addr.GetAddressBytes();
            return (uint)(bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24));
        }
    }
}
