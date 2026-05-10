using Deep_Packet_Analyzer.Types;

namespace Deep_Packet_Analyzer.Tracking
{
    public class ConnectionTracker
    {
        private readonly int _fpId;
        private readonly int _maxConnections;
        private readonly Dictionary<FiveTuple, Connection> _connections = new();

        private int _totalSeen;
        private int _classifiedCount;
        private int _blockedCount;

        public ConnectionTracker(int fpId, int maxConnections = 100000)
        {
            _fpId = fpId;
            _maxConnections = maxConnections;
        }

        public Connection GetOrCreateConnection(FiveTuple tuple)
        {
            if (_connections.TryGetValue(tuple, out var existing))
                return existing;

            if (_connections.Count >= _maxConnections)
                EvictOldest();

            var conn = new Connection
            {
                TupleObj = tuple,
                StateObj = ConnectionState.New,
                FirstSeen = DateTime.UtcNow,
                LastSeen = DateTime.UtcNow
            };

            _connections[tuple] = conn;
            _totalSeen++;
            return conn;
        }

        public Connection? GetConnection(FiveTuple tuple)
        {
            if (_connections.TryGetValue(tuple, out var conn))
                return conn;

            if (_connections.TryGetValue(tuple.Reverse(), out var rev))
                return rev;

            return null;
        }

        public void UpdateConnection(Connection conn, int packetSize, bool isOutbound)
        {
            conn.LastSeen = DateTime.UtcNow;
            if (isOutbound) { conn.PacketsOut++; conn.BytesOut += (ulong)packetSize; }
            else { conn.PacketsIn++; conn.BytesIn += (ulong)packetSize; }
        }

        public void ClassifyConnection(Connection conn, AppType app, string sni)
        {
            if (conn.StateObj != ConnectionState.Classified)
            {
                conn.AppTypeObj = app;
                conn.SniObj = sni;
                conn.StateObj = ConnectionState.Classified;
                _classifiedCount++;
            }
            else if (AppClassifier.IsMoreSpecific(app, conn.AppTypeObj))
            {
                conn.AppTypeObj = app;
                if (!string.IsNullOrEmpty(sni))
                    conn.SniObj = sni;
            }


        }

        public void BlockConnection(Connection conn)
        {
            if (conn.StateObj != ConnectionState.Blocked)
            {
                conn.StateObj = ConnectionState.Blocked;
                conn.ActionObj = PacketAction.Drop;
                _blockedCount++;
            }
        }

        public int CleanupStale(TimeSpan timeout)
        {
            var now = DateTime.UtcNow;
            var staleKeys = _connections
                .Where(kv => (now -kv.Value.LastSeen) > timeout || kv.Value.StateObj == ConnectionState.Closed)
                .Select(kv => kv.Key)
                .ToList();

            foreach (var key in staleKeys)
                _connections.Remove(key);

            return staleKeys.Count;
        }

        private void EvictOldest()
        {
            if (_connections.Count == 0) return;

            var oldest = _connections.MinBy(kv => kv.Value.LastSeen);
            if (oldest.Key is not null)
                _connections.Remove(oldest.Key);
        }

        public void ForEach(Action<Connection> callback)
        {
            foreach (var conn in _connections.Values)
                callback(conn);
        }

        public int ActiveCount => _connections.Count;
        public int TotalSeen => _totalSeen;
        public int ClassifiedCount => _classifiedCount;
        public int BlockedCount => _blockedCount;
    }
}
