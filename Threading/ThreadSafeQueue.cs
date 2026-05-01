using System.Collections.Concurrent;


namespace Deep_Packet_Analyzer.Threading
{
    public class ThreadSafeQueue<T>
    {
        private readonly BlockingCollection<T> _collection;

        public ThreadSafeQueue(int maxSize = 10000)
        {
            _collection = new BlockingCollection<T>(
                new ConcurrentQueue<T>(),
                maxSize
                );
        }

        public void Push(T item)
        {
            try
            {
                _collection.Add(item);
            }
            catch (InvalidOperationException)
            {
                // Queue was shut down — expected during graceful shutdown.
                // Item is silently dropped.
                // Logging it would spam the console during every shutdown.
            }
        }

        public bool TryPush(T item)
        {
            return _collection.TryAdd(item);
        }

        public T? Pop()
        {
            try
            {
                return _collection.Take();
            }
            catch (InvalidOperationException)
            {
                return default;
            }
        }
        public T? PopWithTimeout(TimeSpan timeout)
        {
            if (_collection.TryTake(out T? item, timeout))
                return item;
            return default;
        }

        public bool IsEmpty => _collection.Count == 0;
        public int Count => _collection.Count;

        public void Shutdown()
        {
            _collection.CompleteAdding();
        }

        public bool IsCompleted => _collection.IsAddingCompleted;
    }
}
