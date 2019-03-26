using AttackSurfaceAnalyzer.ObjectTypes;

namespace AttackSurfaceAnalyzer.Collectors
{
    public abstract class BaseCollector : PlatformRunnable
    {
        protected string runId = null;

        private RUN_STATUS _running = RUN_STATUS.NOT_STARTED;

        protected int _numCollected = 0;

        public abstract void Execute();

        public abstract bool CanRunOnPlatform();

        public RUN_STATUS IsRunning()
        {
            return _running;
        }

        public void Start()
        {
            _running = RUN_STATUS.RUNNING;

        }

        public void Stop()
        {
            _running = RUN_STATUS.COMPLETED;
        }

        public int NumCollected()
        {
            return _numCollected;
        }

        public BaseCollector()
        {
            
        }
    }
}