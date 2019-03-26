using AttackSurfaceAnalyzer.ObjectTypes;

namespace AttackSurfaceAnalyzer.Collectors
{
    public abstract class BaseMonitor : PlatformRunnable
    {
        protected string runId = null;

        protected RUN_STATUS _running = RUN_STATUS.NOT_STARTED;

        public abstract void Start();

        public abstract void Stop();

        public abstract bool CanRunOnPlatform();

        public RUN_STATUS RunStatus()
        {
            return _running;
        }

        public BaseMonitor()
        {

        }
    }
}