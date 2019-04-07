using Microsoft.ApplicationInsights.Channel;
using Microsoft.ApplicationInsights.Extensibility;

namespace AttackSurfaceAnalyzer.Utils
{

    class StripIpFilter : ITelemetryProcessor
    {

        private ITelemetryProcessor Next { get; set; }

        public StripIpFilter(ITelemetryProcessor next)
        {
            this.Next = next;
        }

        public void Process(ITelemetry item)
        {
            ModifyItem(item);

            this.Next.Process(item);
        }

        // Example: replace with your own modifiers.
        private void ModifyItem(ITelemetry item)
        {
            item.Context.Location.Ip = "1.1.1.1";
        }
    }

}