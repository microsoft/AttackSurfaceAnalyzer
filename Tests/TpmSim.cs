using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Utils
{
    public class TpmSim
    {
        [DllImport("Tpm")]
        public static extern int StartTcpServer(int port);

        Task task;

        public void StartSimulator(int port = 2321)
        {
            task = Task.Run(() => StartTcpServer(port));
        }

        public void StopSimulator()
        {
            // TODO: Stop the simulator
        }
    }
}