using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Utils
{
    public class TpmSim
    {
        [DllImport("Tpm")]
        public static extern int StartTcpServer(int port);

        private Task task;
        public int Port { get; }

        public void StartSimulator(int port = 2321)
        {
            task = Task.Run(() => StartTcpServer(port));
        }

        public void StopSimulator()
        {
            // TODO: Send "TPM_STOP" to the TPM Simulator
        }

        public TpmSim(int Port = 2321)
        {
            this.Port = Port;
        }

    }
}