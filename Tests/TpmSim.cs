using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Utils
{
    public class TpmSim
    {
        [DllImport("Tpm")]
        public static extern int StartTcpServer(int port);

        private Thread t;
        public int Port { get; }

        public void StartSimulator(int port = 2321)
        {
            t = new Thread(() => StartTcpServer(Port));
        }

        public void StopSimulator()
        {
            t.Abort();
            // TODO: Send "TPM_STOP" to the TPM Simulator?
        }

        public TpmSim(int Port = 2321)
        {
            this.Port = Port;
        }

    }
}