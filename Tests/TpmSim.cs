using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Tpm2Lib;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Utils
{
    public class TpmSim
    {
        public TpmSim(int Port = 2321)
        {
            this.Port = Port;
        }

        public int Port { get; }

        public static Process GetTpmSimulator()
        {
            return new Process()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "TpmSim\\Simulator.exe",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                }
            };
        }

        [DllImport("Tpm")]
        public static extern int StartTcpServer(int port);

        public void Start()
        {
            Task.Run(() => StartTcpServer(Port));
        }

        public void Stop()
        {
            TcpTpmDevice tpmDevice = new TcpTpmDevice("127.0.0.1", Port);

            if (tpmDevice is TcpTpmDevice)
            {
                tpmDevice.Connect();
                tpmDevice.Close();
            }
        }
    }
}