using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Tpm2Lib;

namespace AttackSurfaceAnalyzer.Utils
{
    public class TpmSim
    {
        [DllImport("Tpm")]
        public static extern int StartTcpServer(int port);

        public int Port { get; }

        public void Start()
        {
            Task.Run(() => StartTcpServer(Port));
        }

        public void Stop()
        {
            TcpTpmDevice? tpmDevice = new TcpTpmDevice("127.0.0.1", Port);

            if (tpmDevice is TcpTpmDevice)
            {
                tpmDevice.Connect();
                tpmDevice.Close();
            }
        }

        public TpmSim(int Port = 2321)
        {
            this.Port = Port;
        }

    }
}