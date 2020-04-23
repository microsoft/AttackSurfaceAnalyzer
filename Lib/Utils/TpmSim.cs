using System.Runtime.InteropServices;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class TpmSim
    {
        [DllImport("Tpm")]
        static extern int StartTcpServer(int port);
    }
}
