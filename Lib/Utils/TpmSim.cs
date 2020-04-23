using System.Runtime.InteropServices;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class TpmSim
    {
        [DllImport("Tpm.Dll")]
        static extern int StartTcpServer(int port);
    }
}
