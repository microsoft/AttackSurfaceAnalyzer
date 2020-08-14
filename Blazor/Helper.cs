using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Cli
{
    public static class Helper
    {
        public static string GetGlowClass(bool value)
        {
            return value ? "glowRed" : "glowBlue";
        }
    }
}
