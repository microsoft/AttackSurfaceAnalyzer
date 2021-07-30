using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Cli
{
    public static class Helper
    {
        /// <summary>
        /// This class just serves to make a reference type version of the class name to use
        /// </summary>
        public class GlowClass
        {
            public string ClassName { get; set; } = string.Empty;
        }

        public static string GetGlowClass(bool value)
        {
            return value ? "glowBlue" : "glowRed";
        }

        public static void ToggleGlow(Action RefreshCallback, GlowClass Variable, bool GlowType, int Duration = 500)
        {
            Variable.ClassName = GetGlowClass(GlowType);
            RefreshCallback();
            Task.Run(() =>
            {
                WaitAndResetGlow(RefreshCallback, Variable, Duration);
            });
        }

        static void WaitAndResetGlow(Action RefreshCallback, GlowClass Variable, int Duration)
        {
            Task.Delay(Duration).Wait();
            Variable.ClassName = string.Empty;
            RefreshCallback();
        }
    }
}
