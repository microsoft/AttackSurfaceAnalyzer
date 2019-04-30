using System;
using System.Collections.Generic;
using System.Reflection;
using System.Resources;
using System.Text;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class Strings
    {
        public static string Get(string key)
        {
            return rm.GetString(key);
        }

        public static void Setup()
        {
        }

        // Default locale
        static ResourceManager rm = new ResourceManager("AttackSurfaceAnalyzer.Properties.Resources", Assembly.GetEntryAssembly());
    }
}
