using System;
using System.Collections.Generic;
using System.Reflection;
using System.Resources;
using System.Text;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class Strings
    {
//        var names = assembly.GetManifestResourceNames();
        public static string Get(string key)
        {
            return rm.GetString(key);
        }

        public static void Setup()
        {
            rm = new ResourceManager("AttackSurfaceAnalyzer.Properties.Resources", Assembly.GetEntryAssembly());
        }

        // Default locale
        static ResourceManager rm;
    }
}
