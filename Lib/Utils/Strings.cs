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
        // Default locale
        static readonly ResourceManager rm = new ResourceManager("AttackSurfaceAnalyzer.Properties.Resources", Assembly.GetEntryAssembly());
    }
}
