using System;
using System.Collections.Generic;
using System.Reflection;
using System.Resources;
using System.Text;

namespace AttackSurfaceAnalyzer.Utils
{
    public class Strings
    {
//        var names = assembly.GetManifestResourceNames();
        public string Get(string key)
        {
            return rm.GetString(key);
        }
        ResourceManager rm;
        // Default locale
        public Strings()
        {
            rm = new ResourceManager("AttackSurfaceAnalyzer.Properties.Resources", Assembly.GetEntryAssembly());
        }
    }
}
