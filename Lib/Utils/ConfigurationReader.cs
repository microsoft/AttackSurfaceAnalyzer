using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AttackSurfaceAnalyzer.Utils
{
    public class ConfigurationReader
    {
        public static JObject LoadConfigurationFromFile(string filename = "Configuration.json")
        {
            JObject config = null;

            using (StreamReader file = File.OpenText(filename))
            using (JsonTextReader reader = new JsonTextReader(file))
            {
                config = (JObject)JToken.ReadFrom(reader);
            }
            if (config == null)
            {
                throw new InvalidDataException("Unable to read configuration file.");
            }

            return config;
        }
    }
}