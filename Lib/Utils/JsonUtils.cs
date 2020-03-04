using AttackSurfaceAnalyzer.Objects;
using Utf8Json;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class JsonUtils
    {
        public static byte[] Dehydrate(CollectObject colObj)
        {
            if (colObj == null)
            {
                return null;
            }

            switch (colObj)
            {
                case CertificateObject certificateObject:
                    return JsonSerializer.Serialize(certificateObject);
                case FileSystemObject fileSystemObject:
                    return JsonSerializer.Serialize(fileSystemObject);
                case OpenPortObject openPortObject:
                    return JsonSerializer.Serialize(openPortObject);
                case RegistryObject registryObject:
                    return JsonSerializer.Serialize(registryObject);
                case ServiceObject serviceObject:
                    return JsonSerializer.Serialize(serviceObject);
                case UserAccountObject userAccountObject:
                    return JsonSerializer.Serialize(userAccountObject);
                case GroupAccountObject groupAccountObject:
                    return JsonSerializer.Serialize(groupAccountObject);
                case FirewallObject firewallObject:
                    return JsonSerializer.Serialize(firewallObject);
                case ComObject comObject:
                    return JsonSerializer.Serialize(comObject);
                case EventLogObject eventLogObject:
                    return JsonSerializer.Serialize(eventLogObject);
                default:
                    return null;
            }
        }
    }
}
