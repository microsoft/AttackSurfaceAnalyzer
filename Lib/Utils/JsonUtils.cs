using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using System;
using Utf8Json;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class JsonUtils
    {
        public static byte[] Dehydrate(CollectObject colObj)
        {
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
                    return JsonSerializer.Serialize(colObj);
            }
        }

        /// <summary>
        /// Deserialize a Collect object from a RawCollectResult
        /// </summary>
        /// <param name="res">The RawCollectResult containing the JsonSerialized object to hydrate.</param>
        /// <returns>An appropriately typed collect object based on the collect result passed in, or null if the RESULT_TYPE is unknown.</returns>
        public static CollectObject Hydrate(byte[] bytes, RESULT_TYPE type)
        {
            if (bytes == null)
            {
                throw new NullReferenceException();
            }
            switch (type)
            {
                case RESULT_TYPE.CERTIFICATE:
                    return JsonSerializer.Deserialize<CertificateObject>(bytes);
                case RESULT_TYPE.FILE:
                    return JsonSerializer.Deserialize<FileSystemObject>(bytes);
                case RESULT_TYPE.PORT:
                    return JsonSerializer.Deserialize<OpenPortObject>(bytes);
                case RESULT_TYPE.REGISTRY:
                    return JsonSerializer.Deserialize<RegistryObject>(bytes);
                case RESULT_TYPE.SERVICE:
                    return JsonSerializer.Deserialize<ServiceObject>(bytes);
                case RESULT_TYPE.USER:
                    return JsonSerializer.Deserialize<UserAccountObject>(bytes);
                case RESULT_TYPE.GROUP:
                    return JsonSerializer.Deserialize<GroupAccountObject>(bytes);
                case RESULT_TYPE.FIREWALL:
                    return JsonSerializer.Deserialize<FirewallObject>(bytes);
                case RESULT_TYPE.COM:
                    return JsonSerializer.Deserialize<ComObject>(bytes);
                case RESULT_TYPE.LOG:
                    return JsonSerializer.Deserialize<EventLogObject>(bytes);
                default:
                    return null;
            }
        }
    }
}
