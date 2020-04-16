// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using Newtonsoft.Json;
using System;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class JsonUtils
    {
        /// <summary>
        /// Serialize an object with messagepack
        /// </summary>
        /// <param name="colObj">The object to serialize</param>
        /// <returns>The bytes of the serialized object</returns>
        public static string Dehydrate(CollectObject colObj)
        {
            return JsonConvert.SerializeObject(colObj);
        }

        /// <summary>
        /// Deserialize a Collect object from a RawCollectResult
        /// </summary>
        /// <param name="res">The RawCollectResult containing the msgpack serialized object to hydrate.</param>
        /// <returns>An appropriately typed collect object based on the collect result passed in, or null if the RESULT_TYPE is unknown.</returns>
        public static CollectObject? Hydrate(string bytes, RESULT_TYPE type)
        {
            if (bytes == null)
            {
                throw new NullReferenceException();
            }
            switch (type)
            {
                case RESULT_TYPE.CERTIFICATE:
                    return JsonConvert.DeserializeObject<CertificateObject>(bytes);
                case RESULT_TYPE.FILE:
                    return JsonConvert.DeserializeObject<FileSystemObject>(bytes);
                case RESULT_TYPE.PORT:
                    return JsonConvert.DeserializeObject<OpenPortObject>(bytes);
                case RESULT_TYPE.REGISTRY:
                    return JsonConvert.DeserializeObject<RegistryObject>(bytes);
                case RESULT_TYPE.SERVICE:
                    return JsonConvert.DeserializeObject<ServiceObject>(bytes);
                case RESULT_TYPE.USER:
                    return JsonConvert.DeserializeObject<UserAccountObject>(bytes);
                case RESULT_TYPE.GROUP:
                    return JsonConvert.DeserializeObject<GroupAccountObject>(bytes);
                case RESULT_TYPE.FIREWALL:
                    return JsonConvert.DeserializeObject<FirewallObject>(bytes);
                case RESULT_TYPE.COM:
                    return JsonConvert.DeserializeObject<ComObject>(bytes);
                case RESULT_TYPE.LOG:
                    return JsonConvert.DeserializeObject<EventLogObject>(bytes);
                default:
                    return null;
            }
        }
    }
}
