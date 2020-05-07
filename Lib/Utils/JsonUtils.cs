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
        private static JsonSerializerSettings jsonSettings = new JsonSerializerSettings() { DefaultValueHandling = DefaultValueHandling.IgnoreAndPopulate, DateFormatHandling = DateFormatHandling.IsoDateFormat };

        /// <summary>
        /// Serialize an object with Newtonsoft.Json
        /// </summary>
        /// <param name="colObj">The object to serialize</param>
        /// <returns>The bytes of the serialized object</returns>
        public static string Dehydrate(CollectObject colObj)
        {
            return JsonConvert.SerializeObject(colObj, jsonSettings);
        }

        /// <summary>
        /// Deserialize a Collect object from a RawCollectResult
        /// </summary>
        /// <param name="res">The RawCollectResult containing the msgpack serialized object to hydrate.</param>
        /// <returns>An appropriately typed collect object based on the collect result passed in, or null if the RESULT_TYPE is unknown.</returns>
        public static CollectObject? Hydrate(string serialized, RESULT_TYPE type)
        {
            if (serialized == null)
            {
                throw new NullReferenceException();
            }
            switch (type)
            {
                case RESULT_TYPE.CERTIFICATE:
                    return JsonConvert.DeserializeObject<CertificateObject>(serialized, jsonSettings);
                case RESULT_TYPE.FILE:
                    return JsonConvert.DeserializeObject<FileSystemObject>(serialized, jsonSettings);
                case RESULT_TYPE.PORT:
                    return JsonConvert.DeserializeObject<OpenPortObject>(serialized, jsonSettings);
                case RESULT_TYPE.REGISTRY:
                    return JsonConvert.DeserializeObject<RegistryObject>(serialized, jsonSettings);
                case RESULT_TYPE.SERVICE:
                    return JsonConvert.DeserializeObject<ServiceObject>(serialized, jsonSettings);
                case RESULT_TYPE.USER:
                    return JsonConvert.DeserializeObject<UserAccountObject>(serialized, jsonSettings);
                case RESULT_TYPE.GROUP:
                    return JsonConvert.DeserializeObject<GroupAccountObject>(serialized, jsonSettings);
                case RESULT_TYPE.FIREWALL:
                    return JsonConvert.DeserializeObject<FirewallObject>(serialized, jsonSettings);
                case RESULT_TYPE.COM:
                    return JsonConvert.DeserializeObject<ComObject>(serialized, jsonSettings);
                case RESULT_TYPE.LOG:
                    return JsonConvert.DeserializeObject<EventLogObject>(serialized, jsonSettings);
                default:
                    return null;
            }
        }
    }
}
