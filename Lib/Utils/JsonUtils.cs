// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Newtonsoft.Json;
using System;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using Tpm2Lib;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Utils
{
    public static class JsonUtils
    {
        static JsonUtils()
        {
            TypeDescriptor.AddAttributes(typeof((TpmAlgId, uint)), new TypeConverterAttribute(typeof(TpmPcrTupleConverter<TpmAlgId, uint>)));
        }

        /// <summary>
        ///     Serialize an object with Newtonsoft.Json
        /// </summary>
        /// <param name="colObj"> The object to serialize </param>
        /// <returns> The bytes of the serialized object </returns>
        public static string Dehydrate(CollectObject colObj)
        {
            return JsonConvert.SerializeObject(colObj, jsonSettings);
        }

        /// <summary>
        ///     Deserialize a Collect object from a RawCollectResult
        /// </summary>
        /// <param name="res"> The RawCollectResult containing the msgpack serialized object to hydrate. </param>
        /// <returns>
        ///     An appropriately typed collect object based on the collect result passed in, or null if the
        ///     RESULT_TYPE is unknown.
        /// </returns>
        public static CollectObject? Hydrate(string serialized, RESULT_TYPE type)
        {
            if (serialized == null)
            {
                return null;
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

                case RESULT_TYPE.TPM:
                    return JsonConvert.DeserializeObject<TpmObject>(serialized, jsonSettings);

                case RESULT_TYPE.KEY:
                    return JsonConvert.DeserializeObject<CryptographicKeyObject>(serialized, jsonSettings);

                case RESULT_TYPE.PROCESS:
                    return JsonConvert.DeserializeObject<ProcessObject>(serialized, jsonSettings);

                case RESULT_TYPE.DRIVER:
                    return JsonConvert.DeserializeObject<DriverObject>(serialized, jsonSettings);
                case RESULT_TYPE.FILEMONITOR:
                    return JsonConvert.DeserializeObject<FileMonitorObject>(serialized, jsonSettings);
                default:
                    return null;
            }
        }

        private static readonly JsonSerializerSettings jsonSettings = new JsonSerializerSettings() { DefaultValueHandling = DefaultValueHandling.Ignore, DateFormatHandling = DateFormatHandling.IsoDateFormat, NullValueHandling = NullValueHandling.Ignore };
    }

    public class TpmPcrTupleConverter<T1, T2> : TypeConverter
    {
        public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType)
        {
            return sourceType == typeof(string) || base.CanConvertFrom(context, sourceType);
        }

        public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value)
        {
            var elements = Convert.ToString(value, CultureInfo.InvariantCulture)?.Trim('(').Trim(')').Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            if (Enum.TryParse(typeof(TpmAlgId), elements.First(), out object? result) && result is TpmAlgId Algorithm && uint.TryParse(elements.Last(), out uint Index))
            {
                return (Algorithm, Index);
            }
            return (TpmAlgId.Null, uint.MaxValue);
        }
    }
}