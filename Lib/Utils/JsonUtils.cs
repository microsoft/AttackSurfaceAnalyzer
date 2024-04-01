// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Newtonsoft.Json;
using ProtoBuf;
using System;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Unicode;
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
        public static byte[] Dehydrate(CollectObject colObj)
        {
            using var ms = new MemoryStream();
            switch (colObj)
            {
                case CertificateObject certificateObject:
                    Serializer.Serialize(ms, certificateObject);
                    break;
                case FileSystemObject fileSystemObject:
                    Serializer.Serialize(ms, fileSystemObject);
                    break;
                case OpenPortObject openPortObject:
                    Serializer.Serialize(ms, openPortObject);
                    break;
                case RegistryObject registryObject:
                    Serializer.Serialize(ms, registryObject);
                    break;
                case ServiceObject serviceObject:
                    Serializer.Serialize(ms, serviceObject);
                    break;
                case UserAccountObject userAccountObject:
                    Serializer.Serialize(ms, userAccountObject);
                    break;
                case GroupAccountObject groupAccountObject:
                    Serializer.Serialize(ms, groupAccountObject);
                    break;
                case FirewallObject firewallObject:
                    Serializer.Serialize(ms, firewallObject);
                    break;
                case ComObject comObject:
                    Serializer.Serialize(ms, comObject);
                    break;
                case EventLogObject eventLogObject:
                    Serializer.Serialize(ms, eventLogObject);
                    break;
                case TpmObject tpmObject:
                    Serializer.Serialize(ms, tpmObject);
                    break;
                case CryptographicKeyObject cryptographicKeyObject:
                    Serializer.Serialize(ms, cryptographicKeyObject);
                    break;
                case ProcessObject processObject:
                    Serializer.Serialize(ms, processObject);
                    break;
                case DriverObject driverObject:
                    Serializer.Serialize(ms, driverObject);
                    break;
                case FileMonitorObject fileMonitorObject:
                    Serializer.Serialize(ms, fileMonitorObject);
                    break;
                default:
                    throw new NotSupportedException();
            }
            return ms.ToArray();
        }

        /// <summary>
        ///     Deserialize a Collect object from a RawCollectResult
        /// </summary>
        /// <param name="res"> The RawCollectResult containing the msgpack serialized object to hydrate. </param>
        /// <returns>
        ///     An appropriately typed collect object based on the collect result passed in, or null if the
        ///     RESULT_TYPE is unknown.
        /// </returns>
        public static CollectObject? Hydrate(byte[] serialized, RESULT_TYPE type)
        {
            if (serialized == null)
            {
                return null;
            }

            switch (type)
            {
                case RESULT_TYPE.CERTIFICATE:
                    return Serializer.Deserialize<CertificateObject>(new MemoryStream(serialized));
                case RESULT_TYPE.FILE:
                    return Serializer.Deserialize<FileSystemObject>(new MemoryStream(serialized));
                case RESULT_TYPE.PORT:
                    return Serializer.Deserialize<OpenPortObject>(new MemoryStream(serialized));
                case RESULT_TYPE.REGISTRY:
                    return Serializer.Deserialize<RegistryObject>(new MemoryStream(serialized));
                case RESULT_TYPE.SERVICE:
                    return Serializer.Deserialize<ServiceObject>(new MemoryStream(serialized));
                case RESULT_TYPE.USER:
                    return Serializer.Deserialize<UserAccountObject>(new MemoryStream(serialized));
                case RESULT_TYPE.GROUP:
                    return Serializer.Deserialize<GroupAccountObject>(new MemoryStream(serialized));
                case RESULT_TYPE.FIREWALL:
                    return Serializer.Deserialize<FirewallObject>(new MemoryStream(serialized));
                case RESULT_TYPE.COM:
                    return Serializer.Deserialize<ComObject>(new MemoryStream(serialized));
                case RESULT_TYPE.LOG:
                    return Serializer.Deserialize<EventLogObject>(new MemoryStream(serialized));
                case RESULT_TYPE.TPM:
                    return Serializer.Deserialize<TpmObject>(new MemoryStream(serialized));
                case RESULT_TYPE.KEY:
                    return Serializer.Deserialize<CryptographicKeyObject>(new MemoryStream(serialized));
                case RESULT_TYPE.PROCESS:
                    return Serializer.Deserialize<ProcessObject>(new MemoryStream(serialized));
                case RESULT_TYPE.DRIVER:
                    return Serializer.Deserialize<DriverObject>(new MemoryStream(serialized));
                case RESULT_TYPE.FILEMONITOR:
                    return Serializer.Deserialize<FileMonitorObject>(new MemoryStream(serialized));
                default:
                    return null;
            }
        }

        private static readonly JsonSerializerSettings jsonSettings = new() { DefaultValueHandling = DefaultValueHandling.Ignore, DateFormatHandling = DateFormatHandling.IsoDateFormat, NullValueHandling = NullValueHandling.Ignore };
    }

    public class TpmPcrTupleConverter<T1, T2> : TypeConverter
    {
        public override bool CanConvertFrom(ITypeDescriptorContext? context, Type sourceType)
        {
            return sourceType == typeof(string) || base.CanConvertFrom(context, sourceType);
        }

        public override object ConvertFrom(ITypeDescriptorContext? context, CultureInfo? culture, object value)
        {
            var elements = Convert.ToString(value, CultureInfo.InvariantCulture)?.Trim('(').Trim(')').Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            if (Enum.TryParse(typeof(TpmAlgId), elements?.First(), out object? result) && result is TpmAlgId Algorithm && uint.TryParse(elements?.Last(), out uint Index))
            {
                return (Algorithm, Index);
            }
            return (TpmAlgId.Null, uint.MaxValue);
        }
    }
}