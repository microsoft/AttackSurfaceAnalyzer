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
    public static class SerializationUtils
    {
        static SerializationUtils()
        {
        }

        /// <summary>
        ///     Serialize an object for storage in database
        /// </summary>
        /// <param name="colObj">The object to serialize</param>
        /// <returns> The bytes of the serialized object </returns>
        public static byte[] Dehydrate(CollectObject? colObj)
        {
            if (colObj is null)
            {
                return Array.Empty<byte>();
            }

            return colObj switch
            {
                CertificateObject certificateObject => MessagePack.MessagePackSerializer.Serialize(certificateObject),
                _ => MessagePack.MessagePackSerializer.Serialize(colObj)
            };
        }

        /// <summary>
        ///     Deserialize a Collect object from a RawCollectResult
        /// </summary>
        /// <param name="serialized">The serialized bytes</param>
        /// <param name="type">The <see cref="RESULT_TYPE"/> to hydrate as</param>
        /// <returns>
        ///     An appropriately typed collect object based on the collect result passed in, or null if the
        ///     RESULT_TYPE is unknown.
        /// </returns>
        public static CollectObject? Hydrate(byte[] serialized, RESULT_TYPE type)
        {
            return type switch
            {
                RESULT_TYPE.CERTIFICATE => MessagePack.MessagePackSerializer.Deserialize<CertificateObject>(serialized),
                RESULT_TYPE.FILE => MessagePack.MessagePackSerializer.Deserialize<FileSystemObject>(serialized),
                RESULT_TYPE.PORT => MessagePack.MessagePackSerializer.Deserialize<OpenPortObject>(serialized),
                RESULT_TYPE.REGISTRY => MessagePack.MessagePackSerializer.Deserialize<RegistryObject>(serialized),
                RESULT_TYPE.SERVICE => MessagePack.MessagePackSerializer.Deserialize<ServiceObject>(serialized),
                RESULT_TYPE.USER => MessagePack.MessagePackSerializer.Deserialize<UserAccountObject>(serialized),
                RESULT_TYPE.GROUP => MessagePack.MessagePackSerializer.Deserialize<GroupAccountObject>(serialized),
                RESULT_TYPE.FIREWALL => MessagePack.MessagePackSerializer.Deserialize<FirewallObject>(serialized),
                RESULT_TYPE.COM => MessagePack.MessagePackSerializer.Deserialize<ComObject>(serialized),
                RESULT_TYPE.LOG => MessagePack.MessagePackSerializer.Deserialize<EventLogObject>(serialized),
                RESULT_TYPE.TPM => MessagePack.MessagePackSerializer.Deserialize<TpmObject>(serialized),
                RESULT_TYPE.KEY => MessagePack.MessagePackSerializer.Deserialize<CryptographicKeyObject>(serialized),
                RESULT_TYPE.PROCESS => MessagePack.MessagePackSerializer.Deserialize<ProcessObject>(serialized),
                RESULT_TYPE.DRIVER => MessagePack.MessagePackSerializer.Deserialize<DriverObject>(serialized),
                RESULT_TYPE.FILEMONITOR => MessagePack.MessagePackSerializer.Deserialize<FileMonitorObject>(serialized),
                _ => null
            };
        }
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