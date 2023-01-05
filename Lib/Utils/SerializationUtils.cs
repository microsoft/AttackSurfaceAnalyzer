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
        /// Serialize a CompareResult
        /// </summary>
        /// <param name="compareResult"></param>
        /// <returns></returns>
        public static byte[] DehydrateCompareResult(CompareResult compareResult)
        {
            return MessagePack.MessagePackSerializer.Serialize(compareResult);
        }

        /// <summary>
        /// Deserialize a compare result
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static CompareResult HydrateCompareResult(byte[] data)
        {
            return MessagePack.MessagePackSerializer.Deserialize<CompareResult>(data);
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
                ComObject comObject => MessagePack.MessagePackSerializer.Serialize(comObject),
                CryptographicKeyObject cryptographicKeyObject => MessagePack.MessagePackSerializer.Serialize(cryptographicKeyObject),
                DriverObject driverObject => MessagePack.MessagePackSerializer.Serialize(driverObject),
                EventLogObject eventLogObject => MessagePack.MessagePackSerializer.Serialize(eventLogObject),
                FileMonitorObject fileMonitorObject => MessagePack.MessagePackSerializer.Serialize(fileMonitorObject),
                FileSystemObject fileSystemObject => MessagePack.MessagePackSerializer.Serialize(fileSystemObject),
                FirewallObject firewallObject => MessagePack.MessagePackSerializer.Serialize(firewallObject),
                GroupAccountObject groupAccountObject => MessagePack.MessagePackSerializer.Serialize(groupAccountObject),
                OpenPortObject openPortObject => MessagePack.MessagePackSerializer.Serialize(openPortObject),
                ProcessObject processObject => MessagePack.MessagePackSerializer.Serialize(processObject),
                RegistryObject registryObject => MessagePack.MessagePackSerializer.Serialize(registryObject),
                ServiceObject serviceObject => MessagePack.MessagePackSerializer.Serialize(serviceObject),
                TpmObject tpmObject => MessagePack.MessagePackSerializer.Serialize(tpmObject),
                UserAccountObject userAccountObject => MessagePack.MessagePackSerializer.Serialize(userAccountObject),
                WifiObject wifiObject => MessagePack.MessagePackSerializer.Serialize(wifiObject),
                _ => throw new ArgumentOutOfRangeException(nameof(colObj)),

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
}