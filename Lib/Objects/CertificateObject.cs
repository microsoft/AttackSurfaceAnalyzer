// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.

using System.Runtime.ConstrainedExecution;
using MessagePack;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [MessagePackObject]
    public class CertificateObject : CollectObject
    {
        [SerializationConstructor]        
        public CertificateObject(string StoreLocation, string StoreName, SerializableCertificate Certificate)
        {
            this.StoreLocation = StoreLocation;
            this.StoreName = StoreName;
            this.Certificate = Certificate;
        }
        
        /// <summary>
        ///     The identity of a CertificateObject is based on the StoreLocation, StoreName and
        ///     CertificateHashString of the CertificateObject
        /// </summary>
        [IgnoreMember]
        public override string Identity
        {
            get
            {
                return $"{StoreLocation}{StoreName}{CertificateHashString}";
            }
        }
        
        [IgnoreMember]
        public override RESULT_TYPE ResultType => RESULT_TYPE.CERTIFICATE;

        /// <summary>
        ///     A serializable representation of the Certificate.
        /// </summary>
        [Key(2)]
        public SerializableCertificate Certificate { get; set; }

        /// <summary>
        ///     See Certificate.CertHashString
        /// </summary>
        [IgnoreMember]
        public string CertificateHashString { get { return Certificate.CertHashString; } }

        /// <summary>
        ///     The Store Location or Location on Disk where the Certificate was found
        /// </summary>
        [Key(0)]
        public string StoreLocation { get; set; }

        /// <summary>
        ///     The Name of an X509 Store or another source (like the filesystem)
        /// </summary>
        [Key(1)]
        public string StoreName { get; set; }
    }
}