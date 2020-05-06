// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Objects
{
    public class CertificateObject : CollectObject
    {
        /// <summary>
        /// The Store Location or Location on Disk where the Certificate was found
        /// </summary>
        public string StoreLocation { get; set; }
        /// <summary>
        /// The Name of an X509 Store or another source (like the filesystem)
        /// </summary>
        public string StoreName { get; set; }
        /// <summary>
        /// See Certificate.CertHashString
        /// </summary>
        public string CertificateHashString { get { return Certificate.CertHashString; } }
        /// <summary>
        /// See Certificate.Subject
        /// </summary>
        public string Subject { get { return Certificate.Subject; } }
        /// <summary>
        /// The exported Pkcs7 of the certificate. Not guaranteed to be non-null.
        /// </summary>
        public string? Pkcs7 { get { return Certificate.Pkcs7; } }
        /// <summary>
        /// A serializable representation of the Certificate.
        /// </summary>
        public SerializableCertificate Certificate { get; set; }

        public CertificateObject(string StoreLocation, string StoreName, SerializableCertificate Certificate)
        {
            this.StoreLocation = StoreLocation;
            this.StoreName = StoreName;
            this.Certificate = Certificate;
            ResultType = RESULT_TYPE.CERTIFICATE;
        }

        /// <summary>
        /// The identity of a CertificateObject is based on the StoreLocation, StoreName and CertificateHashString of the CertificateObject
        /// </summary>
        public override string Identity
        {
            get
            {
                return $"{StoreLocation}{StoreName}{CertificateHashString}";
            }
        }
    }
}
