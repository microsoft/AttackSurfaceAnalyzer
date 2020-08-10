// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using System;
using System.Collections.Generic;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class MacSignature
    {
        //Executable=/Applications/1Password 7.app/Contents/MacOS/1Password 7
        //Identifier=com.agilebits.onepassword7
        //Format=app bundle with Mach-O thin (x86_64)
        //CodeDirectory v=20500 size=43910 flags=0x10000(runtime) hashes=1363+5 location=embedded
        //VersionPlatform=1
        //VersionMin=658438
        //VersionSDK=659200
        //Hash type=sha256 size=32
        //CandidateCDHash sha256=c01b95b3f3138c2f868bfe9b6772463fb4c4d989
        //CandidateCDHashFull sha256=c01b95b3f3138c2f868bfe9b6772463fb4c4d98939ea9de67480622558dbff92
        //Hash choices=sha256
        //CMSDigest=c01b95b3f3138c2f868bfe9b6772463fb4c4d98939ea9de67480622558dbff92
        //CMSDigestType=2
        //Page size=4096
        //CDHash=c01b95b3f3138c2f868bfe9b6772463fb4c4d989
        //Signature size=8928
        //Authority=Developer ID Application: AgileBits Inc. (2BUA8C4S2C)
        //Authority=Developer ID Certification Authority
        //Authority=Apple Root CA
        //Timestamp=May 5, 2020 at 9:21:50 AM
        //Info.plist entries=36
        //TeamIdentifier=2BUA8C4S2C
        //Runtime Version=10.15.0
        //Sealed Resources version=2 rules=13 files=2909
        //Internal requirements count=1 size=220

        public List<string>? Authorities { get; set; }
        public string? CandidateCDHashFull { get; set; }
        public string? CMSDigest { get; set; }
        public string? HashChoices { get; set; }
        public string? HashType { get; set; }
        public string? TeamIdentifier { get; set; }
        public DateTime Timestamp { get; set; }
    }
}