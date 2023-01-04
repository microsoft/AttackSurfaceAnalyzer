using System.Collections.Generic;
using MessagePack;
using Tpm2Lib;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [MessagePackObject()]
    public class AsaNvIndex
    {
        [Key(0)]
        public NvAttr Attributes { get; set; }

        // These are all derived properties of the NvAttr flags. Separating them like this allows analysis
        // rules to be written against them
        [IgnoreMember]
        public bool AuthRead { get { return Attributes.HasFlag(NvAttr.Authread); } }
        [IgnoreMember]
        public bool AuthWrite { get { return Attributes.HasFlag(NvAttr.Authwrite); } }
        [IgnoreMember]
        public bool Bits { get { return Attributes.HasFlag(NvAttr.Bits); } }
        [IgnoreMember]
        public bool ClearStClear { get { return Attributes.HasFlag(NvAttr.ClearStclear); } }
        [IgnoreMember]
        public bool Counter { get { return Attributes.HasFlag(NvAttr.Counter); } }
        [IgnoreMember]
        public bool Extend { get { return Attributes.HasFlag(NvAttr.Extend); } }
        [IgnoreMember]
        public bool GlobalLock { get { return Attributes.HasFlag(NvAttr.Globallock); } }
        [IgnoreMember]
        public uint Index { get; set; }
        [IgnoreMember]
        public bool NoDa { get { return Attributes.HasFlag(NvAttr.NoDa); } }
        [IgnoreMember]
        public bool None { get { return Attributes.HasFlag(NvAttr.None); } }
        [IgnoreMember]
        public bool Orderly { get { return Attributes.HasFlag(NvAttr.Orderly); } }
        [IgnoreMember]
        public bool Ordinary { get { return Attributes.HasFlag(NvAttr.Ordinary); } }
        [IgnoreMember]
        public bool OwnerRead { get { return Attributes.HasFlag(NvAttr.Ownerread); } }
        [IgnoreMember]
        public bool OwnerWrite { get { return Attributes.HasFlag(NvAttr.Ownerwrite); } }
        [IgnoreMember]
        public bool PinFail { get { return Attributes.HasFlag(NvAttr.PinFail); } }
        [IgnoreMember]
        public bool PinPass { get { return Attributes.HasFlag(NvAttr.PinPass); } }
        [IgnoreMember]
        public bool PlatformCreate { get { return Attributes.HasFlag(NvAttr.Platformcreate); } }
        [IgnoreMember]
        public bool PolicyDelete { get { return Attributes.HasFlag(NvAttr.PolicyDelete); } }
        [IgnoreMember]
        public bool PolicyRead { get { return Attributes.HasFlag(NvAttr.Policyread); } }
        [IgnoreMember]
        public bool PolicyWrite { get { return Attributes.HasFlag(NvAttr.Policywrite); } }
        [IgnoreMember]
        public bool Ppread { get { return Attributes.HasFlag(NvAttr.Ppread); } }
        [IgnoreMember]
        public bool Ppwrite { get { return Attributes.HasFlag(NvAttr.Ppwrite); } }
        [IgnoreMember]
        public bool ReadLocked { get { return Attributes.HasFlag(NvAttr.Readlocked); } }
        [IgnoreMember]
        public bool ReadStClear { get { return Attributes.HasFlag(NvAttr.ReadStclear); } }
        [IgnoreMember]
        public bool TpmNtBit0 { get { return Attributes.HasFlag(NvAttr.TpmNtBit0); } }
        [IgnoreMember]
        public bool TpmNtBit1 { get { return Attributes.HasFlag(NvAttr.TpmNtBit1); } }
        [IgnoreMember]
        public bool TpmNtBit2 { get { return Attributes.HasFlag(NvAttr.TpmNtBit2); } }
        [IgnoreMember]
        public bool TpmNtBit3 { get { return Attributes.HasFlag(NvAttr.TpmNtBit3); } }
        [IgnoreMember]
        public bool TpmNtBitLength { get { return Attributes.HasFlag(NvAttr.TpmNtBitLength); } }
        [IgnoreMember]
        public bool TpmNtBitMask { get { return Attributes.HasFlag(NvAttr.TpmNtBitMask); } }
        [IgnoreMember]
        public bool TpmNtBitOffset { get { return Attributes.HasFlag(NvAttr.TpmNtBitOffset); } }
        [Key(1)]
        public List<byte>? value { get; set; }
        [IgnoreMember]
        public bool Writeall { get { return Attributes.HasFlag(NvAttr.Writeall); } }
        [IgnoreMember]
        public bool Writedefine { get { return Attributes.HasFlag(NvAttr.Writedefine); } }
        [IgnoreMember]
        public bool Writelocked { get { return Attributes.HasFlag(NvAttr.Writelocked); } }
        [IgnoreMember]
        public bool WriteStclear { get { return Attributes.HasFlag(NvAttr.WriteStclear); } }
        [IgnoreMember]
        public bool Written { get { return Attributes.HasFlag(NvAttr.Written); } }
    }
}