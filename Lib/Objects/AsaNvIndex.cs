using System.Collections.Generic;
using Tpm2Lib;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class AsaNvIndex
    {
        public NvAttr Attributes { get; set; }

        // These are all derived properties of the NvAttr flags. Separating them like this allows analysis
        // rules to be written against them
        public bool AuthRead { get { return Attributes.HasFlag(NvAttr.Authread); } }

        public bool AuthWrite { get { return Attributes.HasFlag(NvAttr.Authwrite); } }
        public bool Bits { get { return Attributes.HasFlag(NvAttr.Bits); } }
        public bool ClearStClear { get { return Attributes.HasFlag(NvAttr.ClearStclear); } }
        public bool Counter { get { return Attributes.HasFlag(NvAttr.Counter); } }
        public bool Extend { get { return Attributes.HasFlag(NvAttr.Extend); } }
        public bool GlobalLock { get { return Attributes.HasFlag(NvAttr.Globallock); } }
        public uint Index { get; set; }
        public bool NoDa { get { return Attributes.HasFlag(NvAttr.NoDa); } }
        public bool None { get { return Attributes.HasFlag(NvAttr.None); } }
        public bool Orderly { get { return Attributes.HasFlag(NvAttr.Orderly); } }
        public bool Ordinary { get { return Attributes.HasFlag(NvAttr.Ordinary); } }
        public bool OwnerRead { get { return Attributes.HasFlag(NvAttr.Ownerread); } }
        public bool OwnerWrite { get { return Attributes.HasFlag(NvAttr.Ownerwrite); } }
        public bool PinFail { get { return Attributes.HasFlag(NvAttr.PinFail); } }
        public bool PinPass { get { return Attributes.HasFlag(NvAttr.PinPass); } }
        public bool PlatformCreate { get { return Attributes.HasFlag(NvAttr.Platformcreate); } }
        public bool PolicyDelete { get { return Attributes.HasFlag(NvAttr.PolicyDelete); } }
        public bool PolicyRead { get { return Attributes.HasFlag(NvAttr.Policyread); } }
        public bool PolicyWrite { get { return Attributes.HasFlag(NvAttr.Policywrite); } }
        public bool Ppread { get { return Attributes.HasFlag(NvAttr.Ppread); } }
        public bool Ppwrite { get { return Attributes.HasFlag(NvAttr.Ppwrite); } }
        public bool ReadLocked { get { return Attributes.HasFlag(NvAttr.Readlocked); } }
        public bool ReadStClear { get { return Attributes.HasFlag(NvAttr.ReadStclear); } }
        public bool TpmNtBit0 { get { return Attributes.HasFlag(NvAttr.TpmNtBit0); } }
        public bool TpmNtBit1 { get { return Attributes.HasFlag(NvAttr.TpmNtBit1); } }
        public bool TpmNtBit2 { get { return Attributes.HasFlag(NvAttr.TpmNtBit2); } }
        public bool TpmNtBit3 { get { return Attributes.HasFlag(NvAttr.TpmNtBit3); } }
        public bool TpmNtBitLength { get { return Attributes.HasFlag(NvAttr.TpmNtBitLength); } }
        public bool TpmNtBitMask { get { return Attributes.HasFlag(NvAttr.TpmNtBitMask); } }
        public bool TpmNtBitOffset { get { return Attributes.HasFlag(NvAttr.TpmNtBitOffset); } }
        public List<byte>? value { get; set; }
        public bool Writeall { get { return Attributes.HasFlag(NvAttr.Writeall); } }
        public bool Writedefine { get { return Attributes.HasFlag(NvAttr.Writedefine); } }
        public bool Writelocked { get { return Attributes.HasFlag(NvAttr.Writelocked); } }
        public bool WriteStclear { get { return Attributes.HasFlag(NvAttr.WriteStclear); } }
        public bool Written { get { return Attributes.HasFlag(NvAttr.Written); } }

        // Don't serialize any of these derived properties
        public static bool ShouldSerializeAuthRead() { return false; }

        public static bool ShouldSerializeAuthWrite()
        {
            return false;
        }

        public static bool ShouldSerializeBits()
        {
            return false;
        }

        public static bool ShouldSerializeClearStClear()
        {
            return false;
        }

        public static bool ShouldSerializeCounter()
        {
            return false;
        }

        public static bool ShouldSerializeExtend()
        {
            return false;
        }

        public static bool ShouldSerializeGlobalLock()
        {
            return false;
        }

        public static bool ShouldSerializeNoDa()
        {
            return false;
        }

        public static bool ShouldSerializeNone()
        {
            return false;
        }

        public static bool ShouldSerializeOrderly()
        {
            return false;
        }

        public static bool ShouldSerializeOrdinary()
        {
            return false;
        }

        public static bool ShouldSerializeOwnerRead()
        {
            return false;
        }

        public static bool ShouldSerializeOwnerWrite()
        {
            return false;
        }

        public static bool ShouldSerializePinFail()
        {
            return false;
        }

        public static bool ShouldSerializePinPass()
        {
            return false;
        }

        public static bool ShouldSerializePlatformCreate()
        {
            return false;
        }

        public static bool ShouldSerializePolicyDelete()
        {
            return false;
        }

        public static bool ShouldSerializePolicyRead()
        {
            return false;
        }

        public static bool ShouldSerializePolicyWrite()
        {
            return false;
        }

        public static bool ShouldSerializePpread()
        {
            return false;
        }

        public static bool ShouldSerializePpwrite()
        {
            return false;
        }

        public static bool ShouldSerializeReadLocked()
        {
            return false;
        }

        public static bool ShouldSerializeReadStClear()
        {
            return false;
        }

        public static bool ShouldSerializeTpmNtBit0()
        {
            return false;
        }

        public static bool ShouldSerializeTpmNtBit1()
        {
            return false;
        }

        public static bool ShouldSerializeTpmNtBit2()
        {
            return false;
        }

        public static bool ShouldSerializeTpmNtBit3()
        {
            return false;
        }

        public static bool ShouldSerializeTpmNtBitLength()
        {
            return false;
        }

        public static bool ShouldSerializeTpmNtBitMask()
        {
            return false;
        }

        public static bool ShouldSerializeTpmNtBitOffset()
        {
            return false;
        }

        public static bool ShouldSerializeWriteall()
        {
            return false;
        }

        public static bool ShouldSerializeWritedefine()
        {
            return false;
        }

        public static bool ShouldSerializeWritelocked()
        {
            return false;
        }

        public static bool ShouldSerializeWriteStclear()
        {
            return false;
        }

        public static bool ShouldSerializeWritten()
        {
            return false;
        }
    }
}