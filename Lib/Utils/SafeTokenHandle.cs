// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.Win32.SafeHandles;
using System;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Utils
{
    /// <summary>
    ///     Represents a wrapper class for a token handle.
    /// </summary>
    internal class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeTokenHandle(IntPtr handle) : base(true)
        {
            base.SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return NativeMethods.CloseHandle(base.handle);
        }

        private SafeTokenHandle() : base(true)
        {
        }
    }
}