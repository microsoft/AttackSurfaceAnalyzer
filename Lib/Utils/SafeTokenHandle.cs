// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.Win32.SafeHandles;
using System;

namespace AttackSurfaceAnalyzer.Utils
{
    /// <summary>
    /// Represents a wrapper class for a token handle.
    /// </summary>
    internal class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        #region Internal Constructors

        internal SafeTokenHandle(IntPtr handle) : base(true)
        {
            base.SetHandle(handle);
        }

        #endregion Internal Constructors

        #region Private Constructors

        private SafeTokenHandle() : base(true)
        {
        }

        #endregion Private Constructors

        #region Protected Methods

        protected override bool ReleaseHandle()
        {
            return NativeMethods.CloseHandle(base.handle);
        }

        #endregion Protected Methods
    }
}