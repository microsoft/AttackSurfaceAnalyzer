// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Types
{
    public enum RESULT_TYPE
    {
        UNKNOWN,
        FILE,
        PORT,
        REGISTRY,
        CERTIFICATE,
        SERVICE,
        USER,
        GROUP,
        FIREWALL,
        COM
    };

    public enum CHANGE_TYPE
    {
        INVALID,
        CREATED,
        DELETED,
        MODIFIED,
        RENAMED
    }

    public enum RUN_STATUS
    {
        NOT_STARTED,
        RUNNING,
        FAILED,
        COMPLETED,
        NO_RESULTS
    }

    public enum ERRORS
    {
        NONE,
        UNIQUE_ID,
        INVALID_PATH,
        ALREADY_RUNNING,
        NO_COLLECTORS
    }

    /// <summary>
    /// See https://docs.microsoft.com/en-us/windows/win32/debug/pe-format for the oracle definitions of these values
    /// </summary>
    public enum DLLCHARACTERISTICS
    {
        // 64 Bit ASLR
        IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020,
        // ASLR
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040,
        // Don't run unless properly signed
        IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
        // DEP
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100,
        // No Isolation
        IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
        // No Exceptions
        IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
        // Do not bind the image
        IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
        // Must execute in an app container
        IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000,
        // Image is a WDM driver
        IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
        // Supports Control Flow Guard
        IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000,
        // Image is terminal server aware
        IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
    }

    // These need better names. But the heirarchy of these makes sense to me as a model.
    // These are flags that can be defined in an analyze.json to arrange output by importance.
    public enum ANALYSIS_RESULT_TYPE
    {
        NONE,
        VERBOSE,
        DEBUG,
        INFORMATION,
        WARNING,
        ERROR,
        FATAL
    }

    public enum OPERATION
    {
        REGEX,
        EQ,
        NEQ,
        LT,
        GT,
        CONTAINS,
        WAS_MODIFIED,
        ENDS_WITH,
        STARTS_WITH,
        DOES_NOT_CONTAIN
    }

    public enum PLATFORM
    {
        WINDOWS,
        LINUX,
        MACOS,
        UNKNOWN
    }

    public class WindowsPermissions
    {
        public string SID { get; set; }
        public string Name { get; set; }
        public string Permissions { get; set; }
        public bool IsInherited { get; set; }
        public string AccessControlType { get; set; }
    }
}