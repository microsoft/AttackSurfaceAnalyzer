// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
namespace AttackSurfaceAnalyzer.Types
{
    /// <summary>
    /// The data type of a Collect object.
    /// </summary>
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
        COM,
        LOG,
        FILEMONITOR
    };

    /// <summary>
    /// The change type of a CompareResult object.
    /// </summary>
    public enum CHANGE_TYPE
    {
        INVALID,
        CREATED,
        DELETED,
        MODIFIED,
        RENAMED
    }

    /// <summary>
    /// The running status of a Comparator or Collector
    /// </summary>
    public enum RUN_STATUS
    {
        NOT_STARTED,
        RUNNING,
        FAILED,
        COMPLETED,
        NO_RESULTS
    }

    /// <summary>
    /// Errors enum.
    /// </summary>
    public enum ASA_ERROR
    {
        NONE,
        UNIQUE_ID,
        INVALID_PATH,
        ALREADY_RUNNING,
        NO_COLLECTORS,
        MATCHING_SCHEMA,
        FAILED_TO_CREATE_DATABASE
    }


    /// <summary>
    /// These are the characteristics defined in the PE Header for Windows executables.
    /// See https://docs.microsoft.com/en-us/windows/win32/debug/pe-format for the oracle definitions of these values
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1717:Only FlagsAttribute enums should have plural names", Justification = "This is the official name for the enum.")]
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

    /// <summary>
    /// Flags available for analysis rules.
    /// </summary>
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

    /// <summary>
    /// Operations available for Analysis rules.
    /// </summary>
    public enum OPERATION
    {
        REGEX,
        EQ,
        NEQ,
        LT,
        GT,
        CONTAINS,
        DOES_NOT_CONTAIN,
        WAS_MODIFIED,
        ENDS_WITH,
        STARTS_WITH,
        CONTAINS_ANY,
        DOES_NOT_CONTAIN_ALL
    }

    /// <summary>
    /// Platform definitions for Analysis rules.
    /// </summary>
    public enum PLATFORM
    {
        WINDOWS,
        LINUX,
        MACOS,
        UNKNOWN
    }

    public enum RUN_TYPE
    {
        COLLECT,
        MONITOR,
        COMPARE
    }
}