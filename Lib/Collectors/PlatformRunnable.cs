// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
namespace AttackSurfaceAnalyzer.Collectors
{
    interface PlatformRunnable
    {
        bool CanRunOnPlatform();
    }
}