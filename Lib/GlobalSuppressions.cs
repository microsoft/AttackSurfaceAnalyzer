// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.

// This file is used by Code Analysis to maintain SuppressMessage attributes that are applied to this project.
// Project-level suppressions either have no target or are given a specific target and scoped to a namespace,
// type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "Preferred format.", Scope = "namespace", Target = "AttackSurfaceAnalyzer")]
[assembly: SuppressMessage("Globalization", "CA1303:Do not pass literals as localized parameters", Justification = "<Pending>", Scope = "member", Target = "~M:AttackSurfaceAnalyzer.Collectors.TpmCollector.GetLoadedEntities(Tpm2Lib.Tpm2,Tpm2Lib.Ht)~Tpm2Lib.TpmHandle[]")]