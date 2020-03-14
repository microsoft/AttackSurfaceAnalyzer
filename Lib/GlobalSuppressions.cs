// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "Preferred format.", Scope = "namespace", Target = "AttackSurfaceAnalyzer")]
[assembly: SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "False warning. We check if dbSettings is null before using it, and in fact this reference is to settings not to dbSettings", Scope = "member", Target = "~M:AttackSurfaceAnalyzer.Objects.SqlConnectionHolder.#ctor(System.String,AttackSurfaceAnalyzer.Utils.DBSettings,System.Int32)")]
