using System.Diagnostics;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class SerializableFileVersionInfo
    {
        public SerializableFileVersionInfo()
        {
        }

        // Summary: Gets the comments associated with the file.
        //
        // Returns: The comments associated with the file or null if the file did not contain version information.
        public string? Comments { get; set; }

        // Summary: Gets the name of the company that produced the file.
        //
        // Returns: The name of the company that produced the file or null if the file did not contain version information.
        public string? CompanyName { get; set; }

        // Summary: Gets the build number of the file.
        //
        // Returns: A value representing the build number of the file or null if the file did not contain
        // version information.
        public int FileBuildPart { get; set; }

        // Summary: Gets the description of the file.
        //
        // Returns: The description of the file or null if the file did not contain version information.
        public string? FileDescription { get; set; }

        // Summary: Gets the major part of the version number.
        //
        // Returns: A value representing the major part of the version number or 0 (zero) if the file did not
        // contain version information.
        public int FileMajorPart { get; set; }

        // Summary: Gets the minor part of the version number of the file.
        //
        // Returns: A value representing the minor part of the version number of the file or 0 (zero) if the
        // file did not contain version information.
        public int FileMinorPart { get; set; }

        // Summary: Gets the name of the file that this instance of System.Diagnostics.FileVersionInfo describes.
        //
        // Returns: The name of the file described by this instance of System.Diagnostics.FileVersionInfo.
        public string? FileName { get; set; }

        // Summary: Gets the file private part number.
        //
        // Returns: A value representing the file private part number or null if the file did not contain
        // version information.
        public int FilePrivatePart { get; set; }

        // Summary: Gets the file version number.
        //
        // Returns: The version number of the file or null if the file did not contain version information.
        public string? FileVersion { get; set; }

        // Summary: Gets the internal name of the file, if one exists.
        //
        // Returns: The internal name of the file. If none exists, this property will contain the original
        // name of the file without the extension.
        public string? InternalName { get; set; }

        // Summary: Gets a value that specifies whether the file contains debugging information or is compiled
        // with debugging features enabled.
        //
        // Returns: true if the file contains debugging information or is compiled with debugging features
        // enabled; otherwise, false.
        public bool IsDebug { get; set; }

        // Summary: Gets a value that specifies whether the file has been modified and is not identical to the
        // original shipping file of the same version number.
        //
        // Returns: true if the file is patched; otherwise, false.
        public bool IsPatched { get; set; }

        public bool IsPreRelease { get; set; }

        // Summary: Gets a value that specifies whether the file was built using standard release procedures.
        //
        // Returns: true if the file is a private build; false if the file was built using standard release
        // procedures or if the file did not contain version information.
        public bool IsPrivateBuild { get; set; }

        // Summary: Gets a value that specifies whether the file is a special build.
        //
        // Returns: true if the file is a special build; otherwise, false.
        public bool IsSpecialBuild { get; set; }

        // Summary: Gets the default language string for the version info block.
        //
        // Returns: The description string for the Microsoft Language Identifier in the version resource or
        // null if the file did not contain version information.
        public string? Language { get; set; }

        // Summary: Gets all copyright notices that apply to the specified file.
        //
        // Returns: The copyright notices that apply to the specified file.
        public string? LegalCopyright { get; set; }

        // Summary: Gets the trademarks and registered trademarks that apply to the file.
        //
        // Returns: The trademarks and registered trademarks that apply to the file or null if the file did
        // not contain version information.
        public string? LegalTrademarks { get; set; }

        // Summary: Gets the name the file was created with.
        //
        // Returns: The name the file was created with or null if the file did not contain version information.
        public string? OriginalFilename { get; set; }

        // Summary: Gets information about a private version of the file.
        //
        // Returns: Information about a private version of the file or null if the file did not contain
        // version information.
        public string? PrivateBuild { get; set; }

        // Summary: Gets the build number of the product this file is associated with.
        //
        // Returns: A value representing the build number of the product this file is associated with or null
        // if the file did not contain version information.
        public int ProductBuildPart { get; set; }

        // Summary: Gets the major part of the version number for the product this file is associated with.
        //
        // Returns: A value representing the major part of the product version number or null if the file did
        // not contain version information.
        public int ProductMajorPart { get; set; }

        // Summary: Gets the minor part of the version number for the product the file is associated with.
        //
        // Returns: A value representing the minor part of the product version number or null if the file did
        // not contain version information.
        public int ProductMinorPart { get; set; }

        // Summary: Gets the name of the product this file is distributed with.
        //
        // Returns: The name of the product this file is distributed with or null if the file did not contain
        // version information.
        public string? ProductName { get; set; }

        // Summary: Gets the private part number of the product this file is associated with.
        //
        // Returns: A value representing the private part number of the product this file is associated with
        // or null if the file did not contain version information.
        public int ProductPrivatePart { get; set; }

        // Summary: Gets the version of the product this file is distributed with.
        //
        // Returns: The version of the product this file is distributed with or null if the file did not
        // contain version information.
        public string? ProductVersion { get; set; }

        // Summary: Gets the special build information for the file.
        //
        // Returns: The special build information for the file or null if the file did not contain version information.
        public string? SpecialBuild { get; set; }

        public static SerializableFileVersionInfo? FromFileVersionInfo(FileVersionInfo fvi)
        {
            if (fvi == null) { return null; }
            return new SerializableFileVersionInfo()
            {
                Comments = fvi.Comments,
                CompanyName = fvi.CompanyName,
                FileBuildPart = fvi.FileBuildPart,
                FileDescription = fvi.FileDescription,
                FileMajorPart = fvi.FileMajorPart,
                FileMinorPart = fvi.FileMinorPart,
                FileName = fvi.FileName,
                FilePrivatePart = fvi.FilePrivatePart,
                FileVersion = fvi.FileVersion,
                InternalName = fvi.InternalName,
                IsDebug = fvi.IsDebug,
                IsPatched = fvi.IsPatched,
                IsPreRelease = fvi.IsPreRelease,
                IsPrivateBuild = fvi.IsPrivateBuild,
                IsSpecialBuild = fvi.IsSpecialBuild,
                Language = fvi.Language,
                LegalCopyright = fvi.LegalCopyright,
                LegalTrademarks = fvi.LegalTrademarks,
                OriginalFilename = fvi.OriginalFilename,
                PrivateBuild = fvi.PrivateBuild,
                ProductBuildPart = fvi.ProductBuildPart,
                ProductMajorPart = fvi.ProductMajorPart,
                ProductMinorPart = fvi.ProductMinorPart,
                ProductName = fvi.ProductName,
                ProductPrivatePart = fvi.ProductPrivatePart,
                ProductVersion = fvi.ProductVersion,
                SpecialBuild = fvi.SpecialBuild
            };
        }
    }
}