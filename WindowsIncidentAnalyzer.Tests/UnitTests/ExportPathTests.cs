using WindowsIncidentAnalyzer.Exporters;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class ExportPathTests
{
    [Fact]
    public void EnsureDirectory_CreatesMissingParentAndReturnsIt()
    {
        var root = Path.Combine(Path.GetTempPath(), "wia-export-path-" + Guid.NewGuid().ToString("N"));
        var file = Path.Combine(root, "nested", "report.html");
        try
        {
            Assert.False(Directory.Exists(Path.Combine(root, "nested")));
            var directory = ExportPath.EnsureDirectory(file);
            Assert.Equal(Path.GetFullPath(Path.Combine(root, "nested")), directory);
            Assert.True(Directory.Exists(directory));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void EnsureDirectory_ExistingParent_IsIdempotent()
    {
        var root = Path.Combine(Path.GetTempPath(), "wia-export-path-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var file = Path.Combine(root, "out.json");
        try
        {
            var first = ExportPath.EnsureDirectory(file);
            var second = ExportPath.EnsureDirectory(file);
            Assert.Equal(first, second);
            Assert.True(Directory.Exists(first));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
