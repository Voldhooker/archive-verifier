using System.Security.Cryptography;

using Archive.Verifier;
using Shouldly;

namespace Archive.Evidence.Tests;

public sealed class VerifyCommandTests : IDisposable
{
    private readonly TestEvidence _evidence = new();
    private readonly DirectoryInfo _folder = Directory.CreateTempSubdirectory("archive-verify-");
    private readonly StringWriter _output = new();
    private readonly StringWriter _errors = new();

    public void Dispose()
    {
        _evidence.Dispose();
        _output.Dispose();
        _errors.Dispose();
        _folder.Delete(recursive: true);
    }

    [Fact]
    public void Run_OnAValidPackage_ExitsZeroAndSaysWhenAndByWhom()
    {
        // Act
        int exit = Run(File("package.zip", _evidence.Package()), "--trust", TrustPem());

        // Assert
        exit.ShouldBe(VerifyCommand.Valid);
        _output.ToString().ShouldContain("VALID");
        _output.ToString().ShouldContain("CN=Test TSA");
    }

    [Fact]
    public void Run_OnAChangedPackage_ExitsOneNamingTheCheck()
    {
        // Arrange: a byte of the object changed.
        byte[] package = _evidence.Package(p =>
        {
            byte[] stored = [.. p.Stored];
            stored[60] ^= 1;
            return p with { Stored = stored };
        });

        // Act
        int exit = Run(File("package.zip", package), "--trust", TrustPem());

        // Assert
        exit.ShouldBe(VerifyCommand.Invalid);
        _output.ToString().ShouldContain("INVALID: the ciphertext-hash check failed.");
    }

    [Fact]
    public void Run_OnAnUnsealedPackage_ExitsTwo()
    {
        // Act and assert
        Run(File("package.zip", _evidence.Package(sealedRecord: false)), "--trust", TrustPem()).ShouldBe(VerifyCommand.Unsealed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Run_WithoutTrustOrPackage_ExitsThreeWithUsage(bool withPackage)
    {
        // Act
        int exit = withPackage ? Run(File("package.zip", _evidence.Package())) : Run("--trust", TrustPem());

        // Assert
        exit.ShouldBe(VerifyCommand.Usage);
        _errors.ToString().ShouldContain("Usage");
    }

    [Fact]
    public void Run_WithADerCertificate_TrustsIt()
    {
        // Act
        int exit = Run(File("package.zip", _evidence.Package()), "--trust", File("root.cer", _evidence.Root.RawData));

        // Assert
        exit.ShouldBe(VerifyCommand.Valid);
    }

    private string TrustPem() => File("root.pem", System.Text.Encoding.ASCII.GetBytes(_evidence.Root.ExportCertificatePem()));

    private string File(string name, byte[] content)
    {
        string path = Path.Combine(_folder.FullName, $"{Convert.ToHexString(RandomNumberGenerator.GetBytes(4))}-{name}");
        System.IO.File.WriteAllBytes(path, content);
        return path;
    }

    private int Run(params string[] args) => VerifyCommand.Run(args, _output, _errors);
}
