using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Sigma;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class SigmaMitreTagParserTests
{
    [Fact]
    public void Apply_ExtractsAttackTagsAndSetsTechniqueAndTactic()
    {
        var context = new FindingContext();
        var tags = new[]
        {
            "attack.discovery",
            "attack.t1033",
            "attack.t1087",
            "car.2013-07-005",
            "attack.discovery"
        };

        SigmaMitreTagParser.Apply(tags, context);

        Assert.Equal(["attack.discovery", "attack.t1033", "attack.t1087"], context.MitreTags);
        Assert.Equal("attack.t1033", context.MitreTechnique);
        Assert.Equal("attack.discovery", context.MitreTactic);
    }

    [Fact]
    public void Apply_TechniqueOnly_SetsTechniqueWithoutTactic()
    {
        var context = new FindingContext();
        SigmaMitreTagParser.Apply(["attack.t1059.001"], context);

        Assert.Single(context.MitreTags);
        Assert.Equal("attack.t1059.001", context.MitreTechnique);
        Assert.Null(context.MitreTactic);
    }

    [Fact]
    public void Apply_TacticOnly_SetsTacticWithoutTechnique()
    {
        var context = new FindingContext();
        SigmaMitreTagParser.Apply(["attack.execution"], context);

        Assert.Single(context.MitreTags);
        Assert.Null(context.MitreTechnique);
        Assert.Equal("attack.execution", context.MitreTactic);
    }

    [Fact]
    public void Apply_EmptyTags_ClearsMitreFields()
    {
        var context = new FindingContext
        {
            MitreTags = ["attack.old"],
            MitreTechnique = "attack.t0000",
            MitreTactic = "attack.old"
        };

        SigmaMitreTagParser.Apply([], context);

        Assert.Empty(context.MitreTags);
        Assert.Null(context.MitreTechnique);
        Assert.Null(context.MitreTactic);
    }

    [Fact]
    public void Apply_IgnoresNonAttackTags()
    {
        var context = new FindingContext();
        SigmaMitreTagParser.Apply(["custom.tag", "detection.engine"], context);

        Assert.Empty(context.MitreTags);
        Assert.Null(context.MitreTechnique);
        Assert.Null(context.MitreTactic);
    }

    [Fact]
    public void Apply_IsCaseInsensitiveForAttackPrefix()
    {
        var context = new FindingContext();
        SigmaMitreTagParser.Apply(["ATTACK.T1003", "Attack.Credential_Access"], context);

        Assert.Equal(2, context.MitreTags.Count);
        Assert.Equal("ATTACK.T1003", context.MitreTechnique);
        Assert.Equal("Attack.Credential_Access", context.MitreTactic);
    }
}
