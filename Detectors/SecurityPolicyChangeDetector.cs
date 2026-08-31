using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public sealed class SecurityPolicyChangeDetector(IOptions<DetectionRulesOptions> options) : SignatureRuleBase
{
    private readonly KnownThreatSignaturesOptions _options = options.Value.KnownThreatSignatures;

    public override string Name => "SecurityPolicyChange";
    public override string Description => "Surfaces high-impact account, group, trust, authentication-policy, and firewall changes.";
    public override DetectionSeverity Severity => DetectionSeverity.Medium;
    public override bool IsEnabled => _options.Enabled;

    protected override IReadOnlyList<DetectionSignature> Signatures { get; } =
    [
        new("SP-001", "User account enabled", "A disabled user account was enabled.", DetectionSeverity.Low, [4722]),
        new("SP-002", "User password change attempted", "An account password change was attempted.", DetectionSeverity.Low, [4723]),
        new("SP-003", "User password reset", "An account password was reset by another principal.", DetectionSeverity.Medium, [4724]),
        new("SP-004", "User account disabled", "A user account was disabled.", DetectionSeverity.Low, [4725]),
        new("SP-005", "User account deleted", "A user account was deleted.", DetectionSeverity.Medium, [4726]),
        new("SP-006", "User account changed", "Security-sensitive attributes of a user account changed.", DetectionSeverity.Medium, [4738]),
        new("SP-007", "User account unlocked", "A locked user account was unlocked.", DetectionSeverity.Low, [4767]),
        new("SP-008", "User account renamed", "A user account name was changed.", DetectionSeverity.Medium, [4781]),
        new("SP-009", "DSRM password changed", "The Directory Services Restore Mode administrator password was changed.", DetectionSeverity.Critical, [4794]),
        new("SP-010", "Member added to security group", "An account was added to a global, local, or universal security group.", DetectionSeverity.Medium, [4728, 4732, 4756]),
        new("SP-011", "Member removed from security group", "An account was removed from a global, local, or universal security group.", DetectionSeverity.Medium, [4729, 4733, 4757]),
        new("SP-012", "User right assigned", "A user right was assigned to an account.", DetectionSeverity.High, [4704]),
        new("SP-013", "User right removed", "A user right was removed from an account.", DetectionSeverity.Medium, [4705]),
        new("SP-014", "System security access granted", "System security access was granted to an account.", DetectionSeverity.High, [4717]),
        new("SP-015", "System security access removed", "System security access was removed from an account.", DetectionSeverity.Medium, [4718]),
        new("SP-016", "Kerberos policy changed", "Domain Kerberos policy was changed.", DetectionSeverity.High, [4713]),
        new("SP-017", "Domain policy changed", "Domain password, lockout, or security policy was changed.", DetectionSeverity.High, [4739]),
        new("SP-018", "Domain trust created", "A trust relationship with another domain was created.", DetectionSeverity.High, [4706]),
        new("SP-019", "Domain trust removed", "A trust relationship with another domain was removed.", DetectionSeverity.High, [4707]),
        new("SP-020", "Domain trust modified", "A domain trust relationship was modified.", DetectionSeverity.High, [4716]),
        new("SP-021", "Object audit settings changed", "Auditing settings on an object were changed.", DetectionSeverity.Medium, [4907]),
        new("SP-022", "Firewall rule added", "A Windows Firewall rule was added.", DetectionSeverity.Medium, [4946]),
        new("SP-023", "Firewall rule modified", "A Windows Firewall rule was modified.", DetectionSeverity.Medium, [4947]),
        new("SP-024", "Firewall rule deleted", "A Windows Firewall rule was deleted.", DetectionSeverity.High, [4948]),
        new("SP-025", "Firewall settings restored", "Windows Firewall settings were restored to defaults.", DetectionSeverity.High, [4950]),
        new("SP-026", "Authentication package loaded", "An authentication package was loaded by LSA.", DetectionSeverity.Medium, [4610]),
        new("SP-027", "Trusted logon process registered", "A trusted logon process registered with LSA.", DetectionSeverity.High, [4611]),
        new("SP-028", "Authentication notification package loaded", "An authentication notification package was loaded by LSA.", DetectionSeverity.Medium, [4614])
    ];
}
