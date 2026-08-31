namespace WindowsIncidentAnalyzer.Infrastructure;

/// <summary>
/// Locale-invariant and Russian/English aliases for Windows identities that appear in Event XML.
/// Channel names and EventData field names stay English; account/group values and OS error text do not.
/// </summary>
public static class WindowsLocale
{
    /// <summary>
    /// Fixed well-known account SIDs (Microsoft WELL_KNOWN_SID_TYPE / well-known SIDs).
    /// Domain-relative RIDs (500 Administrator, 512 Domain Admins, …) are not listed; match those by RID.
    /// NT SERVICE / IIS / DWM SIDs are hashed — use <see cref="IsWellKnownAccountSid"/>.
    /// </summary>
    public static readonly HashSet<string> WellKnownAccountSids = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-0-0",
        "S-1-1-0",
        "S-1-2-0",
        "S-1-2-1",
        "S-1-3-0",
        "S-1-3-1",
        "S-1-3-2",
        "S-1-3-3",
        "S-1-3-4",
        "S-1-4",
        "S-1-5",
        "S-1-5-1",
        "S-1-5-2",
        "S-1-5-3",
        "S-1-5-4",
        "S-1-5-6",
        "S-1-5-7",
        "S-1-5-8",
        "S-1-5-9",
        "S-1-5-10",
        "S-1-5-11",
        "S-1-5-12",
        "S-1-5-13",
        "S-1-5-14",
        "S-1-5-15",
        "S-1-5-17",
        "S-1-5-18",
        "S-1-5-19",
        "S-1-5-20",
        "S-1-5-32",
        "S-1-5-32-544",
        "S-1-5-32-545",
        "S-1-5-32-546",
        "S-1-5-32-547",
        "S-1-5-32-548",
        "S-1-5-32-549",
        "S-1-5-32-550",
        "S-1-5-32-551",
        "S-1-5-32-552",
        "S-1-5-32-554",
        "S-1-5-32-555",
        "S-1-5-32-556",
        "S-1-5-32-557",
        "S-1-5-32-558",
        "S-1-5-32-559",
        "S-1-5-32-560",
        "S-1-5-32-561",
        "S-1-5-32-562",
        "S-1-5-32-568",
        "S-1-5-32-569",
        "S-1-5-32-573",
        "S-1-5-32-574",
        "S-1-5-32-575",
        "S-1-5-32-576",
        "S-1-5-32-577",
        "S-1-5-32-578",
        "S-1-5-32-579",
        "S-1-5-32-580",
        "S-1-5-32-581",
        "S-1-5-32-582",
        "S-1-5-32-583",
        "S-1-5-33",
        "S-1-5-64-10",
        "S-1-5-64-14",
        "S-1-5-64-21",
        "S-1-5-65-1",
        "S-1-5-80",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
        "S-1-5-84-0-0-0-0-0",
        "S-1-5-87-0",
        "S-1-5-90-0",
        "S-1-5-96-0",
        "S-1-5-1000",
        "S-1-5-113",
        "S-1-5-114",
        "S-1-15-2-1",
        "S-1-16-0",
        "S-1-16-4096",
        "S-1-16-8192",
        "S-1-16-8448",
        "S-1-16-12288",
        "S-1-16-16384",
        "S-1-18-1",
        "S-1-18-2",
        "S-1-18-3",
        "S-1-18-4",
        "S-1-18-5",
        "S-1-18-6"
    };

    public static readonly string[] WellKnownAccountSidPrefixes =
    [
        "S-1-5-5-",
        "S-1-5-80-",
        "S-1-5-82-",
        "S-1-5-83-",
        "S-1-5-84-",
        "S-1-5-90-",
        "S-1-5-94-",
        "S-1-5-96-",
        "S-1-15-2-",
        "S-1-15-3-"
    ];

    private static readonly HashSet<string> ServicePrincipalSids = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-5-7",
        "S-1-5-17",
        "S-1-5-18",
        "S-1-5-19",
        "S-1-5-20",
        "S-1-5-80",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
        "S-1-5-84-0-0-0-0-0",
        "S-1-5-90-0",
        "S-1-5-96-0"
    };

    private static readonly string[] ServicePrincipalSidPrefixes =
    [
        "S-1-5-80-",
        "S-1-5-82-",
        "S-1-5-83-",
        "S-1-5-84-",
        "S-1-5-90-",
        "S-1-5-96-"
    ];

    public static readonly HashSet<string> BuiltInServiceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "SYSTEM",
        "СИСТЕМА",
        "ANONYMOUS LOGON",
        "АНОНИМНЫЙ ВХОД",
        "LOCAL SERVICE",
        "ЛОКАЛЬНАЯ СЛУЖБА",
        "NETWORK SERVICE",
        "СЕТЕВАЯ СЛУЖБА",
        "IUSR",
        "IUSR_MACHINE",
        "DefaultAppPool",
        "TrustedInstaller",
        "FONT DRIVER HOST",
        "WINDOW MANAGER"
    };

    public static readonly HashSet<string> PrivilegedGroupSids = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-5-32-544",
        "S-1-5-32-548",
        "S-1-5-32-551",
        "S-1-5-32-555"
    };

    public static readonly HashSet<string> PrivilegedGroupRids = new(StringComparer.OrdinalIgnoreCase)
    {
        "512",
        "518",
        "519"
    };

    public static readonly string[] PrivilegedGroupNames =
    [
        "Administrators",
        "Администраторы",
        "Domain Admins",
        "Администраторы домена",
        "Enterprise Admins",
        "Администраторы предприятия",
        "Schema Admins",
        "Администраторы схемы",
        "Backup Operators",
        "Операторы архива",
        "Операторы резервного копирования",
        "Account Operators",
        "Операторы учета",
        "Операторы учёта",
        "Remote Desktop Users",
        "Пользователи удаленного рабочего стола",
        "Пользователи удалённого рабочего стола"
    ];

    public static readonly string[] UserProfileSuspiciousPaths =
    [
        @"\Temp\",
        @"\AppData\Local\Temp\",
        @"\AppData\",
        @"\Downloads\",
        @"\Загрузки\",
        @"\Documents\",
        @"\Документы\",
        @"\Desktop\",
        @"\Рабочий стол\"
    ];

    public static bool IsNullSid(string? sid) =>
        !string.IsNullOrWhiteSpace(sid) && sid.Trim().Equals("S-1-0-0", StringComparison.OrdinalIgnoreCase);

    public static bool IsWellKnownAccountSid(string? sid)
    {
        if (string.IsNullOrWhiteSpace(sid))
        {
            return false;
        }

        var trimmed = sid.Trim();
        if (WellKnownAccountSids.Contains(trimmed))
        {
            return true;
        }

        return StartsWithAny(trimmed, WellKnownAccountSidPrefixes);
    }

    public static bool IsBuiltInServiceSid(string? sid)
    {
        if (string.IsNullOrWhiteSpace(sid))
        {
            return false;
        }

        var trimmed = sid.Trim();
        return ServicePrincipalSids.Contains(trimmed) || StartsWithAny(trimmed, ServicePrincipalSidPrefixes);
    }

    public static bool IsBuiltInServiceAccountName(string? user)
    {
        if (string.IsNullOrWhiteSpace(user))
        {
            return false;
        }

        var name = SamAccountName(user);
        if (name.EndsWith('$') || BuiltInServiceNames.Contains(name))
        {
            return true;
        }

        return name.StartsWith("DWM-", StringComparison.OrdinalIgnoreCase)
               || name.StartsWith("UMFD-", StringComparison.OrdinalIgnoreCase)
               || name.StartsWith("IUSR_", StringComparison.OrdinalIgnoreCase)
               || name.StartsWith("IWAM_", StringComparison.OrdinalIgnoreCase);
    }

    private static bool StartsWithAny(string value, string[] prefixes)
    {
        foreach (var prefix in prefixes)
        {
            if (value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    public static string SamAccountName(string user)
    {
        var trimmed = user.Trim();
        var slash = trimmed.LastIndexOf('\\');
        return slash >= 0 && slash < trimmed.Length - 1 ? trimmed[(slash + 1)..] : trimmed;
    }

    public static bool IsPrivilegedGroup(string? name, string? sid, IEnumerable<string>? additionalNames = null)
    {
        if (IsPrivilegedGroupSid(sid))
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            return false;
        }

        foreach (var candidate in PrivilegedGroupNames)
        {
            if (name.Contains(candidate, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        if (additionalNames is null)
        {
            return false;
        }

        foreach (var candidate in additionalNames)
        {
            if (!string.IsNullOrWhiteSpace(candidate) && name.Contains(candidate, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    public static bool IsPrivilegedGroupSid(string? sid)
    {
        if (string.IsNullOrWhiteSpace(sid))
        {
            return false;
        }

        var trimmed = sid.Trim();
        if (PrivilegedGroupSids.Contains(trimmed))
        {
            return true;
        }

        var lastDash = trimmed.LastIndexOf('-');
        if (lastDash < 0 || lastDash == trimmed.Length - 1)
        {
            return false;
        }

        return PrivilegedGroupRids.Contains(trimmed[(lastDash + 1)..]);
    }

    public static bool LooksLikeAccessDenied(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return false;
        }

        return message.Contains("unauthorized", StringComparison.OrdinalIgnoreCase)
               || message.Contains("access is denied", StringComparison.OrdinalIgnoreCase)
               || message.Contains("access denied", StringComparison.OrdinalIgnoreCase)
               || message.Contains("отказано в доступе", StringComparison.OrdinalIgnoreCase)
               || message.Contains("отказ в доступе", StringComparison.OrdinalIgnoreCase)
               || message.Contains("недостаточно прав", StringComparison.OrdinalIgnoreCase)
               || message.Contains("недостаточно привилегий", StringComparison.OrdinalIgnoreCase);
    }

    public static bool MatchesSuspiciousPath(string haystack, IEnumerable<string>? configuredPaths)
    {
        if (string.IsNullOrEmpty(haystack))
        {
            return false;
        }

        foreach (var fragment in UserProfileSuspiciousPaths)
        {
            if (haystack.Contains(fragment, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        if (configuredPaths is null)
        {
            return false;
        }

        foreach (var fragment in configuredPaths)
        {
            if (!string.IsNullOrWhiteSpace(fragment) && haystack.Contains(fragment, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    public static IEnumerable<string> MatchingSuspiciousPaths(string haystack, IEnumerable<string>? configuredPaths)
    {
        if (string.IsNullOrEmpty(haystack))
        {
            yield break;
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var fragment in UserProfileSuspiciousPaths.Concat(configuredPaths ?? []))
        {
            if (string.IsNullOrWhiteSpace(fragment) || !seen.Add(fragment))
            {
                continue;
            }

            if (haystack.Contains(fragment, StringComparison.OrdinalIgnoreCase))
            {
                yield return fragment;
            }
        }
    }
}
