using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

internal static class WildcardCreationTests
{
    private static int checks;
    private static Type exceptionType;
    private static Type executableType;
    private static MethodInfo factory;
    private static MethodInfo serialize;
    private static MethodInfo deserialize;

    private static object Read(object value, string property)
    {
        return value.GetType().GetProperty(property).GetValue(value, null);
    }

    private static void Set(object value, string property, object replacement)
    {
        value.GetType().GetProperty(property).SetValue(value, replacement, null);
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
        ++checks;
        Console.WriteLine("PASS: " + message);
    }

    private static object Create(object previous, string pattern)
    {
        return factory.Invoke(null, new object[] { previous, pattern });
    }

    private static object RoundTrip(object exception)
    {
        var bytes = (byte[])serialize.Invoke(null, new[] { exception });
        Check(Encoding.UTF8.GetString(bytes).IndexOf("InvalidSubject", StringComparison.Ordinal) < 0,
            "Serialized wildcard contains no invalid placeholder");
        return deserialize.Invoke(null, new object[] { bytes, exception });
    }

    private static void CheckReplacement(object previous, object replacement, string pattern)
    {
        Check(Read(replacement, "Subject").GetType() == executableType, "Wildcard uses an executable subject");
        Check((string)Read(Read(replacement, "Subject"), "ExecutablePath") == pattern, "Wildcard path is retained");
        Check(!Read(replacement, "Id").Equals(Read(previous, "Id")), "Wildcard receives a fresh exception ID");
        Check(Read(replacement, "Timer").Equals(Read(previous, "Timer")), "Rule lifetime is retained");
        Check(Read(replacement, "CreationDate").Equals(Read(previous, "CreationDate")), "Creation date is retained");
        Check(Read(replacement, "ChildProcessesInherit").Equals(Read(previous, "ChildProcessesInherit")), "Child-process inheritance selection is retained");
        Check(!ReferenceEquals(Read(replacement, "Policy"), Read(previous, "Policy")), "Policy is deep-cloned");
    }

    private static void Test(Assembly app)
    {
        exceptionType = app.GetType("pylorak.TinyWall.FirewallExceptionV3", true);
        executableType = app.GetType("pylorak.TinyWall.ExecutableSubject", true);
        factory = app.GetType("pylorak.TinyWall.ApplicationExceptionForm", true)
            .GetMethod("CreateWildcardException", BindingFlags.NonPublic | BindingFlags.Static);
        Check(factory != null, "Compiled wildcard creation method exists");

        var helper = app.GetType("pylorak.TinyWall.SerializationHelper", true);
        foreach (var method in helper.GetMethods(BindingFlags.Public | BindingFlags.Static))
        {
            var parameters = method.GetParameters();
            if (method.Name == "Serialize" && parameters.Length == 1)
                serialize = method.MakeGenericMethod(exceptionType);
            if (method.Name == "Deserialize" && parameters.Length == 2 && parameters[0].ParameterType == typeof(byte[]))
                deserialize = method.MakeGenericMethod(exceptionType);
        }
        Check(serialize != null && deserialize != null, "Real TinyWall JSON serializer is available");

        const string pattern = @"C:\Users\Test\AppData\Local\OpenAI\Codex\bin\**\codex.exe";
        var empty = exceptionType.GetProperty("Default").GetValue(null, null);
        var emptyId = Read(empty, "Id");
        bool reproduced = false;
        try { serialize.Invoke(null, new[] { empty }); }
        catch (TargetInvocationException error)
        {
            reproduced = error.InnerException.GetType().FullName == "System.Text.Json.JsonException"
                && error.InnerException.Message.IndexOf("InvalidSubject", StringComparison.Ordinal) >= 0;
            if (!reproduced) throw new InvalidOperationException("Unexpected failure while reproducing the original bug.", error.InnerException);
        }
        Check(reproduced, "Default exception reproduces the reported InvalidSubject serialization error");

        var created = Create(empty, pattern);
        CheckReplacement(empty, created, pattern);
        Check(!(bool)Read(created, "ChildProcessesInherit"), "New wildcard defaults to no child-process inheritance");
        Check(Read(empty, "Subject").GetType().Name == "InvalidSubject", "New-rule placeholder is not mutated");
        Check(Read(empty, "Id").Equals(emptyId), "New-rule source ID is not mutated");
        var createdReloaded = RoundTrip(created);
        Check(Read(createdReloaded, "Id").Equals(Read(created, "Id")), "New wildcard survives JSON serialization");
        Check((string)Read(Read(createdReloaded, "Policy"), "AllowedRemoteTcpConnectPorts") == "*",
            "New wildcard retains default TCP policy");
        Check((string)Read(Read(createdReloaded, "Policy"), "AllowedRemoteUdpConnectPorts") == "*",
            "New wildcard retains default UDP policy");

        var subject = Activator.CreateInstance(executableType, new object[] { @"C:\Apps\app.exe" });
        var policy = Activator.CreateInstance(app.GetType("pylorak.TinyWall.TcpUdpPolicy", true));
        Set(policy, "AllowedRemoteTcpConnectPorts", "443,8443");
        Set(policy, "AllowedRemoteUdpConnectPorts", "53");
        Set(policy, "AllowedLocalUdpListenerPorts", "5353");
        Set(policy, "LocalNetworkOnly", true);
        var existing = Activator.CreateInstance(exceptionType, new[] { subject, policy });
        var timerType = app.GetType("pylorak.TinyWall.AppExceptionTimer", true);
        Set(existing, "Timer", Enum.Parse(timerType, "For_1_Hour"));
        Set(existing, "CreationDate", new DateTime(2026, 10, 9, 0, 0, 0, DateTimeKind.Utc));
        Set(existing, "ChildProcessesInherit", true);
        var originalId = Read(existing, "Id");
        var edited = Create(existing, pattern);
        CheckReplacement(existing, edited, pattern);
        var editedReloaded = RoundTrip(edited);
        foreach (string property in new[] { "AllowedRemoteTcpConnectPorts", "AllowedRemoteUdpConnectPorts",
            "AllowedLocalTcpListenerPorts", "AllowedLocalUdpListenerPorts", "LocalNetworkOnly" })
        {
            Check(Equals(Read(Read(editedReloaded, "Policy"), property), Read(policy, property)),
                "Edited wildcard retains policy field " + property);
        }
        Set(Read(edited, "Policy"), "AllowedRemoteTcpConnectPorts", "80");
        Check((string)Read(policy, "AllowedRemoteTcpConnectPorts") == "443,8443", "Editing cloned policy leaves source unchanged");
        Check((bool)Read(existing, "ChildProcessesInherit"), "Source child-process option is unchanged");
        Check(Read(existing, "Id").Equals(originalId), "Existing source ID is unchanged");
        Check((string)Read(Read(existing, "Subject"), "ExecutablePath") == @"C:\Apps\app.exe", "Existing source path is unchanged");
        Check(Read(editedReloaded, "Timer").Equals(Read(existing, "Timer")), "Timed wildcard survives JSON serialization");

        var blockPolicy = Activator.CreateInstance(app.GetType("pylorak.TinyWall.HardBlockPolicy", true));
        var blocked = Activator.CreateInstance(exceptionType, new[] { subject, blockPolicy });
        Set(blocked, "ChildProcessesInherit", true);
        var blockedWildcard = Create(blocked, @"C:\Apps\Blocked\**\*.exe");
        CheckReplacement(blocked, blockedWildcard, @"C:\Apps\Blocked\**\*.exe");
        Check(Read(RoundTrip(blockedWildcard), "Policy").GetType() == blockPolicy.GetType(),
            "Explicit wildcard block policy survives JSON serialization");
    }

    private static void TestFolderPicker(Assembly app, string appPath)
    {
        var form = app.GetType("pylorak.TinyWall.WildcardPathForm", true);
        var patternFactory = form.GetMethod("CreateFolderPattern", BindingFlags.Static | BindingFlags.NonPublic);
        Check(patternFactory != null, "Folder-wide pattern factory exists in the compiled app");
        string recursive = (string)patternFactory.Invoke(null, new object[] { @"C:\Apps\Example\", true });
        Check(recursive == @"C:\Apps\Example\**\*.exe", "Selecting a recursive folder creates an all-executable wildcard");
        Check((string)patternFactory.Invoke(null, new object[] { @"C:\Apps\Example", false }) == @"C:\Apps\Example\*.exe",
            "Selecting a non-recursive folder creates a shallow all-executable wildcard");
        var patternType = app.GetType("pylorak.TinyWall.ExecutablePathPattern", true);
        var parsed = Activator.CreateInstance(patternType, new object[] { recursive });
        var matches = patternType.GetMethod("Matches");
        Check((bool)matches.Invoke(parsed, new object[] { @"C:\Apps\Example\first.exe" }), "Folder wildcard includes any root executable");
        Check((bool)matches.Invoke(parsed, new object[] { @"C:\Apps\Example\deep\nested\second.exe" }), "Folder wildcard includes differently named nested executables");
        Check(!(bool)matches.Invoke(parsed, new object[] { @"C:\Apps\Example-other\first.exe" }), "Folder wildcard excludes sibling folders");
        Check(!(bool)matches.Invoke(parsed, new object[] { @"C:\Apps\Example\deep\notes.txt" }), "Folder wildcard excludes non-executable files");

        var picker = app.GetType("pylorak.TinyWall.ModernFolderPicker", true);
        var dialogInterface = picker.GetNestedType("IFileDialog", BindingFlags.NonPublic);
        var itemInterface = picker.GetNestedType("IShellItem", BindingFlags.NonPublic);
        Check(dialogInterface.GUID == new Guid("42F85136-DB7E-439C-85F1-E4075D135FC8"), "Picker uses the Windows common file-dialog interface");
        object dialog = null, folder = null;
        IntPtr name = IntPtr.Zero;
        try
        {
            string initialFolder = Path.GetDirectoryName(Path.GetFullPath(appPath));
            dialog = picker.GetMethod("CreateDialog", BindingFlags.NonPublic | BindingFlags.Static)
                .Invoke(null, new object[] { initialFolder });
            Check(Marshal.IsComObject(dialog), "Real native dialog initializes without showing UI");
            var optionsArgs = new object[] { (uint)0 };
            dialogInterface.GetMethod("GetOptions").Invoke(dialog, optionsArgs);
            uint options = (uint)optionsArgs[0];
            Check((options & 0x20) != 0, "Native dialog selects folders");
            Check((options & 0x40) != 0, "Native dialog returns filesystem folders only");
            Check((options & 0x800) != 0, "Native dialog requires an existing folder");
            Check((options & 0x02000000) != 0, "Native dialog does not add selections to Windows recent items");
            var folderArgs = new object[] { null };
            dialogInterface.GetMethod("GetFolder").Invoke(dialog, folderArgs);
            folder = folderArgs[0];
            var nameArgs = new object[] { (uint)0x80058000, IntPtr.Zero };
            itemInterface.GetMethod("GetDisplayName").Invoke(folder, nameArgs);
            name = (IntPtr)nameArgs[1];
            Check(string.Equals(Marshal.PtrToStringUni(name), initialFolder, StringComparison.OrdinalIgnoreCase),
                "Native dialog initializes to the current wildcard folder");
        }
        finally
        {
            if (name != IntPtr.Zero) Marshal.FreeCoTaskMem(name);
            if (folder != null) Marshal.ReleaseComObject(folder);
            if (dialog != null) Marshal.ReleaseComObject(dialog);
        }
    }

    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            if (args.Length != 1) throw new ArgumentException("Provide the TinyWall executable path.");
            var app = Assembly.LoadFrom(args[0]);
            Test(app);
            TestFolderPicker(app, args[0]);
            Console.WriteLine("All " + checks + " compiled wildcard creation checks passed.");
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error);
            return 1;
        }
    }
}
