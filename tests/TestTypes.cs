// Minimal domain doubles: these tests do not load TinyWall or create firewall filters.
using System;

namespace pylorak.TinyWall
{
    public enum PolicyType { HardBlock, Unrestricted, TcpUdpOnly, RuleList }
    public enum AppExceptionTimer { Permanent = 0, Until_Reboot = -1, For_5_Minutes = 5 }
    public class ExceptionSubject { }
    public class ExecutableSubject : ExceptionSubject
    {
        public string ExecutablePath { get; }
        public ExecutableSubject(string path) { ExecutablePath = path; }
    }
    public class ServiceSubject : ExecutableSubject
    {
        public ServiceSubject(string path) : base(path) { }
    }
    public class ExceptionPolicy
    {
        public PolicyType PolicyType { get; }
        public ExceptionPolicy(PolicyType type) { PolicyType = type; }
    }
    public class FirewallExceptionV3
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public DateTime CreationDate { get; set; } = DateTime.Now;
        public AppExceptionTimer Timer { get; set; }
        public ExceptionSubject Subject { get; set; }
        public ExceptionPolicy Policy { get; set; }
        public bool ChildProcessesInherit { get; set; }
        public FirewallExceptionV3(ExceptionSubject subject, ExceptionPolicy policy)
        {
            Subject = subject;
            Policy = policy;
        }
    }
}
