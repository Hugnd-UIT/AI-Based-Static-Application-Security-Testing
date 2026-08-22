using System.Diagnostics;

namespace Benchmark.CSharp.Services
{
    public class SystemUtils
    {
        public void PingTarget(string ipAddress)
        {
            // Command Injection [CWE-78]
            string command = "ping -c 4 " + ipAddress;
            Process.Start("cmd.exe", "/c " + command);
        }
    }
}
