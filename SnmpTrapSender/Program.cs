using System;
using System.Collections.Generic;
using System.Net;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;

namespace SnmpTrapSender
{
    class Program
    {
        // Simulation State
        static string PortStatus = "DOWN";
        static int DigitalInput = 0;
        static int DigitalOutput = 0;
        static readonly int PortNumber = 1;

        // Configuration
        static string ReceiverIp = "127.0.0.1";
        static int ReceiverPort = 162;
        static readonly string Community = "public";

        // OIDs
        // Base: 1.3.6.1.4.1.9999
        static readonly string OidPortStatus = "1.3.6.1.4.1.9999.1.1";
        static readonly string OidDigitalInput = "1.3.6.1.4.1.9999.1.2";
        static readonly string OidDigitalOutput = "1.3.6.1.4.1.9999.1.3";
        static readonly string OidPortNumber = "1.3.6.1.4.1.9999.1.4"; // Custom for "Port Number"

        static void Main(string[] args)
        {
            // Parse args for initial port configuration
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--port" && i + 1 < args.Length && int.TryParse(args[i + 1], out int p))
                {
                    ReceiverPort = p;
                }
            }

            Console.WriteLine("=== Simulated PoE Switch (Trap Sender) ===");
            Console.WriteLine("Sending SNMP v2c Traps...");

            while (true)
            {
                Console.WriteLine("\n--------------------------------");
                Console.WriteLine($"Target: {ReceiverIp}:{ReceiverPort}");
                Console.WriteLine($"[Current State] Port {PortNumber}: {PortStatus} | DI: {DigitalInput} | DO: {DigitalOutput}");
                Console.WriteLine("--------------------------------");
                Console.WriteLine("1. Set Port UP");
                Console.WriteLine("2. Set Port DOWN");
                Console.WriteLine("3. Toggle Digital Input");
                Console.WriteLine("4. Toggle Digital Output");
                Console.WriteLine("5. Exit");
                Console.WriteLine("6. Configure Target IP/Port");
                Console.Write("Select action: ");

                var key = Console.ReadKey(intercept: true);
                Console.WriteLine(key.KeyChar);

                string? triggerOid = null;

                switch (key.KeyChar)
                {
                    case '1':
                        PortStatus = "UP";
                        triggerOid = OidPortStatus;
                        break;
                    case '2':
                        PortStatus = "DOWN";
                        triggerOid = OidPortStatus;
                        break;
                    case '3':
                        DigitalInput = DigitalInput == 0 ? 1 : 0;
                        triggerOid = OidDigitalInput;
                        break;
                    case '4':
                        DigitalOutput = DigitalOutput == 0 ? 1 : 0;
                        triggerOid = OidDigitalOutput;
                        break;
                    case '5':
                        Console.WriteLine("Exiting...");
                        return;
                    case '6':
                        ConfigureTarget();
                        continue;
                    default:
                        Console.WriteLine("Invalid option. Please try again.");
                        continue;
                }

                if (triggerOid != null)
                {
                    SendTrap(triggerOid);
                }
            }
        }

        static void ConfigureTarget()
        {
            Console.Write($"Enter Target IP (Default: {ReceiverIp}): ");
            string? ipInput = Console.ReadLine();
            if (!string.IsNullOrWhiteSpace(ipInput) && IPAddress.TryParse(ipInput, out _))
            {
                ReceiverIp = ipInput;
            }

            Console.Write($"Enter Target Port (Default: {ReceiverPort}): ");
            string? portInput = Console.ReadLine();
            if (!string.IsNullOrWhiteSpace(portInput) && int.TryParse(portInput, out int p))
            {
                ReceiverPort = p;
            }
        }

        static void SendTrap(string trapOidValue)
        {
            try
            {
                // Construct payload with all current states
                var variables = new List<Variable>
                {
                    new Variable(new ObjectIdentifier(OidPortNumber), new Integer32(PortNumber)),
                    new Variable(new ObjectIdentifier(OidPortStatus), new OctetString(PortStatus)),
                    new Variable(new ObjectIdentifier(OidDigitalInput), new Integer32(DigitalInput)),
                    new Variable(new ObjectIdentifier(OidDigitalOutput), new Integer32(DigitalOutput))
                };

                // Use the event triggering OID as the Trap OID
                var trapOid = new ObjectIdentifier(trapOidValue);

                // Send Trap
                Messenger.SendTrapV2(
                    0, // Request ID
                    VersionCode.V2,
                    new IPEndPoint(IPAddress.Parse(ReceiverIp), ReceiverPort),
                    new OctetString(Community),
                    trapOid, // snmpTrapOID
                    (uint)(Environment.TickCount / 10), // sysUpTime (milliseconds to centiseconds)
                    variables
                );

                Console.WriteLine($"Trap sent! (OID: {trapOidValue})");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending trap: {ex.Message}");
            }
        }
    }
}
