
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;

namespace SnmpTrapListener
{
    class Program
    {
        static void Main(string[] args)
        {
            int port = 162;

            // Simple argument parsing
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--port" && i + 1 < args.Length && int.TryParse(args[i + 1], out int p))
                {
                    port = p;
                }
            }

            Console.WriteLine("=== SNMP Trap Listener (v2c) ===");
            Console.WriteLine($"Attempting to listen on UDP port {port}...");
            
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            IPEndPoint endPoint = new IPEndPoint(IPAddress.Any, port);

            try
            {
                socket.Bind(endPoint);
            }
            catch (SocketException ex)
            {
                Console.WriteLine($"[Warning] Failed to bind to port {port}: {ex.Message}");

                // If default port 162 fails, try fallback port 16200
                if (port == 162)
                {
                    int fallbackPort = 16200;
                    Console.WriteLine($"Attempting fallback to port {fallbackPort}...");
                    try
                    {
                        endPoint = new IPEndPoint(IPAddress.Any, fallbackPort);
                        socket.Bind(endPoint);
                        port = fallbackPort; // Update current port
                        Console.WriteLine($"Successfully bound to fallback port {port}.");
                        Console.WriteLine("IMPORTANT: Please configure the Sender to use this port.");
                    }
                    catch (Exception fallbackEx)
                    {
                        Console.WriteLine($"[CRITICAL] Error binding to fallback port {fallbackPort}: {fallbackEx.Message}");
                        Console.WriteLine("Press any key to exit...");
                        try { Console.ReadKey(); } catch { }
                        return;
                    }
                }
                else
                {
                    Console.WriteLine("Press any key to exit...");
                    try { Console.ReadKey(); } catch { }
                    return;
                }
            }

            Console.WriteLine($"Listening on UDP port {port}...");

            byte[] buffer = new byte[65535];

            while (true)
            {
                try
                {
                    EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
                    int count = socket.ReceiveFrom(buffer, ref remote);
                    byte[] data = new byte[count];
                    Array.Copy(buffer, data, count);

                    ProcessData(data, (IPEndPoint)remote);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Error] receiving data: {ex.Message}");
                }
            }
        }

        static void ProcessData(byte[] data, IPEndPoint sender)
        {
            try
            {
                // Parse messages. For v1/v2c, UserRegistry is not strictly used but required by signature in some versions.
                IList<ISnmpMessage> messages = MessageFactory.ParseMessages(data, new UserRegistry());

                foreach (ISnmpMessage message in messages)
                {
                    // Check for v2c Trap
                    if (message is TrapV2Message trap)
                    {
                        if (trap.Community().ToString() != "public")
                        {
                            Console.WriteLine($"Ignored trap from {sender.Address} with community '{trap.Community()}'");
                            continue;
                        }

                        DisplayTrap(trap, sender);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Error] parsing SNMP message: {ex.Message}");
            }
        }

        static void DisplayTrap(TrapV2Message trap, IPEndPoint sender)
        {
            Console.WriteLine("--------------------------------------------------");
            Console.WriteLine($"Trap received from {sender.Address}");
            Console.WriteLine($"Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");

            var variables = trap.Variables();

            // V2 Trap Variables:
            // Index 0: sysUpTime (1.3.6.1.2.1.1.3.0)
            // Index 1: snmpTrapOID (1.3.6.1.6.3.1.1.4.1.0)
            // Index 2+: Payload

            if (variables.Count > 1)
            {
                Console.WriteLine($"OID: {variables[1].Data}");
            }

            // Iterate over all variables
            foreach (var variable in variables)
            {
                string oid = variable.Id.ToString();
                string value = variable.Data.ToString();

                // Print generic OID/Value pair
                Console.WriteLine($"  [{oid}]: {value}");

                // Check against known OIDs for friendly display
                switch (oid)
                {
                    case "1.3.6.1.4.1.9999.1.4":
                        Console.WriteLine($"   => Port: {value}");
                        break;
                    case "1.3.6.1.4.1.9999.1.1":
                        Console.WriteLine($"   => Port Status: {value}");
                        break;
                    case "1.3.6.1.4.1.9999.1.2":
                        Console.WriteLine($"   => Digital Input: {value}");
                        break;
                    case "1.3.6.1.4.1.9999.1.3":
                        Console.WriteLine($"   => Digital Output: {value}");
                        break;
                }
            }
        }
    }
}
