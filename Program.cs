using System;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using System.Net.NetworkInformation;
using System.Net;



namespace SharpPcap
{
    class HIDS
    {        
        static void Main()
        {
            Console.WriteLine("Alerta, se necesita ser root para ejecutar el programa en us totalidad!");
            string ver = Version.VersionString;
            string dotnet = Environment.Version.ToString();
            Console.WriteLine("Dotnet {0} \n SharpPcap {1} \n \n", dotnet, ver);
            
            //Define una variable que sirve para enlistar los servicios.
            CaptureDeviceList devices = CaptureDeviceList.Instance; 

            //Si no hay servicios, tira mensaje.
            if (devices.Count < 1)
            {
                Console.WriteLine("No hay servicios");
                Console.ReadKey();            
                return;
            }
            
            //En caso de que si hayan servicios, los enlista con un loop.
            Console.WriteLine("Servicios: ");
            //Loop para mostrar todos los servicios.
            foreach (ICaptureDevice dev in devices)
            {
                Console.WriteLine("{0}\n", dev.ToString());
            }

        
            //Para elegir un servicio de la lista.
            Console.Write("Elige un numero de la lista: ");
            int i = Convert.ToInt32(Console.ReadLine());
            ICaptureDevice device = devices[i];

            //
            device.OnPacketArrival += Device_OnPacketArrival;
            
            //Indica tiempo de espera antes de recoger paquetes al ser elegido.
            int readTimeoutMilliseconds = 500;

            //En caso de fallo al agarrar .
            try
            {
                //Promiscuo == agarra todo lo que vea en la red.
                //Normal == agarra solo lo que va dirigido al dispositivo en cuestion
                device.Open(DeviceMode.Normal, readTimeoutMilliseconds);
            }
            catch (DeviceNotReadyException ex)
            {
                
                Console.WriteLine("Error al abrir el dispositivo de captura: " + ex.Message);
                return;
            }
            
            //Para filtrar protocolo, si no hay filtro se muestra demasiado UDP y no vale la pena porque no se ve na'.
            //puerto 443 porque es el usado para pags web con protocolo HTTPS.
            // filter = "{protocolo} port {no. puerto}";
            //Si se deja vacio, va a agarrar todo el trafico correspondiente.
            string filter = "tcp";
            device.Filter = filter;

            //Mostrar en pantalla el servicio elegido. 
            Console.WriteLine("\nServicio: " + device);
            //Detalles.
            Console.WriteLine("-- El siguiente valor va a ser aplicado para el filtro: \"{0}\"", filter);
            Console.WriteLine("-- Capturando trafico de: {0}, presionar 'Enter' para finalizar.", device.Name);
            
            //Libreria captura trafico.
            device.StartCapture();

            //Agarra tecla para termianr.
            Console.ReadKey();

            device.StopCapture();

            device.Close();   
        }

/*#region Setear info del comienzo, 
        static void PackTraffic()
        {       
                //puerto
            ushort tcpSourcePort = 443;
            ushort tcpDestinationPort = 443;
            var tcpPacket = new TcpPacket(tcpSourcePort, tcpDestinationPort);
                //IP
            var ipSourceAddress = IPAddress.Any;
            var ipDestinationAddress = IPAddress.Any;
            var ipPacket = new IPv4Packet(ipSourceAddress, ipDestinationAddress);
                //MAC
            var sourceHwAddress = "74-e5-0b-d6-2a-72";
            var ethernetSourceHwAddress = System.Net.NetworkInformation.PhysicalAddress.Parse(sourceHwAddress);
            var destinationHwAddress = "04-7D-7B-67-C3-48";
            var ethernetDestinationHwAddress = System.Net.NetworkInformation.PhysicalAddress.Parse(destinationHwAddress);

            var ethernetPacket = new EthernetPacket(ethernetSourceHwAddress, ethernetDestinationHwAddress, EthernetPacketType.None);

            ipPacket.PayloadPacket = tcpPacket;
            ethernetPacket.PayloadPacket = ipPacket;

            Console.WriteLine(ethernetPacket.ToString());

            byte[] packetBytes = ethernetPacket.Bytes;
            Console.WriteLine(packetBytes + "\n");
        }
#endregion*/


#region metodos para color para paquete
        static void ColorRed(string value)
        {
            Console.ForegroundColor = ConsoleColor.DarkRed;
            
        }
        static void ColorCyan(string value)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
        }

        static void ColorNormal(string value)
        {
            Console.ForegroundColor = ConsoleColor.Green;
        }
        static void ColorBlanco(string value)
        {
            Console.ForegroundColor = ConsoleColor.White; 
        }        
#endregion


#region Un lio == output de packet
        
        static void Device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            Packet packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            if (packet is EthernetPacket ethernetPacket)
            {
                if (ethernetPacket.PayloadPacket is IpPacket ipPacket)
                {
                    //URL a alertar, agarra y hace proceso a traves del DNS para conseguir la IP.
                    var url = "https://www.roblox.com/";
                    Uri myUri = new Uri(url);
                    var ip = Dns.GetHostAddresses(myUri.Host)[0];

                    //Definir variables como puertos, direcciones, y alerta en caso de ser necesaria.
                    string sourceAddress = ipPacket.SourceAddress.ToString();
                    var destinationAddress = ipPacket.DestinationAddress.ToString(); 
                    string alert = "";
                    int sourcePort = 0;
                    int destinationPort = 0;
    
                    string protocol = ipPacket.Protocol.ToString();                    
                     
                    //Especificar protocolo OSI 4 UDP o TCP.
                    if (ipPacket.PayloadPacket is TcpPacket tcpPacket)
                    {
                        sourcePort = tcpPacket.SourcePort;
                        destinationPort = tcpPacket.DestinationPort;
                    }

                    else if (ipPacket.PayloadPacket is UdpPacket udpPacket)
                    {
                        sourcePort = udpPacket.SourcePort;
                        destinationPort = udpPacket.DestinationPort;
                    }

                    //Asignacion de los colores declarados.
                    if (destinationAddress == ip.ToString() || sourceAddress == ip.ToString())
                    {
                        ColorRed(destinationAddress);
                        alert = "Alerta, alguien ha entrado a Roblox!";
                    }
                    
                    else if (sourceAddress == "10.0.0.1")
                    {
                        ColorCyan(destinationAddress);
                    }

                    else if (protocol == "TCP")
                    {
                        ColorBlanco(protocol);
                    }
                    else
                    {
                        ColorNormal(destinationAddress);
                    }

                    //Output para los paquetes.
                    DateTime time = e.Packet.Timeval.Date;
                    int len = e.Packet.Data.Length;
                    Console.WriteLine("{0}:{1}:{2},{3} SourceIP={4}, sourcePort={7}, DestinationIP={5}, DestinationPort={8} Len={6}, protocol={9} {10}", 
                        time.Hour, time.Minute, time.Second, time.Millisecond, sourceAddress, destinationAddress, len, sourcePort, destinationPort, protocol, alert);
                    
                }
            }
        }
#endregion
    }

}

