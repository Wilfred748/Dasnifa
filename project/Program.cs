using System;
using SharpPcap;
using SharpPcap.Tunneling;
using SharpPcap.LibPcap;
using PacketDotNet;
using System.Net.NetworkInformation;



namespace SharpPcap
{

    
    class HIDS
    {
        
        //para mostrar los servicios que estan corriendo en el momento
        static void Main(string[] args)
        {
            PackTraffic();
            Interfaces();

            //define una variable que sirve para enlistar los servicios
            CaptureDeviceList devices = CaptureDeviceList.Instance; 

            //si no hay servicios, tira mensaje
            if (devices.Count < 1)
            {
                Console.WriteLine("No hay servicios");
                Console.ReadKey();            
                return;
            }

            Console.WriteLine("Servicios: ");

            //loop para los servicios
            foreach (ICaptureDevice dev in devices)
            {
                Console.WriteLine("{0}\n", dev.ToString());
            }

        
            //Elegir un servicio de la lista
            Console.Write("Elige un numero de la lista: ");
            int i = Convert.ToInt32(Console.ReadLine());
            ICaptureDevice device = devices[i];

            device.OnPacketArrival += Device_OnPacketArrival();

            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceModes.Promiscuous, readTimeoutMilliseconds);

            Console.WriteLine("-- Listening on {0}, enter pa parar....", device.Description);

            device.StartCapture();

            Console.ReadKey();

            device.StopCapture();

            device.Close();
            
            
        }

#region Interfaces MAC
        static void Interfaces(){
            // List available network interfaces
            var devices = CaptureDeviceList.Instance;
            if (devices.Count == 0)
            {
                Console.WriteLine("No se encontraron interfaces de red disponibles.");
                return;
            }

            Console.WriteLine("Interfaces de red disponibles:");
            for (int i = 0; i < devices.Count; i++)
            {
                Console.WriteLine($"[{i + 1}] {devices[i].Description} (MAC: {devices[i].MacAddress})");
            }
        
        }
#endregion 

#region Setear info del trafico de paquetes
        static void PackTraffic(){       
            //puerto
        ushort tcpSourcePort = 443;
        ushort tcpDestinationPort = 443;
        var tcpPacket = new TcpPacket(tcpSourcePort, tcpDestinationPort);
            //IP
        var ipSourceAddress = System.Net.IPAddress.Parse("10.0.0.253");
        var ipDestinationAddress = System.Net.IPAddress.Parse("142.250.217.206");
        var ipPacket = new IPv4Packet(ipSourceAddress, ipDestinationAddress);
            //MAC
        var sourceHwAddress = "74:e5:0b:d6:2a:72";
        var ethernetSourceHwAddress = System.Net.NetworkInformation.PhysicalAddress.Parse(sourceHwAddress);
        var destinationHwAddress = "04-7D-7B-67-C3-48";
        var ethernetDestinationHwAddress = System.Net.NetworkInformation.PhysicalAddress.Parse(destinationHwAddress);

        var ethernetPacket = new EthernetPacket(ethernetSourceHwAddress, ethernetDestinationHwAddress, EthernetType.None);

        ipPacket.PayloadPacket = tcpPacket;
        ethernetPacket.PayloadPacket = ipPacket;

        Console.WriteLine(ethernetPacket.ToString());

        byte[] packetBytes = ethernetPacket.Bytes;
        Console.WriteLine(packetBytes);


        }
#endregion

#region Un lio
        
        static void Device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
        
            var packetLength = e.Packet.Data.Length;
            Console.WriteLine($"Paquete capturado. Longitud: {packetLength} bytes");
            /*ICaptureDevice device = (ICaptureDevice)sender;

            string deviceDescription = device.Description;
            PhysicalAddress deviceMacAddress = device.MacAddress;

            // Acceder a los datos del paquete capturado
            int packetLength = e.Packet.Data.Length;

            // Imprimir información sobre el paquete capturado y el dispositivo
            Console.WriteLine($"Paquete capturado en el dispositivo '{deviceDescription}'. Longitud: {packetLength} bytes");


            DateTime time = e.Packet.Timeval.Date;
            int len = e.Packet.Data.Length;
            Console.WriteLine("{0}:{1}:{2},{3} Len={4}", time.Hour, time.Minute, time.Second, time.Millisecond, len);
        

            Packet packet = null;

            while((packet=device.GetNextPacket()) != null )
            {
                // Prints the time and length of each received packet
                DateTime time = packet.PcapHeader.Date;
                int len = packet.PcapHeader.PacketLength;
                Console.WriteLine("{0}:{1}:{2},{3} Len={4}", time.Hour, time.Minute, time.Second, time.Millisecond, len);
            }*/
        }
        
#endregion


    }
}
