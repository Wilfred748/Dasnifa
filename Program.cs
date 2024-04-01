using System;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using System.Net.NetworkInformation;
using System.Net;
using MySql.Data.MySqlClient;
using Org.BouncyCastle.Asn1;



namespace SharpPcap
{

    class HIDS
    {
        static void Main()
        {
            Console.WriteLine("Alerta, se necesita ser root para ejecutar el programa en us totalidad!");
            MostrarVersiones();

            Console.WriteLine(IPlocal());

            //Conectar a BD
            DatabaseCrea();

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
            string filter = "";//Libreria captura trafico.
            device.StartCapture();

            //Agarra tecla para termianr.
            Console.ReadKey();

            device.StopCapture();

            device.Close();
            device.Filter = filter;

            //Mostrar en pantalla el servicio elegido. 
            Console.WriteLine("\nServicio: " + device);
            //Detalles.
            Console.WriteLine("-- El siguiente valor va a ser aplicado para el filtro: \"{0}\"", filter);
            Console.WriteLine("-- Capturando trafico de: {0}, presionar 'Enter' para finalizar.", device.Name);

            
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

        static void MostrarVersiones()
        {
            string versionSharpPcap = SharpPcap.Version.VersionString;
            string versionDotNet = Environment.Version.ToString();
            Console.WriteLine("Dotnet {0} \n SharpPcap {1} \n", versionDotNet, versionSharpPcap);
        }


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
                    int len = e.Packet.Data.Length;

                    var sourceMACaddr = "";
                    var destMACaddr = "";

                    var iplocal = IPlocal();

                    DateTime hora = e.Packet.Timeval.Date;
                    //UTC-4
                    TimeZoneInfo zonaHoraria = TimeZoneInfo.FindSystemTimeZoneById("Eastern Standard Time");
                    //
                    DateTime horaUTCmenos4 = TimeZoneInfo.ConvertTime(hora, zonaHoraria);
                    //string horaFinal = "{0} {1}:{2}:{3}:{4}", horaUTCmenos4 ;

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
                    else if (ipPacket.PayloadPacket is EthernetPacket ethernetpacket)
                    {
                        sourceMACaddr = ethernetpacket.SourceHwAddress.ToString();
                        destMACaddr = ethernetpacket.DestinationHwAddress.ToString();
                    }
                    else if (ipPacket.PayloadPacket is ARPPacket aRPPacket)
                    {
                        sourceMACaddr = aRPPacket.SenderHardwareAddress.ToString();
                        destMACaddr = aRPPacket.TargetHardwareAddress.ToString();
                    }


                    //Asignacion de los colores declarados.
                    if (destinationAddress == ip.ToString() && sourceAddress == "192.168.114.116")
                    {
                        ColorRed(destinationAddress);
                        alert = "Alerta, alguien ha entrado a Roblox!";

                        using var conn = new MySqlConnection("server=localhost;port=3306;database=alertas;uid=root;password=;");
                        conn.Open();

                        string insertDB = "INSERT into alertas(fecha, IPorigen, Puertoorigen, MACorigen, IpDestino, PuertoDestino, MACdest, longitud, protocolo, alerta) VALUES(@horaUTCmenos4, @sourceAddress, @sourcePort, @sourceMACaddr, @destinationAddress, @destinationPort, @destMACaddr , @len, @protocol, @alert)";
                        var cmd = new MySqlCommand(insertDB, conn);

                        cmd.Parameters.AddWithValue("@horaUTCmenos4", horaUTCmenos4);
                        cmd.Parameters.AddWithValue("@sourceAddress", sourceAddress);
                        cmd.Parameters.AddWithValue("@sourcePort", sourcePort);
                        cmd.Parameters.AddWithValue("@sourceMACaddr", sourceMACaddr);
                        cmd.Parameters.AddWithValue("@destinationAddress", destinationAddress);
                        cmd.Parameters.AddWithValue("@destinationPort", destinationPort);
                        cmd.Parameters.AddWithValue("@destMACaddr", destMACaddr);
                        cmd.Parameters.AddWithValue("@len", len);
                        cmd.Parameters.AddWithValue("@protocol", protocol);
                        cmd.Parameters.AddWithValue("@alert", alert);
                        cmd.Prepare();

                        cmd.ExecuteNonQuery();
                        conn.Close();
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

                    Console.WriteLine("{0}:{1}:{2},{3} SourceIP={4}, sourcePort={7}, MACOrig={11} DestinationIP={5}, DestinationPort={8},  MACDest={12},  Len={6}, protocol={9} {10}",
                    horaUTCmenos4.Hour, horaUTCmenos4.Minute, horaUTCmenos4.Second, horaUTCmenos4.Millisecond, sourceAddress, destinationAddress, len, sourcePort, destinationPort, protocol, alert, sourceMACaddr, destMACaddr);



                }
            }
        }
        #endregion

#region DB???

        //Crear una base de datos en caso de que no exista
        public static void DatabaseCrea()
        {
            string cursor = "server=localhost;port=3306;uid=root;password=;";
            using var conn = new MySqlConnection(cursor);

            try
            {
                conn.Open();
                Console.WriteLine("Connectado.");

                string checkDBinfo = $"SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = 'alertas';";

                string createDB = $"CREATE DATABASE IF NOT EXISTS `alertas`;";
                try
                {
                    string usarDB = $"USE alertas;";
                    MySqlCommand useDatabaseCommand = new MySqlCommand(usarDB, conn);
                    useDatabaseCommand.ExecuteNonQuery();

                    string createTable = @"CREATE TABLE IF NOT EXISTS `alertas` (
                                        `id` INT AUTO_INCREMENT PRIMARY KEY,
                                        `fecha` DATETIME,
                                        `IPorigen` VARCHAR(255),
                                        `Puertoorigen` INT,
                                        `MACorigen` VARCHAR(255),
                                        `IpDestino` VARCHAR(255),
                                        `PuertoDestino` INT,
                                        `MACdest` VARCHAR(255),
                                        `longitud` INT,
                                        `protocolo` VARCHAR(50),
                                        `alerta` VARCHAR(255)
                                    );";

                        MySqlCommand command = new MySqlCommand(createTable, conn);
                        command.ExecuteNonQuery();
                    Console.WriteLine("Tabla alertas creadas");
                    
                }
                catch (MySqlException ex)
                {
                    Console.WriteLine("Error al crear la tabla 'alertas': " + ex.Message);
                }

                MySqlCommand checkDB = new MySqlCommand(checkDBinfo, conn);

                //Checar si hay base de datos
                var existe = checkDB.ExecuteScalar();

                if (existe != null)
                {
                    Console.WriteLine("Base de datos para las alertas ya existe, se va a proceder con el programa. \nToque enter para seguir:");
                }
                else
                {
                    //crear base de datos si no existe
                    MySqlCommand crearBD = new MySqlCommand(createDB, conn);

                    crearBD.ExecuteNonQuery();
                    Console.WriteLine("Base de datos para las alertas cerada, se va a proceder con el programa.");
                }
            }
            catch (MySqlException ex)
            {
                Console.WriteLine("erroi: {0}", ex.Message);
                throw;
            }

            Console.ReadKey();
        }

        #endregion

        //Agarrar la direccion ip del sistema para tenerla como IP local
        static string IPlocal()
        {
            var redInterfaz = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var networkInterface in redInterfaz)
            {
                if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Ethernet || networkInterface.NetworkInterfaceType == NetworkInterfaceType.Wireless80211)
                {
                    var propi = networkInterface.GetIPProperties();
                    foreach (var address in propi.UnicastAddresses)
                    {
                        if (address.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            return address.Address.ToString();
                        }
                    }
                }
            }
            return null;
        }
    }

}
