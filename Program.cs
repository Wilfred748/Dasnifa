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
            Console.WriteLine("Alerta, al usar linux se necesita ser root para ejecutar el programa en su totalidad!");
            MostrarVersiones();

            Console.WriteLine(IPlocal());

            //Conectar a BD
            DatabaseCrea();

            //Define una variable que sirve para enlistar los servicios.
            CaptureDeviceList dispositivos = CaptureDeviceList.Instance;

            //Si no hay servicios, tira mensaje.
            if (dispositivos.Count < 1)
            {
                Console.WriteLine("No hay servicios");
                Console.ReadKey();
                return;
            }

            //En caso de que si hayan servicios, los enlista con un loop.
            Console.WriteLine("Servicios: ");
            //Loop para mostrar todos los servicios.
            foreach (ICaptureDevice dev in dispositivos)
            {
                Console.WriteLine("{0}\n", dev.ToString());
            }


            //Para elegir un servicio de la lista.
            Console.Write("Elige un numero de la lista: ");
            int i = Convert.ToInt32(Console.ReadLine());
            ICaptureDevice dispositivo = dispositivos[i];

            //
            dispositivo.OnPacketArrival += capturaPaquetes;

            //Indica tiempo de espera antes de recoger paquetes al ser elegido.
            int TiempoEsperaMilisec = 2000;

            //En caso de fallo al agarrar .
            try
            {
                //Promiscuo == agarra todo lo que vea en la red.
                //Normal == agarra solo lo que va dirigido al dispositivo en cuestion
                dispositivo.Open(DeviceMode.Normal, TiempoEsperaMilisec);
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
            string filtros = "";//Libreria captura trafico.
            dispositivo.Filter = filtros;

            dispositivo.StartCapture();

            //Agarra tecla para termianr.
            Console.ReadKey();

            dispositivo.StopCapture();

            dispositivo.Close();
            

            //Mostrar en pantalla el servicio elegido. 
            Console.WriteLine("\nServicio: " + dispositivo);
            //Detalles.
            Console.WriteLine("-- El siguiente valor va a ser aplicado para el filtro: \"{0}\"", filtros);
            Console.WriteLine("-- Capturando trafico de: {0}, presionar 'Enter' para finalizar.", dispositivo.Name);

            
        }

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
        
        static void MostrarVersiones()
        {
            string versionSharpPcap = SharpPcap.Version.VersionString;
            string versionDotNet = Environment.Version.ToString();
            Console.WriteLine("Dotnet {0} \n SharpPcap {1} \n", versionDotNet, versionSharpPcap);
        }

#region Un lio == output de packet
        static void capturaPaquetes(object sender, CaptureEventArgs e)
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
                    string direccionOrigen = ipPacket.SourceAddress.ToString();
                    var direccionDestino = ipPacket.DestinationAddress.ToString();
                    string alerta = "";
                    int puertoOrigen = 0;
                    int puertoDestino = 0;
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
                        puertoOrigen = tcpPacket.SourcePort;
                        puertoDestino = tcpPacket.DestinationPort;
                    }

                    else if (ipPacket.PayloadPacket is UdpPacket udpPacket)
                    {
                        puertoOrigen = udpPacket.SourcePort;
                        puertoDestino = udpPacket.DestinationPort;
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
                    if (direccionDestino == ip.ToString() && direccionOrigen == "192.168.114.116")
                    {
                        ColorRed(direccionDestino);
                        alerta = "Alerta, alguien ha entrado a Roblox!";

                        using var conn = new MySqlConnection("server=localhost;port=3306;database=alertas;uid=root;password=;");
                        conn.Open();

                        string insertDB = "INSERT into alertas(fecha, IPorigen, Puertoorigen, MACorigen, IpDestino, PuertoDestino, MACdest, longitud, protocolo, alerta) VALUES(@horaUTCmenos4, @direccionOrigen, @puertoOrigen, @sourceMACaddr, @direccionDestino, @puertoDestino, @destMACaddr , @len, @protocol, @alerta)";
                        var cmd = new MySqlCommand(insertDB, conn);

                        cmd.Parameters.AddWithValue("@horaUTCmenos4", horaUTCmenos4);
                        cmd.Parameters.AddWithValue("@direccionOrigen", direccionOrigen);
                        cmd.Parameters.AddWithValue("@puertoOrigen", puertoOrigen);
                        cmd.Parameters.AddWithValue("@sourceMACaddr", sourceMACaddr);
                        cmd.Parameters.AddWithValue("@direccionDestino", direccionDestino);
                        cmd.Parameters.AddWithValue("@puertoDestino", puertoDestino);
                        cmd.Parameters.AddWithValue("@destMACaddr", destMACaddr);
                        cmd.Parameters.AddWithValue("@len", len);
                        cmd.Parameters.AddWithValue("@protocol", protocol);
                        cmd.Parameters.AddWithValue("@alerta", alerta);
                        cmd.Prepare();

                        cmd.ExecuteNonQuery();
                        conn.Close();
                    }

                    else if (direccionOrigen == "10.0.0.1")
                    {
                        ColorCyan(direccionDestino);
                    }

                    else if (protocol == "TCP")
                    {
                        ColorBlanco(protocol);
                    }
                    else
                    {
                        ColorNormal(direccionDestino);
                    }

                    //Output para los paquetes.

                    Console.WriteLine("{0}:{1}:{2},{3} IP-Origen={4}, Puerto-de-Origen={7}, MACOrig={11} IP-Destino={5}, puerto-de-Destino={8},  MACDest={12},  Longitud={6}, protocolo={9} {10}",
                    horaUTCmenos4.Hour, horaUTCmenos4.Minute, horaUTCmenos4.Second, horaUTCmenos4.Millisecond, direccionOrigen, direccionDestino, len, puertoOrigen, puertoDestino, protocol, alerta, sourceMACaddr, destMACaddr);

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
