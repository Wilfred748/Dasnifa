using System;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using System.Net.NetworkInformation;
using System.Net;
using MySql.Data.MySqlClient;
using Org.BouncyCastle.Asn1;
using System.Security.Policy;

namespace HIDS
{
    class HIDS
    {
        static string alertaPersonalizada = "";     

        static void Main()
        {
            Espacio();
            Dasnifa();

            ColorRed("");
            Console.Write("[!] ");
            ColorAmarillo("");
            Console.WriteLine("Alerta, al usar linux se necesita ser root para ejecutar el programa en su totalidad!");            
            MostrarVersiones();

            ColorBlanco("");
            Console.WriteLine($"Direccion IPv4 actual: {IPlocal()} \n");
            
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

            Console.Write("Elige un numero de la lista: ");
            int i = Convert.ToInt32(Console.ReadLine());
            ICaptureDevice dispositivo = dispositivos[i];
    
            Console.Write("Diga una URL para alertar (ej: https://example.com/ o https://www.example.com/) : ");
            try
            {
                string url = Console.ReadLine();
                Uri myUri = new Uri(url);
                var ip = Dns.GetHostAddresses(myUri.Host)[0];           

                dispositivo.OnPacketArrival += (sender, e) => capturaPaquetes(sender, e, ip);
                int TiempoEsperaMilisec = 500;

                //En caso de fallo al agarrar .
                try
                {
                    //Promiscuo == agarra todo lo que vea en la red.
                    //Normal == agarra solo lo que va dirigido al dispositivo en cuestion
                    dispositivo.Open(DeviceMode.Promiscuous, TiempoEsperaMilisec);
                }
                catch (DeviceNotReadyException ex)
                {

                    Console.WriteLine("Error al abrir el dispositivo de captura: " + ex.Message);
                    return;
                }

                HIDS Hids = new HIDS();
                Hids.ValorAlerta();

                //Para filtrar protocolo, si no hay filtro se muestra demasiado UDP y no vale la pena porque no se ve na'.
                //puerto 443 porque es el usado para pags web con protocolo HTTPS.
                // filter = "{protocolo} port {no. puerto}";
                //Si se deja vacio, va a agarrar todo el trafico correspondiente.
                Console.Write("Indique el puerto a filtrar ('Enter' para cualquiera): ");
                string puerto = Console.ReadLine();
                if (puerto != "")
                {
                    puerto = "port " + puerto;
                }

                Console.Write("Indique el protocolo a filtrar (udp o tcp, 'Enter' para ambos):");
                string protocolo = Console.ReadLine();

                string filtros = $"{protocolo} {puerto}";
                Console.WriteLine(filtros);
                dispositivo.Filter = filtros;

                //Mostrar en pantalla el servicio elegido. 
                Console.WriteLine("\nServicio: " + dispositivo);
                //Detalles.
                Console.WriteLine("-- El siguiente valor va a ser aplicado para el filtro: \"{0}\"", filtros);
                Console.WriteLine("-- Capturando trafico de: {0}, presionar 'Enter' para finalizar.", dispositivo.Name);

                dispositivo.StartCapture();

                Console.ReadKey();

                dispositivo.StopCapture();

                dispositivo.Close();
            }
            catch
            {
                ColorAmarillo("");
                Console.Write("[!] ");
                ColorRed("");
                Console.WriteLine("URL no valida, se va a cerrar el programa.");
                ColorBlanco("");
            }
        }

#region metodos para colorear
        static void ColorRed(string value)
        {
            Console.ForegroundColor = ConsoleColor.DarkRed;
        }

        static void ColorAzul(string value)
        {
            Console.ForegroundColor = ConsoleColor.Blue;
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

        static void ColorAmarillo(string value)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
        }
        #endregion

        static void MostrarVersiones()
        {
            ColorAzul("");
            string versionSharpPcap = SharpPcap.Version.VersionString;
            string versionDotNet = Environment.Version.ToString();
            Console.WriteLine("Dotnet {0} \nSharpPcap {1} \n", versionDotNet, versionSharpPcap);
        }

        #region Un lio == output de packet
        static void capturaPaquetes(object sender, CaptureEventArgs e, IPAddress ip)
        {
            Packet packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            if (packet is EthernetPacket ethernetPacket)
            {
                if (ethernetPacket.PayloadPacket is IpPacket ipPacket)
                {
                    //Definir variables como puertos, direcciones, y alerta en caso de ser necesaria.
                    string direccionOrigen = ipPacket.SourceAddress.ToString();
                    var direccionDestino = ipPacket.DestinationAddress.ToString();

                    int puertoOrigen = 0;
                    int puertoDestino = 0;
                    int len = e.Packet.Data.Length;

                    var sourceMACaddr = "";
                    var destMACaddr = "";
                    string alerta = alertaPersonalizada;

                    string iplocal = IPlocal();

                    DateTime hora = e.Packet.Timeval.Date;
                    //UTC-4
                    TimeZoneInfo zonaHoraria = TimeZoneInfo.FindSystemTimeZoneById("Eastern Standard Time");
                    //
                    DateTime horaUTCmenos4 = TimeZoneInfo.ConvertTime(hora, zonaHoraria);
                    //string horaFinal = "{0} {1}:{2}:{3}:{4}", horaUTCmenos4 ;

                    string protocol = ipPacket.Protocol.ToString();

                    //Especificar protocolo OSI 4 UDP o TCP.
                    switch (ipPacket.PayloadPacket)
                    {
                        case TcpPacket tcpPacket:
                            puertoOrigen = tcpPacket.SourcePort;
                            puertoDestino = tcpPacket.DestinationPort;
                            break;
                        case UdpPacket udpPacket:
                            puertoOrigen = udpPacket.SourcePort;
                            puertoDestino = udpPacket.DestinationPort;
                            break;
                        case EthernetPacket ethernetpacket:
                            sourceMACaddr = ethernetpacket.SourceHwAddress.ToString();
                            destMACaddr = ethernetpacket.DestinationHwAddress.ToString();
                            break;
                        case ARPPacket aRPPacket:
                            sourceMACaddr = aRPPacket.SenderHardwareAddress.ToString();
                            destMACaddr = aRPPacket.TargetHardwareAddress.ToString();
                            break;
                        default:
                            // Handle any other packet types if needed
                            break;
                    }


                    //Asignacion de los colores declarados.
                    if (direccionDestino == ip.ToString() && direccionOrigen == iplocal || direccionDestino == iplocal && direccionOrigen == ip.ToString())
                    {
                        ColorRed(direccionDestino);

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
                        alerta = "";
                    }

                    else if (protocol == "TCP")
                    {
                        ColorBlanco(protocol);
                        alerta = "";
                    }
                    else
                    {
                        ColorNormal(direccionDestino);
                        alerta = "";
                    }

                    //Output para los paquetes.
                    Console.WriteLine("{0}:{1}:{2},{3} IP-Origen={4}, Puerto-de-Origen={7}, MACOrig={11} IP-Destino={5}, puerto-de-Destino={8},  MACDest={12},  Longitud={6}, protocolo={9} {10}",
                    horaUTCmenos4.Hour, horaUTCmenos4.Minute, horaUTCmenos4.Second, horaUTCmenos4.Millisecond, direccionOrigen, direccionDestino, len, puertoOrigen, puertoDestino, protocol, alerta, sourceMACaddr, destMACaddr);
                }
            }
        }
        #endregion

        #region DB
        //Crear una base de datos en caso de que no exista
        static void DatabaseCrea()
        {
            string cursor = "server=localhost;port=3306;uid=root;password=;";
            using var conn = new MySqlConnection(cursor);

            try
            {
                ColorNormal("");
                conn.Open();
                Console.WriteLine("Connectado a la base de datos. \n");

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
                    Console.WriteLine("Tabla 'alertas' creadas");

                }
                catch (MySqlException ex)
                {
                    ColorRed("");
                    Console.WriteLine("[!] Error al crear la tabla 'alertas': " + ex.Message);
                }

                MySqlCommand checkDB = new MySqlCommand(checkDBinfo, conn);

                //Checar si hay base de datos
                var existe = checkDB.ExecuteScalar();

                if (existe != null)
                {
                    ColorAmarillo("");
                    Console.Write("[*] ");
                    ColorAzul("");
                    Console.WriteLine("Base de datos para las alertas ya existe, se va a proceder con el programa. \nToque enter para seguir:");
                    ColorBlanco("");
                }
                else
                {
                    //crear base de datos si no existe
                    MySqlCommand crearBD = new MySqlCommand(createDB, conn);

                    crearBD.ExecuteNonQuery();
                    ColorAmarillo("");
                    Console.Write("[*] ");
                    ColorAzul("");
                    Console.WriteLine("Base de datos para las alertas creada, se va a proceder con el programa.");
                    ColorBlanco("");
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
            string wirelessAdapterName = "Wi-Fi";

            NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();

            foreach (var networkInterface in interfaces)
            {
                if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 &&
                    networkInterface.Name == wirelessAdapterName)
                {
                    var ipProperties = networkInterface.GetIPProperties();

                    foreach (var address in ipProperties.UnicastAddresses)
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
        public void ValorAlerta()
        {
            Console.Write("Diga un valor para las alertas: ");
            alertaPersonalizada = Console.ReadLine();
        }

        static void Espacio()
        {
            Console.WriteLine("\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
        }

        static void Dasnifa()
        {
            ColorAzul("");
            Console.WriteLine("+---------------------------------------------------------+");
            Console.WriteLine("| ______  ___  _____ _   _ ___________ ___    __   _____  |");
            ColorAmarillo("");
            Console.WriteLine("| |  _  \\/ _ \\/  ___| \\ | |_   _|  ___/ _ \\  /  | |  _  | |");
            Console.WriteLine("| | | | / /_\\ \\ `--.|  \\| | | | | |_ / /_\\ \\ `| | | |/' | |");
            ColorNormal("");
            Console.WriteLine("| | | | |  _  |`--. \\ . ` | | | |  _||  _  |  | | |  /| | |");
            Console.WriteLine("| | |/ /| | | /\\__/ / |\\  |_| |_| |  | | | | _| |_\\ |_/ / |");
            ColorRed("");
            Console.WriteLine("| |___/ \\_| |_|____/\\_| \\_/\\___/\\_|  \\_| |_/ \\___(_)___/  |");
            Console.WriteLine("+---------------------------------------------------------+");
            ColorBlanco("\n");

        }
    }
}
