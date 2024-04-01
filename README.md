Spanish: 
# HIDS (Sistema de Detección de Intrusos para Hosts)

## Descripción

Aplicación de monitoreo de red que utiliza la biblioteca SharpPcap para capturar paquetes de red y detectar posibles intrusos en un host. La aplicación muestra información detallada sobre los paquetes capturados, como direcciones IP, puertos, protocolos, etc., y puede alertar sobre actividades sospechosas.

## Funcionalidades Principales

Captura de paquetes de red en tiempo real.
Análisis y visualización de la información de los paquetes capturados.
Detección de actividades sospechosas en la red.
Registro de alertas en una base de datos MySQL.

## Requisitos del Sistema

- Sistema operativo: Windows/Linux
- .NET Framework/.NET Core
- SharpPcap
- MySQL Server
## Instalación y Configuración
Clonar el archivo [Program.cs](https://github.com/Wilfred748/HIDS-DB-SIEM/blob/main/Program.cs) en el archivo a utilizar en C#, para Windows, es recomendable usar Visual Studio, para Linux, puede instalar .NET 6.0 para Visual Studio Code.

- [Instrucciones para Linux](https://github.com/Wilfred748/HIDS-DB-SIEM/blob/main/instrucciones_linux.txt)
 - [Instrucciones para Windows](https://github.com/Wilfred748/HIDS-DB-SIEM/blob/main/instrucciones_windows.txt)

    

## Uso
1. Ejecuta la aplicación.
2. Selecciona el dispositivo de red para la captura de paquetes.
3. Visualiza la información de los paquetes capturados en tiempo real.
4. Analiza las alertas generadas por actividades sospechosas.
5. Detén la captura de paquetes y cierra la aplicación cuando hayas terminado.

## Contribuciones
Las contribuciones son bienvenidas. Si deseas contribuir a este proyecto, por favor abre un problema o envía una solicitud de extracción con tus mejoras.


## Licencia

El proyecto esta bajo la licencia [MIT](https://choosealicense.com/licenses/mit/).

Lincencia NTI (No Tengo Idea)





