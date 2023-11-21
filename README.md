# Ethical-Hacking-Scripts

# Repositorio de scrpts de Hacking

Aviso

Este script se proporciona solo con fines educativos y de investigación. El uso indebido de este script puede violar la ley. El autor no es responsable de ningún mal uso.

# ARP Spoofing Script

Este script de Python implementa el ataque de ARP Spoofing, permitiendo la suplantación de identidad en una red local.

## Requisitos

- Python 3.x
- Linux (se recomienda ejecutar en un entorno Linux)
- Permisos de superusuario para habilitar el reenvío de IP

## Uso

1. Clona este repositorio:

   ```bash
   git clone https://github.com/charliechazz/Hacking

2. Navega al directorio del proyecto

    ```bash
   cd tu-repositorio

3. Ejecuta el script proporcionando la IP objetivo y la IP del host:

     ```bash
     sudo python3 ARP_Spoofer.py <ip_objetivo> <ip_atacante> --iface <nombre_interfaz_de_red> --verbose

4. Para detener el ataque, presiona Ctrl+C. El script restaurará la red a su estado original.

5. Opciones

    --iface: Especifica la interfaz de red a utilizar (por ejemplo, eth0).
   
    --verbose: Habilita el modo verbose para ver mensajes detallados.

6. Contribuciones

   ¡Las contribuciones son bienvenidas! Si encuentras algún error o tienes una mejora, siéntete libre de crear un     problema o enviar una solicitud de extracción.
   
7. Licencia

    Este proyecto está bajo la Licencia MIT - consulta el archivo LICENSE para más detalles.
