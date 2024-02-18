from iputils import *

def binarize(ip):
    return "".join([bin(int(x)+256)[3:] for x in ip.split('.')])

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.id = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            vihl, dscpecn, total_len1, total_len2, flfrag = 69, dscp | ecn, 20, 48, flags | frag_offset
            ttl -= 1
            if ttl > 0:
                csv = calc_checksum( \
                     struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len1, identification, flfrag, ttl, proto, 0, int.from_bytes(str2addr(src_addr), 'big'), int.from_bytes(str2addr(dst_addr), 'big')))
                dg = struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len1, identification, flfrag, ttl, proto, csv, int.from_bytes(str2addr(src_addr), 'big'), int.from_bytes(str2addr(dst_addr), 'big'))
                self.enlace.enviar(dg, next_hop)
            else:
                next_hop2 = self._next_hop(src_addr)
                csv = calc_checksum( \
                           struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len2, identification, flfrag, 64, IPPROTO_ICMP, 0, int.from_bytes(str2addr(self.meu_endereco), 'big'), int.from_bytes(str2addr(src_addr), 'big')))
                wrong_dg = struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len2, identification, flfrag, 64, IPPROTO_ICMP, csv, int.from_bytes(str2addr(self.meu_endereco), 'big'), int.from_bytes(str2addr(src_addr), 'big'))
                csv2 = calc_checksum(wrong_dg + struct.pack('!BBHHH', 11, 0, 0, 0, 0))
                icmp = struct.pack('!BBHHH', 11, 0, csv2, 0, 0)
                self.enlace.enviar(wrong_dg + icmp + datagrama[:28], next_hop2)

    def _next_hop(self, dest_addr):
        bin_addr = binarize(dest_addr)
        CIDRs = []
        for cidr, hop in self.table:
            div = cidr.split('/')
            div = [binarize(div[0]), int(div[1])]
            if bin_addr[:div[1]] == div[0][:div[1]]:
                CIDRs.append((div[0], hop, div[1]))
        if not len(CIDRs): 
            return None
        elif len(CIDRs) == 1:
            return CIDRs[0][1]
        else:
            for i, cidr in enumerate(CIDRs):
                for digit in range(32):
                    equality = 0
                    if cidr[0][digit] == bin_addr[digit]:
                        equality += 1
                    else:
                        break
                CIDRs[i] = (cidr, equality)
        CIDRs = [i for i in CIDRs if i[1] >= CIDRs[0][1]]
        return max(CIDRs, key=lambda x: x[0][2])[0][1]

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.table = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        cs = calc_checksum(struct.pack('!BBHHHBBH', 69, 0, 20+len(segmento), self.id, 0, 64, 6, 0) + str2addr(self.meu_endereco) + str2addr(dest_addr))
        dg = struct.pack('!BBHHHBBH', 69, 0, 20+len(segmento), self.id, 0, 64, 6, cs) + str2addr(self.meu_endereco) + str2addr(dest_addr) + segmento
        self.enlace.enviar(dg, next_hop)