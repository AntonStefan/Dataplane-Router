#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define BYTE 8   //bin TYPE
#define MAX_LINE_LEN 120
#define IP_TYPE 8
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define MAC_ADRESS_LEN 6
#define IP_ADRESS_LEN 4

//Verificare daca s-a intamplat un ARP 
int already = 0;

typedef struct List{
	char *pack;
	struct route_table_entry *bestpath;
	int qlen;
} List;

//Routing table   
struct route_table_entry *rtable;
int rtable_len;
long int rtable_size = 0;

//ARP cache
struct arp_entry *arp_cache_table;
int arp_cache_table_len;
queue arplist;

// Converteste un string in binar
uint32_t to_bin(char *dot_ip) 
{
 	char* aux = strtok(dot_ip, ".");
		uint32_t part_4 = atoi(aux);

		aux = strtok(NULL, ".");
		uint32_t part_3 = atoi(aux);

		aux = strtok(NULL, ".");
		uint32_t part_2 = atoi(aux);

		aux = strtok(NULL, ".");
		uint32_t part_1 = atoi(aux);

		uint32_t result = (part_1 << (3 * BYTE)) | (part_2 << (2 * BYTE)) | (part_3 << BYTE) | (part_4);
		return result;
}


// Verificam headerul de Ethernet de nivel 2 
char valid (struct ether_header *eth_hdr, int interface){
    u_int8_t interfmac[MAC_ADRESS_LEN];
    get_interface_mac(interface, interfmac);

    // Daca adresa mac se potriveste cu adresa mac a interfetei
    if (memcmp(interfmac, eth_hdr->ether_dhost, MAC_ADRESS_LEN) == 0) {
        return 1;
    }
    
    // Daca adresa mac e broadcast
    u_int8_t broadcast_mac[MAC_ADRESS_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    if (memcmp(broadcast_mac, eth_hdr->ether_dhost, MAC_ADRESS_LEN) == 0) {
        return 1;
    }
    
    // Header invalid
    return 0;
}


// Cauta o intrare in cacheul arp si daca il gaseste scrie adresa MAC 
int get_mac_arp_cache(uint32_t ip, uint8_t *buff){
	int i = 0;
	do{
		if(ip == arp_cache_table[i].ip){
			memcpy(buff, arp_cache_table[i].mac, MAC_ADRESS_LEN);
			return 0;
		}
		i++;

	}while (i < arp_cache_table_len);
	return -1;
}

void swap_adress(int size, uint8_t* adr1, uint8_t* adr2) {
	uint8_t* aux = malloc(size * sizeof(uint8_t));
	for(int i = 0; i < size; i++) {
		aux[i] = adr1[i];
		adr1[i] = adr2[i];
		adr2[i] = aux[i];
	}

}

void swap_ip_adress(uint32_t *ip1, uint32_t *ip2) {
	uint32_t aux = 0;
	aux = *ip1;
	*ip1 = *ip2;
	*ip2 = aux;

}

int comparator(const void *p, const void *q) {
	struct route_table_entry *r1 = (struct route_table_entry *)p;
	struct route_table_entry *r2 = (struct route_table_entry *)q;

	// if prefixes are equal then sort by mask
	if (r1->prefix == r2->prefix) {
		return r1->mask - r2->mask;
	}
	// sort by prefix
	return r1->prefix - r2->prefix;
}


// cauta cea mai buna ruta pe tabela de routare 
int binarySearch(int left, int right, uint32_t addr) {
    if (left <= right) {
        if (rtable[(left + right)/2].prefix ==(rtable[(left + right)/2].mask & addr))
            return (left + right)/2;
        else if (rtable[(left + right)/2].prefix >(rtable[(left + right)/2].mask & addr))
            binarySearch(left, (left + right)/2 - 1, addr);
        else
            binarySearch((left + right)/2 + 1, right, addr);
    }
    return -1;
}


// cautare a routei cea mai bune
struct route_table_entry *get_best_route (uint32_t addr) {
    struct route_table_entry *best = NULL;
	long int ok;
	//  cautare in timp O(logn)
	long int idx = binarySearch(0, rtable_size - 1, addr);
	for (int i = idx; i < rtable_size - 1; i++){
		int x = addr & rtable[i].mask;
		if(x == rtable[i].prefix){
			if(best == NULL || (best->mask < rtable[i].mask)){
				best = &rtable[i];
				ok = i;
			}
		}
	}
	if (rtable[ok].prefix != (addr & rtable[ok].mask))
	return NULL;
	
    return best;
}


// numara cate linii are un fisier pentru a afla dimensiunea
long int file_lines(char *filename) {
	FILE *fd = fopen(filename, "r");
	DIE(fd == NULL, "Error opening file.");
	char *entry = (char *)malloc(MAX_LINE_LEN * sizeof(char));
	size_t length = 0;

	long int size = 1;
	while (getline(&entry, &length, fd) != -1) {
		size++;
	}
	fclose(fd);
	return size;
}

void copy_adress(int size, uint8_t* adress_source, uint8_t* adress_dest) {
	for(int i = 0; i < size; i++) {
		adress_source[i] = adress_dest[i];
	}
}

// pachetul Arp destinat routerului 
void update_arp_cache(int interface, char *buf, int len) {
    struct ether_header *eth_hdr = (struct ether_header *) buf;
    if (eth_hdr->ether_type != htons(0x0806)) {
        return;
    }
    struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));
	queue rest = queue_create();
    uint32_t router_ip = to_bin(get_interface_ip(interface));
    if (arp_hdr->tpa == router_ip && arp_hdr->op == htons(2)) {
		already = 1;
        // Actualizare cache prin concatenare
        arp_cache_table[arp_cache_table_len].ip = arp_hdr->spa;
        memcpy(arp_cache_table[arp_cache_table_len].mac, arp_hdr->sha, MAC_ADRESS_LEN);
        arp_cache_table_len++;

        // Cauta in coada pachetele ce asteapta reply
	   cauta_cont:
        if(!queue_empty(arplist)) {
            List *waiting_entry = queue_deq(arplist);
            if (waiting_entry->bestpath->next_hop == arp_hdr->spa) {
                struct ether_header *eth_hdr = (struct ether_header *) waiting_entry->pack;
                memcpy(eth_hdr->ether_dhost, arp_hdr->sha, MAC_ADRESS_LEN);
                send_to_link(waiting_entry->bestpath->interface, waiting_entry->pack, waiting_entry->qlen);
                free(waiting_entry);
            }
            else {
                queue_enq(rest, waiting_entry);
            }
			goto cauta_cont;
        }

        // Resturile sunt bagate in asteptare la loc
        while (!queue_empty(rest)) {
            queue_enq(arplist, queue_deq(rest));
        }
        free(rest);
    }
}

// Pentru request oferim reply
void handle_arp_request(int interface, char *buf, int len) {
    struct ether_header *eth_hdr = (struct ether_header *) buf;
    if (eth_hdr->ether_type != htons(0x0806)) {
        return;
    }
    struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));
    if (arp_hdr->tpa == to_bin(get_interface_ip(interface))) {
        arp_hdr->op = htons(2);
        memcpy(arp_hdr->tha, arp_hdr->sha, MAC_ADRESS_LEN);
        get_interface_mac(interface, arp_hdr->sha);
        swap_ip_adress(&arp_hdr->spa, &arp_hdr->tpa);
        memcpy(eth_hdr->ether_shost, arp_hdr->sha, MAC_ADRESS_LEN);
        memcpy(eth_hdr->ether_dhost, arp_hdr->tha, MAC_ADRESS_LEN);
        send_to_link(interface, buf, len);
    }
}


int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char buf[MAX_PACKET_LEN];  

	// Do not modify this line
	init(argc - 2, argv + 2);  

	// Structurile de date folosite de router
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	arp_cache_table = malloc(sizeof(struct arp_entry) * 1000);
	rtable_len = read_rtable(argv[1], rtable);
	rtable_size = file_lines(argv[1]);

	qsort(rtable, rtable_size, sizeof(struct route_table_entry), comparator);

	arp_cache_table_len = 0;
	
	arplist = queue_create();
	
	while(1){
		int interface;
		size_t len;
		int ok = 0;

		// Apel blocant ce asteapta primirea de pachete
		interface = recv_from_any_link(buf, &len);  
		DIE(interface < 0, "recv_from_any_links");    

		struct ether_header *eth_hdr = (struct ether_header *) buf;  

		// Verifcam headerul de Eth de nivel 2
		if(valid(eth_hdr, interface) == 0){
			continue;
		}

		if(eth_hdr->ether_type == IP_TYPE) {
			struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
			struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

			//Daca destinatia e routerul
			if(ip_hdr->daddr == to_bin(get_interface_ip(interface))) {
					ok = 1;				
				if(ip_hdr->protocol == ARP_REQUEST){

					// Facem ping reply
					icmp_hdr->code = 0;
					icmp_hdr->type = 0;
					icmp_hdr->checksum = 0;
					icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, len - sizeof(struct iphdr) - sizeof(struct ether_header));
					
					swap_adress(MAC_ADRESS_LEN, eth_hdr->ether_dhost, eth_hdr->ether_shost);
	 				swap_ip_adress(&ip_hdr->saddr, &ip_hdr->daddr);

					send_to_link(interface, buf, 100);
				}
			}
			// Checksum
			u_int16_t sum = ip_hdr->check;
			ip_hdr->check = 0;
			if (ntohs(sum) != checksum((u_int16_t *) ip_hdr, sizeof(struct iphdr))){
				continue;
			}

			// Time-to-live
			ip_hdr->check = sum;
			if(ip_hdr->ttl < 2){

				// Trimite pachet de Time exceeded
				ip_hdr->protocol = 1;
				icmp_hdr->type = 11;
				icmp_hdr->code = 0;
				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = checksum((u_int16_t *) ip_hdr, sizeof(struct iphdr) + sizeof(struct icmphdr));

				swap_adress(MAC_ADRESS_LEN, eth_hdr->ether_dhost, eth_hdr->ether_shost);
	 			swap_ip_adress(&ip_hdr->saddr, &ip_hdr->daddr);

				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
				len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

				send_to_link(interface, buf, 100);
				continue;
			}
			// Decrementare time-to-live
			ip_hdr->ttl --; 

			// Recalculare checksum
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((u_int16_t *) ip_hdr, sizeof(struct iphdr)));

			// Pentru un pachet IPV4 care nu este destinat routerului cauta unde sa il trimita in continuare
			if(ok == 0){
				// Aplicam LPM
				struct route_table_entry *dest_entry = get_best_route(ip_hdr->daddr);

				// Verifica cazul in care hostul este unreachable
				if (dest_entry == NULL) {
					ip_hdr->protocol = ARP_REQUEST;
					icmp_hdr->type = 3;
					icmp_hdr->code = 0;
					icmp_hdr->checksum = 0;
					icmp_hdr->checksum = checksum((u_int16_t *) ip_hdr, sizeof(struct iphdr) + sizeof(struct icmphdr));

					swap_adress(MAC_ADRESS_LEN, eth_hdr->ether_dhost, eth_hdr->ether_shost);
	 				swap_ip_adress(&ip_hdr->saddr, &ip_hdr->daddr);

					len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
					send_to_link(interface, buf, 100);
					continue;
        	}else {

				// Completeaza headerul de Ethernet, in cazul in care adresa mac din tabela ARP are aceasta adresa IP
				get_interface_mac(dest_entry->interface, eth_hdr->ether_shost);
				int searchpacket = get_mac_arp_cache(dest_entry->next_hop, eth_hdr->ether_dhost);

				if(searchpacket) {
					// Construire intrare
					List *waiting_entry = malloc(sizeof(List));
					waiting_entry->pack = malloc(len);
					memcpy(waiting_entry->pack, buf, len);
					waiting_entry->bestpath = dest_entry;
					waiting_entry->qlen = len;
					queue_enq(arplist, waiting_entry);

						
					struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));
					// Nivelul 2 Ethernet
					
					memcpy(eth_hdr->ether_shost, eth_hdr->ether_shost, MAC_ADRESS_LEN);
					memset(eth_hdr->ether_dhost, 255, MAC_ADRESS_LEN);
					eth_hdr->ether_type = 0x0608;

					// Completam ARP  
					
					arp_hdr->htype = htons(1);
					arp_hdr->ptype = htons(0x0800);
					arp_hdr->hlen = MAC_ADRESS_LEN;
					arp_hdr->plen = 4;
					arp_hdr->op = htons(1);
					memcpy(arp_hdr->sha, eth_hdr->ether_shost, MAC_ADRESS_LEN);
					arp_hdr->spa = to_bin (get_interface_ip(dest_entry->interface));
					memset(arp_hdr->tha, 0, MAC_ADRESS_LEN);
					arp_hdr->tpa = dest_entry->next_hop;

					send_to_link(dest_entry->interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));
					}
				else 
				send_to_link(dest_entry->interface, buf, 100);
				}
			
		}
		}else {
			update_arp_cache(interface, buf, len);//DACA E ARP_REPLY, actualizam cacheul ARP
			if(already == 0)  // Pachetul nu a fost de tip arp reply
			handle_arp_request(interface, buf, len);  //DACA E DE TIP ARP_REQUEST trimitem replyul
			else
			already =0;  //Pachetul a fost de tip arp reply si il aducem la valoarea originala 0
	}
}
}


		

