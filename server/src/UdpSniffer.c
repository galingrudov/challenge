#include <pcap.h>
#include <stdio.h>
#include <string.h>

#define SESSION_TIMEOUT 1000
#define MAGIC_NUMBER 33

// ethernet headers are always exactly 14 bytes 
#define SIZE_ETHERNET 14

// IP header
struct sniff_ip
{
  u_char ip_vhl;// version << 4 | header length >> 2 */
  u_char ip_tos;// type of service
  u_short ip_len;// total length
  u_short ip_id;// identification
  u_short ip_off;// fragment offset field
 #define IP_RF 0x8000// reserved fragment flag
 #define IP_DF 0x4000// dont fragment flag
 #define IP_MF 0x2000// more fragments flag
 #define IP_OFFMASK 0x1fff// mask for fragmenting bits
  u_char ip_ttl;// time to live
  u_char ip_p;// protocol
  u_short ip_sum;// checksum
  struct in_addr ip_src,ip_dst;// source and dest address
};
/*
Internet Header Length (IHL)
The second field (4 bits) is the Internet Header Length (IHL), which is the number of 32-bit words in the header.
*/
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)

// this function return all network devices
int get_all_interfaces(pcap_if_t **alldevsp);


int get_defalult_interface(char ** dev);


int sniffing_udp(char* dev);

void got_udp_packet(u_char *args, const struct pcap_pkthdr *header,
	    const u_char *packet);
int main(int argc, char *argv[])
{

  char *dev;// The device to sniff on
  char error[PCAP_ERRBUF_SIZE]; // error string

  if (get_defalult_interface(&dev)==-1)
  {
    return (1);
  }
  /* print out device name */
  printf("DEV: %s\n",dev);

  if(sniffing_udp(dev)==-1)
  {
    return (1); 
  }
  return(0);
}

int get_all_interfaces(pcap_if_t **alldevsp)
{
  return 2;
}
int get_defalult_interface(char ** dev)
{
  char error[PCAP_ERRBUF_SIZE]; // error string
  *dev = pcap_lookupdev(error);
  if (*dev == NULL)
  {
    fprintf(stderr, "Couldn't find default device: %s\n", error);
    return (-1);
  }
  return 0;
}

int sniffing_udp(char* dev)
{
  pcap_t *handle;                // Session handle
  char filter_exp[] = "udp and ip[4:2]==33"; //The filter expression
  bpf_u_int32 mask;              //Our netmask
  bpf_u_int32 net;               //Our IP
  struct pcap_pkthdr header;     // The header that pcap gives us
  const u_char *packet;          //The actual packet
  struct bpf_program fp;         //The compiled filter
  char errbuf[PCAP_ERRBUF_SIZE]; // error string

// Find the properties for the device
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
  {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
    net = 0;
    mask = 0;
  }

// Open the session
  handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
  if (handle == NULL)
  {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return(-1);
  }

// Compile  filter
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
  {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return(-1);
  }
//and apply filter
  if (pcap_setfilter(handle, &fp) == -1)
  {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return(-1);
  }
// start pcap_loop() that call a callback function every time a packet is sniffed that meets our filter requirements
  pcap_loop(handle,10,got_udp_packet,NULL);
}


void got_udp_packet(u_char *args, const struct pcap_pkthdr *header,
	    const u_char *packet)
{
  fprintf(stdout, "working");
}
