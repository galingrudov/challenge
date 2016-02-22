#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>

// defines
#define SESSION_TIMEOUT 1000
#define MAGIC_NUMBER 33

// ethernet headers are always exactly 14 bytes 
#define SIZE_ETHERNET 14

//loopbach header is 4 bytes
#define SIZE_LOOPBACK 4

// Pseudo-device that captures on all interfaces
#define SIZE_OF_ANY  16
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

int handle;

int linkhdrlen; // length of the link layer header 


// functions
//receive destination adress and id_ip from Ip header
int get_ip_header_info(u_char* buff, char** dst_ip, u_int* ip_len);

// function ger the destination port and udp data
int get_udp_info(u_char* buff, u_int16_t *port, char** data);

// this function return all network devices
int get_all_interfaces(pcap_if_t **alldevsp);

// return default interface on the current machine
int get_defalult_interface(char ** dev);

// start sniffing for data on device dev
int sniffing_udp(char* dev);

// call back function using from pcap. It is called every time when sutable packet is fined
void got_udp_packet(u_char *args, const struct pcap_pkthdr *header,
	     const u_char *packet);

// depending on the interface type calculate its header length
int calculate_link_len_h(pcap_t * pc_hdl);

// open udp socket
int init_socket();

//sent data using udp socket 
int send_data(char * dst_ip, u_short port, char* data);

int main(int argc, char *argv[])
{

  char *dev = "any";// The device to sniff on
  char error[PCAP_ERRBUF_SIZE]; // error string

// print out device name
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
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL)
  {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return(-1);
  }

// calculate the length of the current inteface
  if((linkhdrlen = calculate_link_len_h(handle))== -1)
   return -1;

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
  pcap_loop(handle,1,got_udp_packet,NULL);
}


void got_udp_packet(u_char *args, const struct pcap_pkthdr *header,
	   const  u_char *packet)
{
  u_char * buff = packet;
  char * dst_addr,*data;
  u_short port;
  u_int ip_len;
  buff += linkhdrlen; //we don't need any information from interface protocol
  if(get_ip_header_info(buff, &dst_addr, &ip_len) == -1)
    return;
  buff += ip_len;

  if(get_udp_info(buff, &port, &data)==-1)
    return;

// get num of cpu as int vaslue
  u_char cpu_cores = atoi(data);

// send information back to client
  pid_t pid;
  int i,fork_count = 0;
  pid_t pid_number;

//write separate process for each cpu core
for(i = 0; i < cpu_cores; ++i)
{
  pid = fork();//start new process

  if (pid == 0)// if it is a child process
  {
    ++fork_count;
    pid_number = getpid(); // get number of the current process
    u_char str_pid[255];
    memset((char*)str_pid,0,sizeof str_pid );
    snprintf(str_pid, sizeof str_pid, "%d",pid_number);
    if(send_data(dst_addr,  port, str_pid)!= 0)
      fprintf(stderr, "failed to send data");
    printf("pid number is %d\n",pid_number);
    return;
  }
}

for(i=0; i< fork_count;++i)
  wait(NULL);
}

int get_ip_header_info(u_char* buff, char** dst_ip, u_int *ip_len)
{

  const struct sniff_ip *ip; // The IP header

  ip = (struct sniff_ip*)buff;

  *ip_len = IP_HL(ip)*4; // convert to bites.*32 to receive  bits and then / 8 to receive bites
  if(*ip_len <20)
  {
    fprintf(stderr, "Invalid IP header length: %u bytes\n", *ip_len);
    return (-1);
  }

  *dst_ip = inet_ntoa(ip->ip_src);
  return (0);
}


int get_udp_info(u_char* buff, u_int16_t *port, char** data)
{
  struct udphdr* udp_hdr; // udp header strucrure defined in udp.h
  u_int16_t sourse_port;  // src port of udp packet
  char* cpu_num; // data in the udp packet
  udp_hdr = (struct udphdr*)buff;
  *port = ntohs(udp_hdr->source);
  // getting data in the udp body
  *data =(char*)(buff + sizeof(struct udphdr));
  return (0);
}

// open udp socket
int init_socket()
{
  handle = socket(AF_INET, SOCK_DGRAM,IPPROTO_UDP);
  if(handle <= 0)
  {
    fprintf(stderr, "failed to create socket\n");
    return (-1);
  }
// socket create successfully
  return 0;
}

int send_data(char * dst_ip, u_short port, char* data)
{
  if(init_socket()!=0)
  {
    fprintf(stderr, "failed to send data \n");
    return -1;
  }
  struct sockaddr_in address;
  // reset address strucrute to zero
  memset((char*)&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = inet_addr(dst_ip);
  address.sin_port = htons(port);
  //printf("handle: %d, data %s, addr %s, port %d\n",handle, data, dst_ip, port);
 //client is needed some time to establish connection

  printf("sleep for 3 sec\n");
  sleep(3);
  int sent_bytes = sendto(handle, data, strlen(data),0,(const struct sockaddr*) &address, sizeof(struct sockaddr_in));
 // printf("sent bytes %d, bytes to send %d\n",sent_bytes,strlen(data) );
  if(sent_bytes != strlen(data))
  {
    fprintf(stderr, "failed to send packet\n");
    return -1;
  }
  return 0;
}

int calculate_link_len_h(pcap_t * pc_hdl)
{
  int link_hdr_len, link_type;

  // Determine the datalink layer type.
  if ((link_type = pcap_datalink(pc_hdl)) < 0)
  {
    fprintf(stderr,"pcap_datalink(): %s\n", pcap_geterr(pc_hdl));
    return-1;
  }

  // Set the datalink layer header size.
  switch (link_type)
  {
  case DLT_NULL:
    link_hdr_len = SIZE_LOOPBACK;
    break;

  case DLT_EN10MB:
    link_hdr_len = SIZE_ETHERNET;
    break;

  case DLT_SLIP:
  case DLT_PPP:
    break;
  case DLT_LINUX_SLL:
   link_hdr_len = SIZE_OF_ANY;
   break;
  default:
    printf("Unsupported datalink (%d)\n", link_type);
    return -1 ;
  }
  return link_hdr_len;
}
