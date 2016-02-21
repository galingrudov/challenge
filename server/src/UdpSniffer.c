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
// functions
//receive destination adress and id_ip from Ip header
int get_ip_header_info(u_char* buff, char** dst_ip, u_int* ip_len);

int get_udp_info(u_char* buff, u_int16_t *port, char** data);
// this function return all network devices
int get_all_interfaces(pcap_if_t **alldevsp);


int get_defalult_interface(char ** dev);


int sniffing_udp(char* dev);

void got_udp_packet(u_char *args, const struct pcap_pkthdr *header,
	    const u_char *packet);

// open udp socket
int init_socket();

int send_data(char * dst_ip, u_short port, char* data);

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
  pcap_loop(handle,1,got_udp_packet,NULL);
}


void got_udp_packet(u_char *args, const struct pcap_pkthdr *header,
	    const u_char *packet)
{
  u_char * buff = packet;
  char * dst_addr,*data;
  u_short port;
  u_int ip_len;
  buff += SIZE_ETHERNET; //we don't need any information from ethernet protocol

  if(get_ip_header_info(buff, &dst_addr, &ip_len) == -1)
    return;
  buff += ip_len;

  if(get_udp_info(buff, &port, &data)==-1)
    return;

// get num of cpu as int vaslue
  u_char cpu_cores = atoi(data);

// send information back to client
  pid_t pid;
  int i;

//write separate process for each cpu core
for(i = 0; i < cpu_cores; ++i)
{
  pid = fork();//start new process

  if (pid == 0)// if it is a child process
  {
      pid_t pid_number = getpid(); // get number of the current process
      u_char str_pid[255];
      memset((char*)str_pid,0,sizeof str_pid );
     snprintf(str_pid, sizeof str_pid, "%u",pid_number);
    if(send_data(dst_addr,  port, "hhh")!= 0)
      fprintf(stderr, "failed to send data");
    printf("pid number is %d\n",pid_number);
    return;
  }
}

  fprintf(stdout, "working dst_sddr = %s, iplen=%d, cores =%d\n", dst_addr, ip_len, cpu_cores);
}

int get_ip_header_info(u_char* buff, char** dst_ip, u_int *ip_len)
{

  const struct sniff_ip *ip; // The IP header
 // u_int size_ip,magic_num;
  ip = (struct sniff_ip*)buff;

  *ip_len = IP_HL(ip)*4; // convert to bites.*32 to receive  bits and then / 8 to receive bites
  if(*ip_len <20)
  {
    fprintf(stderr, "Invalid IP header length: %u bytes\n", *ip_len);
    return (-1);
  }
  //magic_num = ntohs(ip->ip_id);
//  *ip_len = size_ip;
  *dst_ip = inet_ntoa(ip->ip_src);
  return (0); 
//fprintf(stdout,"TTL %d: ",ip->ip_ttl);
//        fprintf(stdout,"%s\n ",
  //              inet_ntoa(ip->ip_src));
 //      fprintf(stdout,"%s\n",
    //          inet_ntoa(ip->ip_dst));
//printf("dest =%d\n",ntohs(ip->ip_dst.s_addr));
//printf("size is %d\n",size_ip);
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
  printf("handle: %d\n, data %s,\n addr %s, port %d",handle, data, dst_ip, port);
  int sent_bytes = sendto(handle, data, strlen(data),0,(const struct sockaddr*) &address, sizeof(struct sockaddr_in));
  printf("sent bytes %d\n bytes to send %d\n",sent_bytes,strlen(data) );
  if(sent_bytes != strlen(data))
  {
    fprintf(stderr, "failed to send packet\n");
    return -1;
  }
  return 0;
}
