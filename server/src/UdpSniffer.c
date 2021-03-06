#define _GNU_SOURCE
#include <sched.h>   //cpu_set_t , CPU_SET

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
#include <unistd.h>  //sysconf
#include <time.h> // clockid_t

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

// calculate interface header length
int calculate_link_len_h(pcap_t * pc_hdl);

// open udp socket
int init_socket();

//sent data using udp socket
int send_data(char * dst_ip, u_short port, char* data);

//stick the process id to the given core
int stick_proccess_to_core(int core_id, int pid_id);

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
  //start processing
  u_char * buff = packet;
  char * dst_addr,*data;
  u_short port;
  u_int ip_len;
  struct timespec initial_time,  final_time;
// CLOCK_REALTIME System-wide realtime clock .Can be used in different processes.
  clock_gettime(CLOCK_REALTIME, &initial_time);

 //we don't need any information from interface protocol
  if(get_ip_header_info(buff + linkhdrlen, &dst_addr, &ip_len) == -1)
    return;

  if(get_udp_info(buff + linkhdrlen + ip_len, &port, &data)==-1)
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
    ++fork_count; //increase number os created  processes
    pid_number = getpid(); // get number of the current process

    // glue pid_it to core
    stick_proccess_to_core(i,pid_number);
    u_char str_pid[255],str_time_diff[255];// buffer fot pid_id, time processing

    //init buffer with 0
    memset((char*)str_pid,0,sizeof str_pid );
   //convert pid_id number to string
    snprintf(str_pid, sizeof str_pid, "pid_id = %d, ",pid_number);

 //stop timer. The processing of the udp packet is finished.
    clock_gettime(CLOCK_REALTIME, &final_time);

   // calculate time diff
// bpf_u_int3
   bpf_u_int32 time_ns=(final_time.tv_sec - initial_time.tv_sec)*1e9 +
          (final_time.tv_nsec - initial_time.tv_nsec);

   //init buff with 0
   memset((char*)str_time_diff, 0, sizeof str_time_diff);
 // convert to string
   sprintf(str_time_diff,"time = %d ",time_ns);

// conc 
    strcat(str_pid, str_time_diff);
    // sending pid_id back to sender of magic number
    if(send_data(dst_addr,  port, str_pid)!= 0)
      fprintf(stderr, "failed to send data");
    return; // return from the child process
  }
}

// because the child processes are int queue we have to call wait function for each child
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

//catch the udp header data fron buffer
  udp_hdr = (struct udphdr*)buff;

  // we nned ort of sender beacuse we will send information to huim on that port
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
  // add data to socket structure
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = inet_addr(dst_ip);
  address.sin_port = htons(port);
// handle variable is a global varialble and it is initialise in the init_socket function
  int sent_bytes = sendto(handle, data, strlen(data),0,(const struct sockaddr*) &address, sizeof(struct sockaddr_in));
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

int stick_proccess_to_core(int core_id, int pid_id)
{
  int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
  if (core_id < 0 || core_id >= num_cores)
      return -1;

   cpu_set_t cpu_set;
   CPU_ZERO(&cpu_set);
   CPU_SET(core_id, &cpu_set);
   return sched_setaffinity(pid_id, sizeof(cpu_set), &cpu_set);
}
