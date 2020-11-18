#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
int sockfd4=0;
int scokfd4_2=0;
int scokfd4_3=0;
int sock_raw_fd=0;
char mac[12];
 struct sockaddr_ll sll;   //指定网卡名需要sockaddr_ll类型
struct sockaddr_in servaddr4;
struct sockaddr_in servaddr4;
socklen_t addr_len =sizeof(struct sockaddr_in);
/*以太网头*/
struct sniff_ethernet
{
  struct ether_addr ether_dhost;
  struct ether_addr ether_shost;
  u_short ether_type;
};
/*IP头*/
struct sniff_ip
{
  u_char ip_vhl;
  u_char ip_tos;
  u_short ip_len;
  u_short ip_id;
  u_short ip_off;
  #define IP_RF 0x8000
  #define IP_DF 0x4000
  #define IP_MF 0x2000
  #define IP_OFFMASK 0x1fff
  u_char ip_ttl;
  u_char ip_p;
  u_short ip_sum;
  struct in_addr ip_src,ip_dst;
};
/*UDP报头*/
struct sniff_udp
{
  u_short udp_sport;
  u_short udp_dport;
  u_short udp_len;
  u_short udp_sum;
};

/*arp*/

struct arp_head
{
    u_char hardware_type[2];
    u_char protocol_type[2];
    u_char hardware_size;
    u_char protocol_size;
    u_char opcode[2];
    u_char  send_mac[6];
    struct in_addr  send_ip;
    u_char  target_mac[6];
    struct in_addr  target_ip;

}__attribute__((packed));


void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
  /*int * id = (int *)arg;
  printf("id: %d\n", ++(*id));
  printf("Packet length: %d\n", pkthdr->len);
  printf("Number of bytes: %d\n", pkthdr->caplen);
  printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));
  int i;
 /* for(i=0; i<pkthdr->caplen; ++i)
  {
    printf("%02x", packet[i]);
    if( (i + 1) % 16 == 0 )
    {
      printf("\n");
    }
  }*/
  printf("\n");
  printf("receving*********************\n");
  struct sniff_ethernet *ethernet;
  struct sniff_ip *ip;//ip包头
  struct sniff_udp *udp;//udp包头
  struct arp_head *arp;
  u_char *payload;//数据包负载的数据
  int payload_size;//数据包负载的数据大小

  //change the place of initialize socket to enable the port num random
  sockfd4=socket(AF_INET,SOCK_DGRAM,0);
  bzero(&servaddr4,sizeof(servaddr4));
  servaddr4.sin_family=AF_INET;
  servaddr4.sin_port=htons(12346);
  inet_pton(AF_INET,"127.0.0.1",&servaddr4.sin_addr);
  char ether_smac[256];
  char ether_dmac[256];
  ethernet=(struct sniff_ethernet*)(packet);
   struct ether_addr smac;
  smac=ethernet->ether_shost;
 sprintf(ether_smac,"%02x:%02x:%02x:%02x:%02x:%02x",smac.ether_addr_octet[0],smac.ether_addr_octet[1],smac.ether_addr_octet[2],smac.ether_addr_octet[3],smac.ether_addr_octet[4],smac.ether_addr_octet[5]);
 struct ether_addr dmac;
  dmac=ethernet->ether_dhost;
 sprintf(ether_dmac,"%02x:%02x:%02x:%02x:%02x:%02x",dmac.ether_addr_octet[0],dmac.ether_addr_octet[1],dmac.ether_addr_octet[2],dmac.ether_addr_octet[3],dmac.ether_addr_octet[4],dmac.ether_addr_octet[5]);
   u_short ftype = 0;
   ftype=ntohs(ethernet->ether_type);
   switch(ftype){
     case 0x0800:
  //取出IP包
  ip=(struct sniff_ip*)(packet + sizeof(struct sniff_ethernet));
  //printf("len:%d\n",ntohs(ip->ip_len));
  udp = (struct sniff_udp*)(packet + sizeof(struct sniff_ethernet) + sizeof(struct sniff_ip));
  //取出IP包
  payload = (u_char *)(packet + sizeof(struct sniff_ethernet) + sizeof(struct sniff_ip) + sizeof(struct sniff_udp));

  //printf("len:%d\n",ntohs(udp->udp_len));
  struct in_addr addr2;
  addr2 = ip -> ip_src;
char addr3[256];
 inet_ntop(AF_INET,(void *)&addr2,addr3,256);
 printf("%s\n",addr3);
 if(strcmp(mac,ether_smac) && strcmp("ff:ff:ff:ff:ff:ff",ether_dmac)){
        printf("can send\n");
        sendto(sockfd4,payload,ntohs(udp->udp_len)-8,0,(struct sockaddr *)&servaddr4,addr_len);
        break;

}
  case 0x0806:
      arp=(struct arp_head*)(packet + sizeof(struct sniff_ethernet));
      struct in_addr addr4;
      addr4 = arp->send_ip;
      char addr5[256];
      inet_ntop(AF_INET,(void *)&addr4,addr5,256);
      if(strcmp(mac,ether_smac))
      {
      sendto(sock_raw_fd, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
      printf("send arp packet success!\n");
      }
      break;
 }
  //sendto(sockfd4,ip,ntohs(ip->ip_len),0,(struct sockaddr *)&servaddr4,addr_len);
}

int main(int argc ,char* argv[])
{
  char errBuf[PCAP_ERRBUF_SIZE], * devStr;
  /* open a device, wait until a packet arrives */
  //pcap_t * device = pcap_open_live(argv[1], BUFSIZ, 1, 0, errBuf);
  pcap_t * device = pcap_open_live(argv[1], 65500, 1, 0, errBuf);
  if(!device)
  {
    printf("error: pcap_open_live(): %s\n", errBuf);
    exit(1);
  }
  /* construct a filter */

  strcpy(mac,argv[3]);
  struct bpf_program filter;

  //过滤规则设置
  pcap_compile(device, &filter, "ip or arp", 1, 0);
  pcap_setfilter(device, &filter);
  //过滤出来发到本地的udp 5012端口

  sockfd4=socket(AF_INET,SOCK_DGRAM,0);
  bzero(&servaddr4,sizeof(servaddr4));
  servaddr4.sin_family=AF_INET;
  servaddr4.sin_port=htons(12346);
  inet_pton(AF_INET,"127.0.0.1",&servaddr4.sin_addr);

  sock_raw_fd=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP)); //添加ARP发送通道

  struct ifreq req;  //配置ip、激活接口、配置MTU等
  strncpy(req.ifr_name,argv[2],IFNAMSIZ); //将网卡名放入
  if(-1==ioctl(sock_raw_fd, SIOCGIFINDEX, &req))
  {
      perror("ioctl");
      close(sock_raw_fd);
      exit(1);
  }
  bzero(&sll, sizeof(sll));
  sll.sll_ifindex=req.ifr_ifindex;
  sll.sll_family=AF_PACKET;
//  sll.sll_halen=ETHER_ADDR_LEN;
  sll.sll_protocol=htons(ETH_P_ARP);
//  memcpy(sll.sll_addr,dst_mac,ETHER_ADDR_LEN);

  scokfd4_2=socket(AF_INET,SOCK_DGRAM,0);
  scokfd4_3=socket(AF_INET,SOCK_DGRAM,0);

  /* wait loop forever */
  int id = 0;
  pcap_loop(device, -1, getPacket, (u_char*)&id);
  pcap_close(device);

  return 0;
}
