#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <libnet.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>


#ifndef u_char
#define u_char unsigned char
#endif

#ifndef u_int8
#define u_int8 unsigned char
#endif

#ifndef u_int16
#define u_int16 unsigned short
#endif

#ifndef u_int32
#define u_int32 unsigned int
#endif

#ifndef u_int64
#define u_int64 unsigned long long
#endif

#ifndef u_short
#define u_short unsigned short
#endif
int sfd_no=0;
int sockfd4=0;
int sockfd4_2=0;
int sockfd4_3=0;
int sock_raw_fd=0;
char mac[256];
 struct sockaddr_ll sll;   //指定网卡名需要sockaddr_ll类型
struct sockaddr_in servaddr4;
socklen_t addr_len =sizeof(struct sockaddr_in);
/*以太网头*/
struct sniff_ethernet
{
  struct ether_addr ether_dhost;
  struct ether_addr ether_shost;
  u_short ether_type;
};
/*IPv4头*/
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
//IPv6基本首部
#if 0
typedef struct tagIPv6Header_t
{
    u_char    version:4;      // 4-bit版本号
    u_char  traffic_class:8;  // 8-bit流量等级
    u_int32 label:20;       // 20-bit流标签
    u_short    payload_len;    // 16-bit 载荷长度
    u_char    next_header;    // 8-bit 下一首部
    u_char    hop_limit;        // 8-bit 跳数限制
    struct
    {
        u_int64 prefix_subnetid;
        u_char interface_id[8];
    } src_ip;                // 128-bit 源地址
    struct
    {
        u_int64 prefix_subnetid;
        u_char interface_id[8];
    } dst_ip;                // 128-bit 目的地址

} IPv6Header_t;
#else

typedef struct tagIPv6Header_t
{
    union
    {
        struct ip6_hdrctl
        {
            u_int32_t ip6_unl_flow;/* 4位的版本，8位的传输与分类，20位的流标识符 */
            u_int16_t ip6_unl_plen;/* 载荷长度 */
            u_int8_t ip6_unl_nxt;  /* 下一个报头 */
            u_int8_t ip6_unl_hlim; /* 跨度限制 */
        }ip6_unl ;

        u_int8_t ip6_un2_vfc;/* 4位的版本号，跨度为4位的传输分类 */
    }ip6_ctlun ;

#define ip6_vfc              ip6_ctlun.ip6_un2_vfc
#define ip6_flow             ip6_ctlun.ip6_unl.ip6_unl_flow
#define ip6_plen             ip6_ctlun.ip6_unl.ip6_unl_plen
#define ip6_nxt              ip6_ctlun.ip6_unl.ip6_unl_nxt
#define ip6_hlim             ip6_ctlun.ip6_unl.ip6_unl_hlim
#define ip6_hops             ip6_ctlun.ip6_unl.ip6_unl_hops

    struct in6_addr ip6_src;/* 发送端地址 */
    struct in6_addr ip6_dst;/* 接收端地址 */
}IPv6Header_t;
#endif

/*UDP报头*/
struct sniff_udp
{
  u_short udp_sport;
  u_short udp_dport;
  u_short udp_len;
  u_short udp_sum;
};

/*arp报头*/
struct arp_head
{
    u_short hardware_type;  //2
    u_short protocol_type; //2
    u_char hardware_size;  //1
    u_char protocol_size;  //1
    u_short opcode;  //2
    u_char  send_mac[6];  //6
    struct in_addr  send_ip; //4
    u_char  target_mac[6]; //6
    struct in_addr  target_ip; //4

}__attribute__((packed));





/*回调函数*/
void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{

  printf("proccessing`````\n");
  struct sniff_ethernet *ethernet;
  struct sniff_ip *ip;//ip包头
  struct arp_head *arp;
  struct tagIPv6Header_t *ipv6;//ipv6包头
  struct sniff_udp *udp;//udp包头
  u_char *payload;//数据包负载的数据
  int payload_size;//数据包负载的数据大小

  //change the place of initialize socket to enable the port num random
  /*
  sockfd4=socket(AF_INET,SOCK_DGRAM,0);
  bzero(&servaddr4,sizeof(servaddr4));
  servaddr4.sin_family=AF_INET;
  servaddr4.sin_port=htons(12345);
  inet_pton(AF_INET,"127.0.0.1",&servaddr4.sin_addr);
  */

  ethernet=(struct sniff_ethernet*)(packet);
  char ether_mac[512];
  u_short ftype = 0;
  ftype = ntohs(ethernet->ether_type); //指向ip包的类型
  struct ether_addr smac;
  smac=ethernet->ether_shost;
//  snprintf(ether_mac,20,"%s",ether_ntoa(&smac));
 sprintf(ether_mac,"%02x:%02x:%02x:%02x:%02x:%02x",smac.ether_addr_octet[0],smac.ether_addr_octet[1],smac.ether_addr_octet[2],smac.ether_addr_octet[3],smac.ether_addr_octet[4],smac.ether_addr_octet[5]);
  printf("ftype=%x\n",ftype);
  switch(ftype){
        case 0x0800:  /* ipv4 */
        ip=(struct sniff_ip*)(packet + sizeof(struct sniff_ethernet));
//      printf("len:%d\n",ntohs(ip->ip_len));
                printf("len:%d\n",ntohs(ip->ip_len));
                struct in_addr addr2;
                addr2= ip->ip_src;  //获取源ip
                char addr3[256];
                inet_ntop(AF_INET,(void *)&addr2,addr3,256); //源ip转换为string格式
                printf("ethernet addr = %s\n",ether_mac);
                if(!strcmp(mac,ether_mac))
                {       //对比筛选出要封装的ip包
         sendto(sockfd4,ip,ntohs(ip->ip_len),0,(struct sockaddr *)&servaddr4,addr_len);
             printf("send %s \n",addr3);
                }  //将数据包从ip开始发送到
                break;

    case 0x0806:
      printf("arp packet starting!\n");
      arp=(struct arp_head*)(packet + sizeof(struct sniff_ethernet));
      struct in_addr addr4;
      addr4= arp->send_ip;
      char addr5[256];
      inet_ntop(AF_INET,(void *)&addr4,addr5,256);
      //printf("%s\n",addr5);
      printf("%s\n",ether_mac);
      printf("%s\n",mac);
      if(!strcmp(mac,ether_mac))
      {

      sendto(sock_raw_fd, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
      printf("send arp packet success!\n");
      }
      break;

  }

}

int main(int argc ,char* argv[])
{
  char errBuf[PCAP_ERRBUF_SIZE], * devStr;
  /* open a device, wait until a packet arrives */
  pcap_t * device = pcap_open_live(argv[1], BUFSIZ, 1, 0, errBuf);  //获取网卡设备地址
  if(!device)
  {
    printf("error: pcap_open_live(): %s\n", errBuf);
    exit(1);
  }
  strcpy(mac,argv[3]);
  /* construct a filter */
  struct bpf_program filter;
  //过滤规则设置
  pcap_compile(device, &filter, "ip or arp", 1, 0);  //过滤规则设置ip类型
  pcap_setfilter(device, &filter);
  //过滤出来发到本地的udp 5012端口

  sockfd4=socket(AF_INET,SOCK_DGRAM,0);
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


  bzero(&servaddr4,sizeof(servaddr4));  //socket地址清空及设置
  servaddr4.sin_family=AF_INET;
  servaddr4.sin_port=htons(12345);  //目的端口12345
  inet_pton(AF_INET,"127.0.0.1",&servaddr4.sin_addr);

  /* wait loop forever */
  int id = 0;
  pcap_loop(device, -1, getPacket, (u_char*)&id);  //开启循环抓包
  pcap_close(device);

  return 0;
}


