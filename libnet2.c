#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libnet.h>
char * sock_ntop(const struct sockaddr* sa,socklen_t salen) {
        char portstr[8];
        static char str[128];
        struct sockaddr_in *sin=(struct sockaddr_in*)sa;
        if(inet_ntop(AF_INET,&sin->sin_addr,str,sizeof(str))==NULL) return NULL;
        if(ntohs(sin->sin_port)!=0) {
                snprintf(portstr,sizeof(portstr),":%d",ntohs(sin->sin_port));
                strcat(str,portstr);
        }
        return str;
}
/*以太网头*/
struct sniff_ethernet
{
        u_char ether_dhost[ETHER_ADDR_LEN];
        u_char ether_shost[ETHER_ADDR_LEN];
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
/*
typedef struct tagIpv4Header_t
{
        union
        {
                struct ip_hdrctl
                {
                        u_char ip_vhl;
                        u_char ip_tos;
                        u_short

                }
        }

}
*/
typedef struct tagIPv6Header_t
{
    union
    {
        struct ip6_hdrctl
        {
            u_int32_t ip6_unl_flow;/* 4位的版本，8位的传输与分类，20位的流标识符 */
            u_int16_t ip6_unl_plen;/* 报头长度 */
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
/*UDP报头*/
struct sniff_udp
{
        u_short udp_sport;
        u_short udp_dport;
        u_short udp_len;
        u_short udp_sum;
};
int main(int argc, char *argv[])
{
        int sockfd2=0;
        struct sockaddr_in servaddr2;
        sockfd2=socket(AF_INET,SOCK_DGRAM,0);
        bzero(&servaddr2,sizeof(servaddr2));
        servaddr2.sin_family=AF_INET;
        servaddr2.sin_port=htons(9996);
        servaddr2.sin_addr.s_addr=htonl(INADDR_ANY) ;
        bind(sockfd2, (struct sockaddr *)&servaddr2, sizeof(servaddr2));
        int count =0;
        char errBuf[100];
        libnet_t *lib_net = NULL;
        libnet_ptag_t lib_t1 = 0;
    libnet_ptag_t lib_t2 = 0;
    libnet_ptag_t lib_t3 = 0;
//      unsigned char src_mac[6] = {0x02,0x42,0xac,0x11,0x01,0x22}; // 6e:b7:c5:1c:93:5d
//      unsigned char dst_mac[6] = {0x02,0x42,0xac,0x11,0x00,0x22}; // 02:42:ac:11:00:02
        unsigned char src_mac[6]; // 6e:b7:c5:1c:93:5d
        strcpy(src_mac,argv[3]);
        unsigned char dst_mac[6];
        strcpy(dst_mac,argv[2]); // 02:42:ac:11:00:02
        //unsigned char src_mac[6] = {0x6c,0xb3,0x11,0x50,0x25,0xbe};//发送者网卡地址00:0c:29:97:c7:c1 0x00,0x07,0x32,0x3f,0xe2,0x23eth1 6c:b3:11:50:25:be
        //unsigned char dst_mac[6] = {0x00,0xe0,0x4c,0x1a,0x02,0x43};//接收者网卡地址‎b8:ae:ed:23:3a:f0 0xb8,0xae,0xed,0x23,0x3c,0xe3
        lib_net = libnet_init(LIBNET_LINK_ADV, argv[1], errBuf);        //初始化
        if(NULL == lib_net)
        {
                perror("libnet_init");
                exit(-1);
        }

        unsigned char buffer[5000];
        unsigned char buffer1[1480];
        unsigned char buffer2[1480];
        struct sockaddr_in addr;
        socklen_t addr_len =sizeof(struct sockaddr_in);
        int len=0;
        while(1)
{
                bzero(buffer,sizeof(buffer));
                len = recvfrom(sockfd2,buffer,sizeof(buffer), 0 , (struct sockaddr *)&addr ,&addr_len);
                printf("receive %s: len:%d\n",sock_ntop((struct sockaddr *)&addr,addr_len),len);
                printf("proccessing***********************************\n");
                struct sniff_ip *ip;//ip4包头
                ip=(struct sniff_ip*)(buffer);//IP
                u_char *ip_1;
                ip_1=(u_char *)(buffer);
                lib_t1 = libnet_build_ethernet( //构造以太网数据包
                                                                                (u_int8_t *)dst_mac,
                                                                                (u_int8_t *)src_mac,
                                                                                0x0800, // 或者，ETHERTYPE_IP
                                                                                ip_1,//ip
                                                                                len,//ip-len
                                                                                lib_net,
                                                                                lib_t1
                                                                        );
                int res = 0;
                res = libnet_write(lib_net);    //发送数据包
                                printf("send!\n");
                memset(buffer,0,sizeof(buffer));
                if(-1 == res)
                {
                        perror("libnet_write");
                        exit(-1);
                }

}
        libnet_destroy(lib_net);        //销毁资源
        printf("----ok-----\n");
        return 0;
 }

