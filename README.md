# AOS-gateway  
IPv4协议数据包通过网关实现AOS帧头封装，下层使用IP协议实现透传。  
程序功能如下：  
1.aos_gateway:实现对数据包的AOS封装和解封  
2.pcap1.c捕获网卡发来的数据包，去掉以太网头部以后发送给网关封装  
3.libnet1.c网关封装好的数据包外层封装udp头、ipv4头、以太网头,其中以太网头目的mac地址需手动添加或从数据库读取  
4.pcap2.c：接收对端发来的AOD数据包，将AOS帧之前的透传协议去掉，发给网关去除AOS帧头  
libnet2.c，将解封之后的数据包发送给接收端。  



运行代码：  
/****编译***/  
gcc aos_gateway.c -o aos -pthread  
gcc pcap1.c -o pcap1 -lpcap  
gcc pcap2.c -o pcap2 -lpcap  
gcc libnet1.c -o libnet1 -lnet  
gcc libnet2.c -o libnet2 -lnet  

/*****后台运行***/  
nohup ./aos > /dev/null 2>&1 &  
nohup ./pcap1  vs0_2_eth0 vs0_2_eth1 00:60:2f:f6:83:95> /dev/null 2>&1 &  
nohup ./libnet1 vs0_2_eth1 00:60:2f:f6:83:95 00:60:2F:DF:75:53> /dev/null 2>&1 &  
nohup ./libnet2 vs0_2_eth0 00:60:2f:f6:83:95 a2:0b:ba:28:91:cb> /dev/null 2>&1 &  
nohup ./pcap2 vs0_2_eth1 vs0_2_eth0 00:60:2f:f6:83:95 > /dev/null 2>&1 &  



说明：vs0_2_eth0为网关与节点相连的网卡，vs0_2_eth1为网关与交换机或下一跳连接的网卡  
00:60:2f:f6:83:95为本机vs0_2_eth1的mac地址  
a2:0b:ba:28:91:cb为本机vs0_2_eth0的mac地址  
00:60:2F:DF:75:53为下一跳mac   

备注：为了实现ARP功能，网关vs0_2_eth1的mac地址与节点vs0_2的mac地址须保持一致。
