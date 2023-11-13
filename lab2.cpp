#include <iostream>
#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <iostream>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"packet.lib")
#pragma warning (disable: 4996)

using namespace std;

#define ETH_ARP         0x0806  //以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE    1  //硬件类型字段值为表示以太网地址
#define ETH_IP          0x0800  //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST     1   //ARP请求
#define ARP_RESPONSE       2      //ARP应答

//报文格式
#pragma pack(1)//以1byte方式对齐
typedef struct FrameHeader_t {//帧首部
	BYTE DesMAC[6];//目的地址
	BYTE SrcMAC[6];//源地址
	WORD FrameType;//帧类型
}FrameHeader_t;
typedef struct ARPFrame_t {//IP首部
	FrameHeader_t FrameHeader;
	WORD HardwareType;//硬件类型
	WORD ProtocolType;//协议类型
	BYTE HLen;//硬件地址长度
	BYTE PLen;//协议地址长度
	WORD Operation;//操作类型
	BYTE SendHa[6];//发送方MAC地址
	DWORD SendIP;//发送方IP地址
	BYTE RecvHa[6];//接收方MAC地址
	DWORD RecvIP;//接收方IP地址
}ARPFrame_t;


bool compare(u_char Arr1[], u_char Arr2[], int n)
{
	for (int i = 0; i < n; i++)
	{
		if (Arr1[i] != Arr2[i])
			return false;
	}
	return true;
}

int main()
{
	pcap_if_t* alldevs;   //所有网络适配器
	pcap_if_t* d;   //选中的网络适配器 
	int inum;   //选择网络适配器
	int i = 0;   //for循环变量
	pcap_t* adhandle;   //打开网络适配器，捕捉实例,是pcap_open返回的对象
	char errbuf[PCAP_ERRBUF_SIZE];   //错误缓冲区,大小为256

	/* 获取本机设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳转到选中的适配器 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* 打开设备 */
	if ((adhandle = pcap_open(d->name,          // 设备名
		65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	unsigned char mac[6] = { 0x00,0x01,0x02,0x03,0x04,0x05 };//本地物理地址或假的物理地址


	cout << "请输入目标ip地址 " << endl;
	char* Decip = new char[20];
	cin >> Decip;


	//开始填充ARP包，填充数据写死在代码中，测试用时数据可随意填写
	ARPFrame_t ARP_Packet;
	ARP_Packet.FrameHeader.FrameType = htons(0x806);//帧类型为ARP
	ARP_Packet.HardwareType = htons(0x0001);//硬件类型为以太网
	ARP_Packet.ProtocolType = htons(0x0800);//协议类型为IP
	ARP_Packet.HLen = 6;//硬件地址长度为6
	ARP_Packet.PLen = 4;//协议地址长为4
	ARP_Packet.Operation = htons(0x0001);//操作为ARP请求
	memset(ARP_Packet.FrameHeader.DesMAC, 0xff, 6);
	memcpy(ARP_Packet.FrameHeader.SrcMAC, mac, 6);
	memcpy(ARP_Packet.SendHa, mac, 6);
	memset(ARP_Packet.RecvHa, 0xff, 6);
	ARP_Packet.SendIP = inet_addr("122.122.122.122");//本机IP或假的ip
	ARP_Packet.RecvIP = inet_addr(Decip);//目标主机IP



	//如果发送成功
	if (pcap_sendpacket(adhandle, (u_char*)&ARP_Packet, sizeof(ARP_Packet)) == 0) {
		printf("\nPacketSend succeed\n");
	}
	else {
		printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
	}

	while (1)//可能会捕获到多条消息
	{
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
		if (rtn == 1)
		{
			ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
			if (ntohs(IPPacket->FrameHeader.FrameType) == 0x806)
			{//输出目的MAC地址
				if (!compare(IPPacket->FrameHeader.SrcMAC, mac, 6))//不是一开始发送的广播arp请求
				{
					printf(" MAC地址为:");
					//输出MAC地址
					for (int i = 0; i < 6; i++)
					{
						printf("%02x:", IPPacket->FrameHeader.SrcMAC[i]);
					}
					break;//找到MAc地址，退出
				}
			}
		}
	}

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);
	while (true);

	return 0;
}