#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "pcap.h"
#include <WinSock2.h>
#include <time.h>
#include <stdio.h>

u_char user[20];//User
u_char pass[20];//Password


/*MAC header*/
typedef struct mac_header
{
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
}mac_header;

/* TCP header */
typedef struct tcp_header
{
	u_short sport;		// Sourse port
	u_short dsport;		// Destination port
	u_int seq;			// Sequence
	u_int ack_num;		// Acknowledge number
	u_char ihl;			// Internet header length
	u_char frame;
	u_short wsize;		// Window size
	u_short crc;		// Check sum
	u_short urg;
}tcp_header;

/* IPv4 header */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	u_char saddr[4];		// Source address
	u_char daddr[4];		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

#define FROM_NIC
int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "port 21";
	struct bpf_program fcode;
#ifdef FROM_NIC	
	
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (Not available)\n");
	}

	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	/* Check if the user specified a valid adapter */
	if(inum < 1 || inum > i)
	{
		printf("\nOut of range.\n");
		
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for(d = alldevs, i = 0; i < inum-1 ;d = d->next, i++);
	
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter %s.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Check the link layer. We support only Ethernet for simplicity. */
	if(pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	if(d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask=0xffffff; 
	
	/* Compile filter */
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Set filter */
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Listening */
	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
#else
	/* Open the capture file */
	if ((adhandle = pcap_open_offline("C:\\Users\\RakahDraShen\\Desktop\\dns.pcap",			// name of the device
		errbuf					// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file.\n");
		return -1;
	}

	/* read and dispatch packets until EOF is reached */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);
#endif
	return 0;
}

void print_inf(ip_header* ih, mac_header* mh, const struct pcap_pkthdr* header, char user[], char pass[], int isSucceed)
{
	if (user[0] == '\0') return;

	char timestr[46];
	struct tm *ltime;
	time_t local_tv_sec;

	/* Convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", ltime);

	/* Print date and time */
	printf("%s ", timestr);

	/* Print client MAC address */
	printf("%02X-%02X-%02X-%02X-%02X-%02X,",mh->dest_addr[0], mh->dest_addr[1], mh->dest_addr[2], mh->dest_addr[3], mh->dest_addr[4], mh->dest_addr[5]);
	
	/* Print client IP address */
	printf("%d.%d.%d.%d,",ih->daddr[0], ih->daddr[1], ih->daddr[2], ih->daddr[3]);
	
	/* Print FTP server MAC address */
	printf("%02X-%02X-%02X-%02X-%02X-%02X,",mh->src_addr[0], mh->src_addr[1], mh->src_addr[2],mh->src_addr[3], mh->src_addr[4], mh->src_addr[5]);
	
	/* Print FTP server IP address */
	printf("%d.%d.%d.%d,",ih->saddr[0], ih->saddr[1], ih->saddr[2], ih->saddr[3]);

	/* Print user and password */
	printf("%s,%s,", user, pass);

	if (isSucceed) printf("SUCCEED\n");
	else printf("FAILED\n");

	/* Another format */
	printf("FTP: %d.%d.%d.%d    User:%s    Password:%s    Status:", ih->saddr[0], ih->saddr[1], ih->saddr[2], ih->saddr[3],user,pass);
	if (isSucceed) printf("SUCCEED\n");
	else printf("FAILED\n");

	user[0] = '\0';
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	ip_header* ih;
	mac_header* mh;
	u_int i = 0;

	int length = sizeof(mac_header) + sizeof(ip_header);
	mh = (mac_header*)pkt_data;
	ih = (ip_header*)(pkt_data + 14); //length of ethernet header

	int name_point = 0;
	int pass_point = 0;
	int tmp;


	for (int i = 0; i < ih->tlen - 40; i++) 
	{
		/* Get user name and password */
		if (*(pkt_data + i) == 'U' && *(pkt_data + i + 1) == 'S' && *(pkt_data + i + 2) == 'E' && *(pkt_data + i + 3) == 'R') 
		{
			name_point = i + 5;	// User

			int j = 0;
			while (!(*(pkt_data + name_point) == 13 && *(pkt_data + name_point + 1) == 10)) //
			{
				user[j] = *(pkt_data + name_point);
				j++;
				++name_point;
			}
			user[j] = '\0';
			break;

		}

		if (*(pkt_data + i) == 'P' && *(pkt_data + i + 1) == 'A' && *(pkt_data + i + 2) == 'S' && *(pkt_data + i + 3) == 'S') 
		{
			pass_point = i + 5;	// Password
			tmp = pass_point;

			int k = 0;
			while (!(*(pkt_data + pass_point) == 13 && *(pkt_data + pass_point + 1) == 10))
			{
				pass[k] = *(pkt_data + pass_point);
				k++;
				++pass_point;

			}
			pass[k] = '\0';

			for (;; tmp++) 
			{
				if (*(pkt_data + tmp) == '2' && *(pkt_data + tmp + 1) == '3' && *(pkt_data + tmp + 2) == '0') 
				{
					print_inf(ih, mh, header, (char*)user, (char*)pass, 1);
					break;
				}
				else if (*(pkt_data + tmp) == '5' && *(pkt_data + tmp + 1) == '3' && *(pkt_data + tmp + 2) == '0')
				{
					print_inf(ih, mh, header, (char*)user, (char*)pass, 0);
					break;
				}
			}
			break;
		}
	}
}