#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#pragma comment(lib,"ws2_32.lib")

unsigned long dwProtocol=IPPROTO_IP;
unsigned long dwInterface=0;
unsigned long dwIoControlCode=SIO_RCVALL;

// WSAIoctl option
#define SIO_RCVALL              (IOC_IN|IOC_VENDOR|1)
/*
#define SIO_RCVALL_MCAST        (IOC_IN|IOC_VENDOR|2)
#define SIO_RCVALL_IGMPMCAST    (IOC_IN|IOC_VENDOR|3)
#define SIO_KEEPALIVE_VALS      (IOC_IN|IOC_VENDOR|4)
#define SIO_ABSORB_RTRALERT (IOC_IN|IOC_VENDOR|5)
#define SIO_UCAST_IF            (IOC_IN|IOC_VENDOR|6)
#define SIO_LIMIT_BROADCASTS    (IOC_IN|IOC_VENDOR|7)
#define SIO_INDEX_BIND          (IOC_IN|IOC_VENDOR|8)
#define SIO_INDEX_MCASTIF       (IOC_IN|IOC_VENDOR|9)
#define SIO_INDEX_ADD_MCAST (IOC_IN|IOC_VENDOR|10)
#define SIO_INDEX_DEL_MCAST     (IOC_IN|IOC_VENDOR|11)
*/

#define HI_WORD(byte)    (((byte) >> 4) & 0x0F)
#define LO_WORD(byte)    ((byte) & 0x0F)

// A list of protocol types in the IP protocol header
char *szProto[] = {"Reserved",     //  0
                   "ICMP",         //  1
                   "IGMP",         //  2
                   "GGP",          //  3
                   "IP",           //  4
                   "ST",           //  5
                   "TCP",          //  6
                   "UCL",          //  7
                   "EGP",          //  8
                   "IGP",          //  9
                   "BBN-RCC-MON",  // 10
                   "NVP-II",       // 11
                   "PUP",          // 12
                   "ARGUS",        // 13
                   "EMCON",        // 14
                   "XNET",         // 15
                   "CHAOS",        // 16
                   "UDP",          // 17
                   "MUX",          // 18
                   "DCN-MEAS",     // 19
                   "HMP",          // 20
                   "PRM",          // 21
                   "XNS-IDP",      // 22
                   "TRUNK-1",      // 23
                   "TRUNK-2",      // 24
                   "LEAF-1",       // 25
                   "LEAF-2",       // 26
                   "RDP",          // 27
                   "IRTP",         // 28
                   "ISO-TP4",      // 29
                   "NETBLT",       // 30
                   "MFE-NSP",      // 31
                   "MERIT-INP",    // 32
                   "SEP",          // 33
                   "3PC",          // 34
                   "IDPR",         // 35
                   "XTP",          // 36
                   "DDP",          // 37
                   "IDPR-CMTP",    // 38
                   "TP++",         // 39
                   "IL",           // 40
                   "SIP",          // 41
                   "SDRP",         // 42
                   "SIP-SR",       // 43
                   "SIP-FRAG",     // 44
                   "IDRP",         // 45
                   "RSVP",         // 46
                   "GRE",          // 47
                   "MHRP",         // 48
                   "BNA",          // 49
                   "SIPP-ESP",     // 50
                   "SIPP-AH",      // 51
                   "I-NLSP",       // 52
                   "SWIPE",        // 53
                   "NHRP",         // 54
                   "unassigned",   // 55
                   "unassigned",   // 56
                   "unassigned",   // 57
                   "unassigned",   // 58
                   "unassigned",   // 59
                   "unassigned",   // 60
                   "any host internal protocol",  // 61
                   "CFTP",         // 62
                   "any local network",           // 63
                   "SAT-EXPAK",    // 64
                   "KRYPTOLAN",    // 65
                   "RVD",          // 66
                   "IPPC",         // 67
                   "any distributed file system", // 68
                   "SAT-MON",    // 69
                   "VISA",       // 70
                   "IPCV",       // 71
                   "CPNX",       // 72
                   "CPHB",       // 73
                   "WSN",        // 74
                   "PVP",        // 75
                   "BR-SAT-MON", // 76
                   "SUN-ND",     // 77
                   "WB-MON",     // 78
                   "WB-EXPAK",   // 79
                   "ISO-IP",     // 80
                   "VMTP",       // 81
                   "SECURE-VMTP",// 82
                   "VINES",      // 83
                   "TTP",        // 84
                   "NSFNET-IGP", // 85
                   "DGP",        // 86
                   "TCF",        // 87
                   "IGRP",       // 88
                   "OSPFIGP",    // 89
                   "Sprite-RPC", // 90
                   "LARP",       // 91
                   "MTP",        // 92
                   "AX.25",      // 93
                   "IPIP",       // 94
                   "MICP",       // 95
                   "SCC-SP",     // 96
                   "ETHERIP",    // 97
                   "ENCAP",      // 98
                   "any private encryption scheme",    // 98
                   "GMTP"        // 99
};

// Decode TCP/IP header.
int decode(char *hdr)
{
    SOCKADDR_IN stSrc,stDest;
    unsigned short ip_version,
                   ip_hdr_len,
                   ip_tos,
                   ip_total_len,
                   ip_id,
                   ip_flags,
                   ip_ttl,
                   ip_frag_offset,
                   ip_proto,
                   ip_hdr_chksum,
                   ip_src_port,
                   ip_dest_port;
    unsigned int   ip_src,ip_dest;
    unsigned short usVal;
    char *tcpip,szSrc[255],szDest[255];

    ip_version = (unsigned short)HI_WORD(*hdr);
    ip_hdr_len = (unsigned short)(LO_WORD(*hdr) * 4);
    tcpip= (char *)(hdr + ip_hdr_len);
    hdr++;

    ip_tos = *hdr;
    hdr++;

    memcpy(&usVal, hdr, 2);
    ip_total_len = ntohs(usVal);
    hdr += 2;

    memcpy(&usVal, hdr, 2);
    ip_id = ntohs(usVal);
    hdr += 2;

    ip_flags = (unsigned short)((*hdr) >> 5);

    memcpy(&usVal, hdr, 2);
    ip_frag_offset = (unsigned short)((ntohs(usVal)) & 0x1FFF);
    hdr+=2;

    ip_ttl = *hdr;
    hdr++;

    ip_proto = *hdr;
    hdr++;

    memcpy(&usVal, hdr, 2);
    ip_hdr_chksum = ntohs(usVal);
    hdr += 2;

    memcpy(&stSrc.sin_addr.s_addr, hdr, 4);
    ip_src = ntohl(stSrc.sin_addr.s_addr);
    hdr += 4;

    memcpy(&stDest.sin_addr.s_addr, hdr, 4);
    ip_dest = ntohl(stDest.sin_addr.s_addr);
    hdr += 4;

    //printf("%-10s %-15s->%-15s\n",szProto[ip_proto],inet_ntoa(stSrc.sin_addr),inet_ntoa(stDest.sin_addr));

    switch(ip_proto){
        case 2: // IGMP
        case 6: // TCP
        case 17: //UDP
            memcpy(&ip_src_port,tcpip,2);
            ip_src_port=ntohs(ip_src_port);
            memcpy(&ip_dest_port,tcpip+2,2);
            ip_dest_port=ntohs(ip_dest_port);
            sprintf(szSrc,"%s:%d",inet_ntoa(stSrc.sin_addr),ip_src_port);
            sprintf(szDest,"%s:%d",inet_ntoa(stDest.sin_addr),ip_dest_port);
            printf("%-10s %-21s-> %-21s\n",szProto[ip_proto],szSrc,szDest);
        default:
            printf("%-10s %-21s-> %-21s\n",szProto[ip_proto],inet_ntoa(stSrc.sin_addr),inet_ntoa(stDest.sin_addr));
    }
    return 0;
}

// Print all local IP interfaces.
void printif()
{
    SOCKET_ADDRESS_LIST *pstlist=NULL;
    SOCKET s;
    char szBuf[4096];
    unsigned long dwBytesRet;
    int i;

    s=socket(AF_INET,SOCK_STREAM,IPPROTO_IP);
    if(s==SOCKET_ERROR){
        printf("socket() failed!error code:%d\n",WSAGetLastError());
        return;
    }
    if(WSAIoctl(s,SIO_ADDRESS_LIST_QUERY,NULL,0,szBuf,4096,&dwBytesRet,NULL,NULL)==SOCKET_ERROR)
    {
        printf("WSAIoctl(SIO_ADDRESS_LIST_QUERY) failed!Error code:%d\n",WSAGetLastError());
        return;
    }
    pstlist=(SOCKET_ADDRESS_LIST *)szBuf;
    for(i=0;i<pstlist->iAddressCount;i++)
    {
        printf("      %d  %s\n",i,inet_ntoa(((SOCKADDR_IN *)pstlist->Address[i].lpSockaddr)->sin_addr));;
    }

    closesocket(s);
    return;
}

void usage(char *progname)
{
    printf("usage: %s [interface-num]\n\n",progname);
    printf("  -i:num  Capture on this interface\n");
    printf("      Available interfaces:\n");
    printif();
    printf("  -h     Help information\n");

    WSACleanup();
    ExitProcess((unsigned int)-1);
}

void ArgsProc(int argc,char **argv)
{
    int i;

    for(i=1;i<argc;i++)
    {
        if(strlen(argv[i])<2){
            continue;
        }
        if((argv[i][0]=='-')||argv[i][0]=='/')
        {
            switch(tolower(argv[i][1]))
            {
                case 'i':
                    dwInterface=atoi(&argv[i][3]);
                    break;
                case 'h':
                    usage(argv[0]);
                    break;
                default:
                    usage(argv[0]);
            }
        }
    }
}


// Get all local IP interfaces.
int getif(SOCKET s,SOCKADDR_IN *if0,unsigned long dwNum)
{
    SOCKET_ADDRESS_LIST *pstList=NULL;
    unsigned long dwBytesRet;
    char szBuf[4096];
    int  nRet;

    nRet=WSAIoctl(s, SIO_ADDRESS_LIST_QUERY, NULL,0,szBuf, 4096, &dwBytesRet, NULL,NULL);
    if(nRet==SOCKET_ERROR){
        printf("WSAIoctl(SIO_ADDRESS_LIST_QUERY) failed!Error code:%d\n",WSAGetLastError());
        return 1;
    }

    pstList=(SOCKET_ADDRESS_LIST *)szBuf;
    if((int)(dwNum)>=pstList->iAddressCount){
        return 1;
    }
    if0->sin_addr.s_addr=((SOCKADDR_IN *)pstList->Address[dwNum].lpSockaddr)->sin_addr.s_addr;

    return 0;
}

int main(int argc,char **argv)
{
    WSADATA  stWsaData;
    SOCKET     s;
    SOCKADDR_IN if0;
    unsigned int  uiOptval;
    unsigned long dwBytesRet;
    int nRet,bLoop=1;
    char szBuff[65535];

    if(WSAStartup(MAKEWORD(2, 2),&stWsaData)!=0)
    {
        printf("WSAStartup() failed!Error code:%d\n",WSAGetLastError());
        return 1;
    }

    ArgsProc(argc,argv);
    s=socket(AF_INET,SOCK_RAW,dwProtocol);
    if(s==INVALID_SOCKET){
        printf("socket() failed!Error code:%d\n",WSAGetLastError());
        return 1;
    }
    // Get an interface to read IP packets on
    if(getif(s,&if0,dwInterface)!=0)
    {
        printf("Unable to obtain an interface!\n");
        return 1;
    }
    printf("Binding to if:%s\n",inet_ntoa(if0.sin_addr));

    // This socket must be bound before calling the ioctl
    if0.sin_family=AF_INET;
    if0.sin_port=htons(0);

    if(bind(s,(SOCKADDR *)&if0,sizeof(if0))==SOCKET_ERROR){
        printf("bind() falied!Error code:%d\n",WSAGetLastError());
        return 1;
    }

    uiOptval=1;
    if(WSAIoctl(s,dwIoControlCode,&uiOptval,sizeof(uiOptval),NULL,0,&dwBytesRet,NULL,NULL)==SOCKET_ERROR)
    {
        printf("WSAIoctl(%d) failed,Error code:%d\n",dwIoControlCode,WSAGetLastError());

        return 1;
    }

    while(bLoop){
        nRet=recv(s,szBuff,sizeof(szBuff),0);
        if(nRet==SOCKET_ERROR)
        {
            printf("recv() failed!Error code:%d\n",WSAGetLastError());
            return 1;
        }
        decode(szBuff);
    }

    closesocket(s);
    WSACleanup();

    return 0;
}
