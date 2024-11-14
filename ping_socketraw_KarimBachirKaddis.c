#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>

// Valore dell'opzione
#define ICMP_FILTER 1

// Dimensione del pacchetto
#define PING_PCKT_S 64

// Timeout di ricezione in secondi
#define RCV_TIMEOUT 1

// Guardia per il loop di ping
int pingloop = 1;

// Struttura del filtro ICMP
struct icmp_filter
{
    uint32_t data;
};

// Struttura del pacchetto
struct ping_pckt
{
    struct icmphdr hdr;
    char msg[PING_PCKT_S - sizeof(struct icmphdr)];
};
struct rcv_pckt
{
    struct iphdr iphdr;
    struct icmphdr icmphdr;
    char msg[PING_PCKT_S - sizeof(struct icmphdr)];
};

// Funzione chiamata tramite interrupt
void intHandler()
{
    pingloop = 0;
}

// Calcolo della checksum
uint16_t checksum(void *data, int len){
    uint16_t *buf = data;
    uint32_t sum = 0;
    // Somma dei byte 2 a 2
    while (len > 1){
        sum += *(buf++);
        len -= 2;
    }
    if (len == 1) sum += (uint8_t)*buf;
    // Da 32Byte a 16Byte
    while (sum >> 16){
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    return ~sum;
}

// Avvia il loop di ping finche pingloop == 1
void send_ping(int sd, struct sockaddr_in *dst_addr, int dst_addr_len, char *ping_ip)
{
    struct ping_pckt snd_pckt;
    struct rcv_pckt rcv_pckt;
    struct sockaddr_in r_addr;
    int pid = getpid(), msg_count = 0, msg_received_count = 0,
        snd_pckt_len = sizeof(snd_pckt), rcv_pckt_len = sizeof(rcv_pckt), r_addr_len = sizeof(r_addr), pcktLoss;
    struct timespec snd_time, rcv_time, s_time, e_time;
    struct timeval rcv_timeout;
    long double rtt_msec = 0, total_msec = 0;
    rcv_timeout.tv_sec = RCV_TIMEOUT;
    rcv_timeout.tv_usec = 0;

    clock_gettime(CLOCK_MONOTONIC, &s_time);

    // Filtro per accettare solo reply, dst unreachable e time exceeded
    struct icmp_filter filter;
    filter.data = ~((1 << ICMP_TIME_EXCEEDED) | (1 << ICMP_DEST_UNREACH) | (1 << ICMP_ECHOREPLY));

    // Imposta la socket option ICMP_FILTER
    if (setsockopt(sd, SOL_RAW, ICMP_FILTER, &filter, sizeof(filter)) < 0){
        printf("\nSetting ICMP_FILTER socket option failed!\n");
        return;
    }
    printf("\nICMP_FILTER socket option set...\n");

    // Imposta la socket option SO_RCVTIMEO
    if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&rcv_timeout, sizeof rcv_timeout) < 0){
        printf("\nSetting SO_RCVTIMEO socket option failed!\n");
        return;
    }
    printf("SO_RCVTIMEO socket option set...\n\n");

    while (pingloop)
    {
        memset(&snd_pckt, 0, snd_pckt_len);
        memset(&rcv_pckt, 0, rcv_pckt_len);

        // Setup dell'header ICMP
        snd_pckt.hdr.type = ICMP_ECHO;
        snd_pckt.hdr.un.echo.id = htons(pid);
        snd_pckt.hdr.un.echo.sequence = htons(msg_count);
        msg_count++;
        // Payload ICMP
        for (int i = 0; i < sizeof(snd_pckt.msg); i++)
            snd_pckt.msg[i] = i + '0';
        // Calcolo della checksum e inserimento nell'header
        snd_pckt.hdr.checksum = checksum(&snd_pckt, snd_pckt_len);

        clock_gettime(CLOCK_MONOTONIC, &snd_time);

        // Invio del pacchetto
        int sent = sendto(sd, &snd_pckt, snd_pckt_len, 0, (struct sockaddr *)dst_addr, dst_addr_len);
        if (sent <= 0){
            printf("\nPacket send Failed!\n");
        } else{
            // Ricezione del pacchetto
            int recvd = recvfrom(sd, &rcv_pckt, rcv_pckt_len, 0, (struct sockaddr *)&r_addr, &r_addr_len);
            if (recvd < 0){
                printf("\nPacket receive failed!\n");
            } else{

                clock_gettime(CLOCK_MONOTONIC, &rcv_time);

                double timeElapsed = ((double)(rcv_time.tv_nsec - snd_time.tv_nsec)) / 1000000;
                rtt_msec = (rcv_time.tv_sec - snd_time.tv_sec) * 1000 + timeElapsed;

                // Dst unreachable
                if (rcv_pckt.icmphdr.type == ICMP_DEST_UNREACH){
                    switch (rcv_pckt.icmphdr.code)
                    {
                    case ICMP_HOST_UNREACH:
                        printf("Error...Destination Host Unreachable, ICMP type %d code %d\n",
                               rcv_pckt.icmphdr.type, rcv_pckt.icmphdr.code);
                        break;
                    case ICMP_PROT_UNREACH:
                        printf("Error...Destination Protocol Unreachable, ICMP type %d code %d\n",
                               rcv_pckt.icmphdr.type, rcv_pckt.icmphdr.code);
                        break;
                    case ICMP_NET_UNREACH:
                        printf("Error...Destination Net Unreachable, ICMP type %d code %d\n",
                               rcv_pckt.icmphdr.type, rcv_pckt.icmphdr.code);
                        break;
                    case ICMP_PORT_UNREACH:
                        printf("Error...Destination Port Unreachable, ICMP type %d code %d\n",
                               rcv_pckt.icmphdr.type, rcv_pckt.icmphdr.code);
                        break;
                    default:
                        printf("Error...Destination Unreachable, ICMP type %d code %d\n",
                               rcv_pckt.icmphdr.type, rcv_pckt.icmphdr.code);
                        break;
                    }
                }
                // Time exceeded
                else if (rcv_pckt.icmphdr.type == ICMP_TIME_EXCEEDED){
                    switch (rcv_pckt.icmphdr.code)
                    {
                    case ICMP_TIMXCEED_INTRANS:
                        printf("Error...TTL Exceeded, ICMP type %d code %d\n",
                               rcv_pckt.icmphdr.type, rcv_pckt.icmphdr.code);
                        break;
                    case ICMP_TIMXCEED_REASS:
                        printf("Error...Fragment reassembly time Exceeded, ICMP type %d code %d\n",
                               rcv_pckt.icmphdr.type, rcv_pckt.icmphdr.code);
                        break;
                    default:
                        printf("Error...Time Exceeded, ICMP type %d code %d\n",
                               rcv_pckt.icmphdr.type, rcv_pckt.icmphdr.code);
                        break;
                    }
                }
                // Reply
                else if (rcv_pckt.icmphdr.type == ICMP_ECHOREPLY
                         && rcv_pckt.icmphdr.un.echo.id == htons(pid)){
                    printf("%d bytes from %s: icmp_seq=%d ttl=%d rtt=%Lf ms\n",
                           PING_PCKT_S, ping_ip, msg_count,
                           rcv_pckt.iphdr.ttl, rtt_msec);
                    msg_received_count++;
                }
                else{
                    printf("ERROR\n");
                }
            }
        }

        sleep(1);
    }

    clock_gettime(CLOCK_MONOTONIC, &e_time);

    double timeElapsed = ((double)(e_time.tv_nsec - s_time.tv_nsec)) / 1000000;
    total_msec = (e_time.tv_sec - s_time.tv_sec) * 1000 + timeElapsed;
    pcktLoss = ((msg_count - msg_received_count) / msg_count) * 100;

    printf("\n=== %s ping statistics ===\n", ping_ip);
    printf("%d packets sent, %d packets received, %d%% packet loss. time: %Lf ms.\n",
           msg_count, msg_received_count, pcktLoss, total_msec);
}

int main(int argc, char *argv[])
{
    int sd, dst_addr_len;
    struct sockaddr_in dst_addr;

    if (argc != 2){
        printf("\nFormat %s <address>\n", argv[0]);
        return 0;
    }

    // Setup destinatario
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = inet_addr(argv[1]);
    dst_addr_len = sizeof(dst_addr);
    // Socket
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sd < 0){
        printf("\nSocket file descriptor ERROR!!\nExiting...\n");
        return 0;
    }
    else printf("\nSocket file descriptor %d\n", sd);

    // Cattura l'interrupt
    signal(SIGINT, intHandler);

    // Chiama il loop
    send_ping(sd, &dst_addr, dst_addr_len, argv[1]);

    printf("\nExiting...\n");
    return 0;
}
