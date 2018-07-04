#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <errno.h>
#include <libgen.h>
#include <time.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>

#include "myether.h"
/*****************************************************************************
 * C03:   PRIVATE CONSTANT DEFINITIONS
 *****************************************************************************/
#define MAX_IFNAMSIZ 32
#define MAXNAME 10
#define ETHERHERNETHEADER 14
#define ETHER_TYPE   ((u_int16_t) 0x1234) || ((u_int16_t) 0x4321)//magic number
#define RX_BUF_SIZE 1600
//#define fragment_count 2
/*****************************************************************************
 * C04:   PRIVATE DATA TYPES
 *****************************************************************************/

typedef struct {
    char ethernet_header[ETHERHERNETHEADER];
    char name[MAXNAME];
    char surname[MAXNAME];
    char filename[32];
    uint32_t file_size;
    uint16_t fragment_count;
    uint16_t fragment_index;
    uint32_t fragment_size;
    uint32_t data_crc;
    char data[0];
}__attribute__((packed)) capture_format_t;


void write_to_file(int *format, char **fragments, char *fname, int fragsize);

void capture_file(char *ifname);

void crc32(const void *data, size_t n_bytes, uint32_t* crc);

static void usage()
{
    fprintf(stderr, "\nUsage:\n./rx_raw <ifname>\n");
    fprintf(stderr, "Example:\n./rx_raw eth0\n");
}


int main(int argc , char * argv[]){
    char ifname[MAX_IFNAMSIZ] = {0};
    int ret;
    //struct timespec sleep_time;
    char *arg_ifname;

    if (argc != 2) {
        usage();
        goto bail;
    }

    arg_ifname = argv[1];

    snprintf(ifname, MAX_IFNAMSIZ, "%s", arg_ifname);

    if (!net_device_up(ifname)) {
        fprintf(stderr, "%s is not up\n", ifname);
        goto bail;
    }


    capture_file(ifname);
    return 0;
    bail:
    return -1;
}

void capture_file(char *ifname){
    int sfd,ret;
    capture_format_t *hdr;
    char **fragments;
    char *buffer;
    int done = 0;
    int frag_count;
    int totalbytes = 0;
    int *sizes;
    uint32_t crc_chk;
    sfd = net_create_raw_socket(ifname, ETHER_TYPE, 0);
    if (sfd == -1) {
        fprintf(stderr, "failed to init socket\n");
        return;
    }

    buffer = malloc(RX_BUF_SIZE);
    hdr = (capture_format_t *) buffer;

    ret = recv(sfd, hdr, RX_BUF_SIZE, 0);

    if (ret <= 0) {
        fprintf(stderr, "ERROR: recv failed ret: %d, errno: %d\n", ret, errno);
        return;
    }
    fprintf(stderr, "%d bytes received\n", ret);
    fprintf(stderr,"fragment infos : fsize %d , name %s , surname %s , fragment size %d .\n",
            hdr->file_size, hdr->name,hdr->surname,hdr->fragment_size);

    frag_count = hdr->fragment_count;

    fragments = calloc(frag_count, sizeof(char*));

    sizes = calloc(frag_count, sizeof(int));

    fragments[hdr->fragment_index - 1] = hdr->data;
    sizes[hdr->fragment_index - 1] = hdr->fragment_size;
    totalbytes += hdr->fragment_size;
    int j = 1;
    while (!done) {
        buffer = calloc(RX_BUF_SIZE ,sizeof(char));
        hdr = (capture_format_t *) buffer;

        ret = recv(sfd, buffer, RX_BUF_SIZE, 0);
        fprintf(stderr, "%d bytes received\n", ret);
        if (ret <= 0) {
            fprintf(stderr, "ERROR: recv failed ret: %d, errno: %d\n", ret, errno);
            free(buffer);
            continue;
        }

        if(hdr->fragment_size > RX_BUF_SIZE){
            fprintf(stderr,"MAX BUFFER SIZE reached. ");
            fprintf(stderr,"Dropping... \n");
            free(buffer);
            continue;
        }
        if (ret != hdr->fragment_size + sizeof(capture_format_t)){
            fprintf(stderr,"Error recv ret value");
            free(buffer);
            continue;
        }
        if(hdr->fragment_index <= 0 || hdr->fragment_index > hdr->fragment_count){
            fprintf(stderr,"Error , reading fragment index : %d",hdr->fragment_index);
            continue;
        }
        crc_chk = 0;
        crc32(hdr->data,hdr->fragment_size,&crc_chk);
        if(crc_chk != hdr->data_crc){
            fprintf(stderr,"CRC ERROR. %d %d \n",crc_chk,hdr->data_crc);
            free(buffer);
            continue;
        }
        if (frag_count <= j)
            done=1;
        fprintf(stderr," --- %d",hdr->fragment_index);
        if(sizes[hdr->fragment_index - 1] != 0){
            fprintf(stderr,"Same data ! discarding... \n");
            // free(buffer); SEGFAULT
            continue;
        }

        fragments[hdr->fragment_index -1] = hdr->data;
        sizes[hdr->fragment_index -1] = hdr->fragment_size;
        totalbytes += hdr->fragment_size;

        fprintf(stderr,"New frag fragment infos : fsize %d , name %s ,surname %s : %d/%d , fragment index %d .\n",
                hdr->file_size, hdr->name,hdr->surname,j,hdr->fragment_count,hdr->fragment_index);
        ++j;
    }

    if(hdr->file_size != totalbytes){
        fprintf(stderr, "ERROR: file size error received: %d total bytes %d \n", hdr->file_size, totalbytes);
        return;
    }

    write_to_file(sizes, fragments, hdr->filename, frag_count);
    printf("Completed (%s) \n",hdr->filename);
}

uint32_t crc32_for_byte(uint32_t r)
{
    int j;
    for (j = 0; j < 8; ++j)
        r = (r & 1 ? 0 : (uint32_t)0xEDB88320L) ^ r >> 1;
    return r ^ (uint32_t)0xFF000000L;
}

void crc32(const void *data, size_t n_bytes, uint32_t* crc)
{
    size_t i;
    static uint32_t table[0x100];
    if (!*table)
        for (i = 0; i < 0x100; ++i)
            table[i] = crc32_for_byte(i);
    for (i = 0; i < n_bytes; ++i)
        *crc = table[(uint8_t)*crc ^ ((uint8_t*)data)[i]] ^ *crc >> 8;
}

void write_to_file(int *sizes, char **fragments, char *fname, int fragsize) {
    FILE* outp;
    outp = fopen(fname,"w");
    for (int i = 0; i < fragsize; ++i) {
        fwrite(fragments[i],sizes[i],1,outp);
        free(fragments[i]- sizeof(capture_format_t));
    }
    free(sizes);
    free(fragments);
    fclose(outp);
}