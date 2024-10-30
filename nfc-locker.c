#include <nfc/nfc.h>
#include <nfc/nfc-types.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>

#define MAX_UUID 100
#define MAX_UUID_LEN 7

unsigned char uid_list[MAX_UUID][MAX_UUID_LEN + 1];
unsigned int locker_id[MAX_UUID];
unsigned int uid_cnt = 0;

uint8_t hexvalue(char hexchar) {
    if (hexchar >= '0' && hexchar <= '9')
        return hexchar - '0';
    else if (hexchar >= 'A' && hexchar <= 'F')
        return hexchar - 'A' + 10;
    else if (hexchar >= 'a' && hexchar <= 'f')
        return hexchar - 'a' + 10;
    else
        return 0;
}

void handle_sighup(int sig) {
    FILE *uidfile;

    uidfile = fopen("uid.txt", "r");

    if (uidfile != NULL) {
        uid_cnt = 0;

        while (!feof(uidfile) && uid_cnt < 100) {
            char uidline[256];
            char uidstr[128];
            int lockerid;
            uint8_t uid_bytes[10];
            int uidstr_len;

            if (!fgets(uidline, sizeof(uidline), uidfile)) break;
            sscanf(uidline, "%s %d", uidstr, &lockerid);

            uidstr_len = strlen(uidstr);

            if (uidstr_len % 2 == 0) {
                // even length of uid
                uid_bytes[0] = uidstr_len / 2;
                for (int cnt = 0; cnt < uidstr_len; cnt+= 2) {
                    uid_bytes[1 + cnt / 2] = hexvalue(uidstr[cnt])*16+hexvalue(uidstr[cnt+1]);
                }
            } else {
                // odd - assume 0 in front
                uid_bytes[0] = uidstr_len / 2 + 1;
                uid_bytes[1] = hexvalue(uidstr[0]);
                for (int cnt = 1; cnt < uidstr_len; cnt+= 2) {
                    uid_bytes[2 + cnt / 2] = hexvalue(uidstr[cnt])*16+hexvalue(uidstr[cnt+1]);
                }
            }
	    memcpy(uid_list[uid_cnt], uid_bytes, uid_bytes[0] + 1);
            locker_id[uid_cnt] = lockerid;
            uid_cnt++;
        }
        fclose(uidfile);
    }

    printf("%d entries read from uid.txt\n", uid_cnt);
}

int main(void) {
    nfc_device *pnd;
    nfc_context *context;
    nfc_target nt;
    uint8_t uid[10];
    size_t uid_len;
    int sockfd;
    struct sockaddr_in server_addr;


// hard code it for now

    uint8_t uid_list0[5] = { 0x04, 0x53, 0x16, 0x0b, 0xca };
    uint8_t uid_list1[5] = { 0x04, 0x8d, 0x5a, 0x93, 0xb6 };

/*
    uid_cnt = 2;
    memcpy(uid_list[0], uid_list0, 5);
    locker_id[0] = 13;

    memcpy(uid_list[1], uid_list1, 5);
    locker_id[1] = 13;
 */

    handle_sighup(0);

    signal(SIGHUP, handle_sighup);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(30001);
    server_addr.sin_addr.s_addr = inet_addr("192.168.1.100");

    uint8_t prev_uid[10];
    size_t  prev_uid_len = -1;

    const nfc_modulation nmMifare = {
	.nmt = NMT_ISO14443A,
	.nbr = NBR_106,
    };

    // Initialize libnfc
    nfc_init(&context);
    if (context == NULL) {
        printf("Unable to init libnfc\n");
        return 1;
    }

    // Open NFC device
    pnd = nfc_open(context, NULL);
    if (pnd == NULL) {
        printf("Unable to open NFC device\n");
        nfc_exit(context);
        return 1;
    }

    // Initiate NFC device
    if (nfc_initiator_init(pnd) < 0) {
        nfc_perror(pnd, "nfc_initiator_init");
        nfc_close(pnd);
        nfc_exit(context);
        return 1;
    }

    printf("Looking for NFC card\n");
    // Poll for a target

    while (1) {

    if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) > 0) {
        uid_len = nt.nti.nai.szUidLen;
        memcpy(uid, nt.nti.nai.abtUid, uid_len);

	if ((uid_len == prev_uid_len) && (memcmp(uid, prev_uid, uid_len) == 0)) {
	    // same card, quietly ignore
        } else {
            int found = 0;

	    prev_uid_len = uid_len;
	    memcpy(prev_uid, uid, uid_len);

            printf("Card detected. UID: [%d] ", (int) uid_len);

            for (size_t i = 0; i < uid_len; i++) {
                printf("%02x", uid[i]);
            }

	    printf("\n");

            for (int cnt = 0; cnt < uid_cnt; cnt++) {
                if ((uid_len == uid_list[cnt][0]) &&
                    (memcmp(uid, &uid_list[cnt][1], uid_len) == 0)) {
                    printf("UID matched to entry %d, opening locker %d\n", cnt, locker_id[cnt]);
                    found = 1;
                    if (sockfd != -1) {
                        uint8_t message[2];
                        message[0] = 0x4;
                        message[1] = locker_id[cnt];
                        sendto(sockfd, message, sizeof(message), 0, (const struct sockaddr *) &server_addr, sizeof(server_addr));
                    }
                    usleep(250000);
		    // allow UID to match more than one entry to open multiple lockers
                }
            }

            if (!found) printf("UID not found in list\n");
            sleep(1);
        }
    } else {
        if (prev_uid_len != -1) {
	    prev_uid_len = -1;
            // printf("No NFC tag found\n");
            // set nfc led to red
        }
    }
    }

    // Close NFC device
    nfc_close(pnd);
    nfc_exit(context);
    return 0;
}
