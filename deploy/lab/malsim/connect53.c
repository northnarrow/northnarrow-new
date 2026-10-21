/* nn-ms: benign lab helper for deploy/lab/malsim/net-check.sh (lab PR 224,
 * case MS05B). One TCP connect to ADDR:PORT (IPv4, loopback in the suite),
 * at once, then a 2 s pause so the process is still there when the agent
 * names its image, then exit. It sends nothing. The suite runs a copy from
 * a staging directory (/var/tmp/nn-ms.*) to check that the port-53
 * exemption of NN-L-NET-008 / NN-L-CHAIN-002 holds only for a configured
 * resolver; R003 kills the copy at exec, the connect is observed first. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char marker[] = "nn-ms";

int main(int argc, char **argv)
{
    struct sockaddr_in a;
    int s;

    if (argc != 3)
        return 2;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)atoi(argv[2]));
    if (inet_pton(AF_INET, argv[1], &a.sin_addr) != 1)
        return 2;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return 3;
    (void)connect(s, (struct sockaddr *)&a, sizeof a);
    sleep(2);
    close(s);
    return marker[0] == 'n' ? 0 : 1;
}
