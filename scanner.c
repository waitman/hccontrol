#include <bluetooth.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <netgraph/ng_message.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "hccontrol.h"

#define	MAX_BT_CONN	1000

static int hci_inquiry(int s);
static void hci_inquiry_response(int s,int n, uint8_t **b);
static int find_hci_nodes (struct nodeinfo **);

void create_sockets(void);
static int hci_read_connection_list(int s);
static void usage(void);
void * rssi_runner(void *arg);
void * btconnect_runner(void *arg);


/* Globals */
int	 	verbose = 0; 
int	 	timeout;
int	 	numeric_bdaddr = 0;
int		last_btrec = 0;
const char *	node1 = "ubt0hci";
const char *	node2 = "ubt1hci";
const char *	node3 = "ubt2hci";

int		socket1 = 0;	/* inquiry sockets */
int		socket2 = 0;
int		socket3 = 0;
int		socket1a = 0;	/* remote connection sockets */
int		socket2a = 0;
int		socket3a = 0;
int		socket1b = 0;	/* rssi sockets */
int		socket2b = 0;
int		socket3b = 0;



struct btrec {
	bdaddr_t bdaddr;
	int channel;
	int rssi1; /* node 1 */
	int rssi2; /* node 2 */
	int rssi3; /* node 3 */
	int connected;
};



struct btrec btrecs[MAX_BT_CONN];

/* Create socket and bind it */
static int
socket_open(char const *node)
{
	struct sockaddr_hci			 addr;
	struct ng_btsocket_hci_raw_filter	 filter;
	int					 s, mib[4], num;
	size_t					 size;
	struct nodeinfo 			*nodes;

	num = find_hci_nodes(&nodes);
	if (num == 0)
		errx(7, "Could not find HCI nodes");

	if (node == NULL) {
		node = strdup(nodes[0].name);
		if (num > 1)
			fprintf(stdout, "Using HCI node: %s\n", node);
	}

	free(nodes);

	s = socket(PF_BLUETOOTH, SOCK_RAW, BLUETOOTH_PROTO_HCI);
	if (s < 0)
		err(1, "Could not create socket");

	memset(&addr, 0, sizeof(addr));
	addr.hci_len = sizeof(addr);
	addr.hci_family = AF_BLUETOOTH;
	strncpy(addr.hci_node, node, sizeof(addr.hci_node));
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		err(2, "Could not bind socket, node=%s", node);

	if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		err(3, "Could not connect socket, node=%s", node);

	memset(&filter, 0, sizeof(filter));
	bit_set(filter.event_mask, NG_HCI_EVENT_COMMAND_COMPL - 1);
	bit_set(filter.event_mask, NG_HCI_EVENT_COMMAND_STATUS - 1);
	bit_set(filter.event_mask, NG_HCI_EVENT_INQUIRY_COMPL - 1);
	bit_set(filter.event_mask, NG_HCI_EVENT_INQUIRY_RESULT - 1);
	bit_set(filter.event_mask, NG_HCI_EVENT_CON_COMPL - 1);
	bit_set(filter.event_mask, NG_HCI_EVENT_DISCON_COMPL - 1);
	bit_set(filter.event_mask, NG_HCI_EVENT_REMOTE_NAME_REQ_COMPL - 1);
	bit_set(filter.event_mask, NG_HCI_EVENT_READ_REMOTE_FEATURES_COMPL - 1);
	bit_set(filter.event_mask, NG_HCI_EVENT_READ_REMOTE_VER_INFO_COMPL - 1);
	bit_set(filter.event_mask, NG_HCI_EVENT_RETURN_LINK_KEYS - 1);
	bit_set(filter.event_mask, NG_HCI_EVENT_READ_CLOCK_OFFSET_COMPL - 1);
	bit_set(filter.event_mask, NG_HCI_EVENT_CON_PKT_TYPE_CHANGED - 1);
	bit_set(filter.event_mask, NG_HCI_EVENT_ROLE_CHANGE - 1);

	if (setsockopt(s, SOL_HCI_RAW, SO_HCI_RAW_FILTER, 
			(void * const) &filter, sizeof(filter)) < 0)
		err(4, "Could not setsockopt()");

	size = (sizeof(mib)/sizeof(mib[0]));
	if (sysctlnametomib("net.bluetooth.hci.command_timeout",mib,&size) < 0)
		err(5, "Could not sysctlnametomib()");

	if (sysctl(mib, sizeof(mib)/sizeof(mib[0]),
			(void *) &timeout, &size, NULL, 0) < 0)
		err(6, "Could not sysctl()");

	timeout ++;

	return (s);
} /* socket_open */


/* Create sockets */
void
create_sockets(void)
{
	int					 num;
	struct nodeinfo 			*nodes;

	num = find_hci_nodes(&nodes);
	
	if (num == 0)
		errx(7, "Could not find HCI nodes");


	/* socket 1 */
	node1 = strdup(nodes[0].name);
	socket1 = socket_open(node1);
	if (socket1>0)
	{
		socket1a = socket_open(node1);
		socket1b = socket_open(node1);
	}

	/* socket 2 */
	if (num>1)
	{
		node2 = strdup(nodes[1].name);
		socket2 = socket_open(node2);
		if (socket2>0)
		{
			socket2a = socket_open(node2);
			socket2b = socket_open(node2);
		}
	}

	if (num>2)
	{
		node3 = strdup(nodes[2].name);
		socket3 = socket_open(node3);
		if (socket3>0)
		{
			socket3a = socket_open(node3);
			socket3b = socket_open(node3);
		}
	}
	
	free(nodes);
	return;
}



/* Send Inquiry command to the unit */
static int
hci_inquiry(int s)
{
	int			 n0,timo;
	char			 b[512];
	ng_hci_inquiry_cp	 cp;
	ng_hci_event_pkt_t	*e = (ng_hci_event_pkt_t *) b;
	int	socketa;

	if (s == socket1)
	{
		socketa=socket1a;
	}
	if (s == socket2)
	{
		socketa=socket2a;
	}
	if (s == socket3)
	{
		socketa=socket3a;
	}
		
	/* set defaults */
	cp.lap[2] = 0x9e;
	cp.lap[1] = 0x8b;
	cp.lap[0] = 0x33;
	cp.inquiry_length = 5;
	cp.num_responses = 8;


	/* send request and expect status back */
	n0 = sizeof(b);
	if (hci_request(s, NG_HCI_OPCODE(NG_HCI_OGF_LINK_CONTROL,
			NG_HCI_OCF_INQUIRY), (char const *) &cp, sizeof(cp),
			b, &n0) == ERROR)
		return (ERROR);

	if (*b != 0x00)
		return (FAILED);

	timo = timeout;
	timeout = cp.inquiry_length * 3.28 + 1;

wait_for_more:
	/* wait for inquiry events */
	n0 = sizeof(b);
	if (hci_recv(s, b, &n0) == ERROR) {
		timeout = timo;
		return (ERROR);
	}

	if (n0 < sizeof(*e)) {
		timeout = timo;
		errno = EIO;
		return (ERROR);
	}

	switch (e->event) {
	case NG_HCI_EVENT_INQUIRY_RESULT: {
		ng_hci_inquiry_result_ep	*ir = 
				(ng_hci_inquiry_result_ep *)(e + 1);
		uint8_t				*r = (uint8_t *)(ir + 1);

		/*fprintf(stdout, "Inquiry result, num_responses=%d\n",
			ir->num_responses);*/

		for (n0 = 0; n0 < ir->num_responses; n0++)
		{
			hci_inquiry_response(socketa, n0, &r);
		}

		goto wait_for_more;
		}

	case NG_HCI_EVENT_INQUIRY_COMPL:
		/*fprintf(stdout, "Inquiry complete. Status: %s [%#02x]\n",
			hci_status2str(*(b + sizeof(*e))), *(b + sizeof(*e)));*/
		break;

	default:
		goto wait_for_more;
	}

	timeout = timo;

	return (OK);
} /* hci_inquiry */

/* Print Inquiry_Result event */
static void
hci_inquiry_response(int s, int n, uint8_t **b)
{

	int			 n0;
	char			 bd[512];
	char * node = "ubt0hci";
	
	ng_hci_create_con_cp	 cp;
	ng_hci_event_pkt_t	*e = (ng_hci_event_pkt_t *) bd; 

	/* Set defaults */
	memset(&cp, 0, sizeof(cp));
	cp.pkt_type = htole16(	NG_HCI_PKT_DM1 | NG_HCI_PKT_DH1 |
				NG_HCI_PKT_DM3 | NG_HCI_PKT_DH3 |
				NG_HCI_PKT_DM5);
	cp.page_scan_rep_mode = NG_HCI_SCAN_REP_MODE0;
	cp.page_scan_mode = NG_HCI_MANDATORY_PAGE_SCAN_MODE;
	cp.clock_offset = 0;
	cp.accept_role_switch = 1;


	ng_hci_inquiry_response	*ir = (ng_hci_inquiry_response *)(*b);
	

	*b += sizeof(*ir);
	
	/* check to see if we already know about this connection */


	int found = 0;
	for (int j=0; j<last_btrec; j++)
	{
		if (memcmp(&btrecs[j].bdaddr,&ir->bdaddr,sizeof(ir->bdaddr)) == 0) found = 1;
	}
	if (found) goto the_end;
	
	if (s == socket1a)
	{
		node = strdup(node1);
	}
	if (s == socket2a)
	{
		node = strdup(node2);
	}
	if (s == socket3a)
	{
		node = strdup(node3);
	}
	
	fprintf(stdout, "\t%s\tBD_ADDR: %s\n", node, hci_bdaddr2str(&ir->bdaddr));
	
	memcpy(&btrecs[last_btrec].bdaddr, &ir->bdaddr, sizeof(btrecs[last_btrec].bdaddr));
	++last_btrec;
		
	memcpy(&cp.bdaddr, &ir->bdaddr, sizeof(cp.bdaddr));
	
	/* send request and expect status response */
	n0 = sizeof(bd);
	
	/* open connection on all available sockets */
	
	if (socket1a>0)
	{
		if (hci_request(socket1a, NG_HCI_OPCODE(NG_HCI_OGF_LINK_CONTROL,
			NG_HCI_OCF_CREATE_CON),
			(char const *) &cp, sizeof(cp), bd, &n0) == ERROR)
		goto the_second_end;
	}
	if (socket2a>0)
	{
		if (hci_request(socket2a, NG_HCI_OPCODE(NG_HCI_OGF_LINK_CONTROL,
			NG_HCI_OCF_CREATE_CON),
			(char const *) &cp, sizeof(cp), bd, &n0) == ERROR)
		goto the_second_end;
	}	
	if (socket3a>0)
	{
		if (hci_request(socket3a, NG_HCI_OPCODE(NG_HCI_OGF_LINK_CONTROL,
			NG_HCI_OCF_CREATE_CON),
			(char const *) &cp, sizeof(cp), bd, &n0) == ERROR)
		goto the_second_end;
	}
	
	if (*bd != 0x00)
		goto the_end;

	n0 = sizeof(bd);
	if (hci_recv(s, bd, &n0) == ERROR)
		goto the_end;
	if (n0 < sizeof(*e)) {
		errno = EIO;
		goto the_end;
	}
the_end:
return;
the_second_end:
fprintf(stdout,"Error Connnecting");
return;
	
} /* hci_inquiry_response */


/* Find all HCI nodes */
static int
find_hci_nodes(struct nodeinfo** nodes)
{
	char * node = "ubt0hci";
	struct ng_btsocket_hci_raw_node_list_names	r;
	struct sockaddr_hci				addr;
	int						s;

	r.num_names = MAX_NODE_NUM;
	r.names = (struct nodeinfo*)calloc(MAX_NODE_NUM, sizeof(struct nodeinfo));
	if (r.names == NULL)
		err(8, "Could not allocate memory");

	s = socket(PF_BLUETOOTH, SOCK_RAW, BLUETOOTH_PROTO_HCI);
	if (s < 0)
		err(9, "Could not create socket");

	memset(&addr, 0, sizeof(addr));
	addr.hci_len = sizeof(addr);
	addr.hci_family = AF_BLUETOOTH;
	strncpy(addr.hci_node, node, sizeof(addr.hci_node));
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		err(10, "Could not bind socket");

	if (ioctl(s, SIOC_HCI_RAW_NODE_LIST_NAMES, &r, sizeof(r)) < 0)
		err(11, "Could not get list of HCI nodes");

	close(s);

	*nodes = r.names;

	return (r.num_names);
} /* find_hci_nodes */


static int
hci_read_connection_list(int s)
{
        struct ng_btsocket_hci_raw_con_list     r;
        int                                     n, error = OK;
	
        ng_hci_read_rssi_cp			cp;
        ng_hci_read_rssi_rp			rp;
        int					nr;
	char * node = "ubt1hci";
	int					socketb;
	

	if (s == socket1)
	{
		socketb = socket1b;
		node = strdup(node1);
	}
	if (s == socket2)
	{
		socketb = socket2b;
		node = strdup(node2);
	}
	if (s == socket3)
	{
		socketb = socket3b;
		node = strdup(node3);
	}


        memset(&r, 0, sizeof(r));
        r.num_connections = NG_HCI_MAX_CON_NUM;
        r.connections = calloc(NG_HCI_MAX_CON_NUM, sizeof(ng_hci_node_con_ep));
        if (r.connections == NULL) {
                errno = ENOMEM;
                return (ERROR);
        }

        if (ioctl(socketb, SIOC_HCI_RAW_NODE_GET_CON_LIST, &r, sizeof(r)) < 0) {
                error = ERROR;
                goto out;
        }

        /* reset connection table */
	for (int j=0; j<last_btrec; j++)
	{
		btrecs[j].connected = 0;
	}

        for (n = 0; n < r.num_connections; n++) {

		cp.con_handle = r.connections[n].con_handle;

	        /* send command */
        	nr = sizeof(rp);
		if (hci_request(socketb, NG_HCI_OPCODE(NG_HCI_OGF_STATUS,
                        NG_HCI_OCF_READ_RSSI),
                        (char const *) &cp, sizeof(cp),
                        (char *) &rp, &nr) == ERROR)
                return (ERROR);

        if (rp.status != 0x00) {
                fprintf(stdout, "Status: %s [%#02x]\n",
                        hci_status2str(rp.status), rp.status);
                return (FAILED);
        }
        int check_rssi = 0;
	int this_j = -1;
        for (int j=0; j<last_btrec; j++)
	{
		if (memcmp(&btrecs[j].bdaddr,&r.connections[n].bdaddr,sizeof(btrecs[j].bdaddr)) == 0)
		{
			btrecs[j].connected =  1;
			if (s == socket1)
			{
				check_rssi = btrecs[j].rssi1;
			}
			if (s == socket2)
			{
				check_rssi = btrecs[j].rssi2;
			}
			if (s == socket3)
			{
				check_rssi = btrecs[j].rssi3;
			}
			this_j = j;
		}
	}
	if (this_j>0)  /* wait until other thread catches up */
	{
		int measure_rssi = (int) rp.rssi;
	
		if (measure_rssi != check_rssi)
		{
			fprintf(stdout, "\t%-17.17s\t%6d\t%s\t%d dB\n", hci_bdaddr2str(&r.connections[n].bdaddr),
				r.connections[n].con_handle,node,measure_rssi);
			if (s == socket1)
			{
				btrecs[this_j].rssi1 = measure_rssi;
			}
			if (s == socket2)
			{
				btrecs[this_j].rssi2 = measure_rssi;
			}
			if (s == socket3)
			{
				btrecs[this_j].rssi3 = measure_rssi; break;
			}
		}
	}

        }
out:
        free(r.connections);

        return (error);
}


/* Main */
int
main(int argc, char *argv[])
{
	/* one thread scans for new BT ADDR and connects, the other thread reads RSSI */
	pthread_t		*thread;
	thread = (pthread_t *)malloc(sizeof(*thread)*2);

	
	int	 n;
	int	do_rssi = 0;

	/* Process command line arguments */
	while ((n = getopt(argc, argv, "rh")) != -1) {
		switch (n) {

		case 'r':
			do_rssi = 1;
			break;

		case 'h':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	
	pthread_create(&thread[0],NULL,btconnect_runner,NULL);
	if (do_rssi)
	{
		pthread_create(&thread[1],NULL,rssi_runner,NULL);
	}
	
	pthread_join(thread[0],NULL);
	if (do_rssi)
	{
		pthread_join(thread[1],NULL);
	}

	return (0);
} /* main */


void *
btconnect_runner(void *arg)
{
	
	
	create_sockets(); 

	while (1==1)		/* forever */
	{
	
		if (socket1>0)
		{
			hci_inquiry(socket1);
		}
		if (socket2>0)
		{
			hci_inquiry(socket2);
		}
		if (socket3>0)
		{
			hci_inquiry(socket3);
		}
	}
	return (NULL);
}

void *
rssi_runner(void *arg)
{
	while (1==1)		/* forever */
	{
		if (socket1>0)
		{
			hci_read_connection_list(socket1);
		}
		if (socket2>0)
		{
			hci_read_connection_list(socket2);
		}
		if (socket3>0)
		{
			hci_read_connection_list(socket3);
		}
		usleep(1500000);
	}
	return (NULL);
}

/* Usage */
static void
usage(void)
{
	fprintf(stdout, "Usage: hcscanner [-r] (do_rssi)\n");
	exit(255);
} /* usage */

