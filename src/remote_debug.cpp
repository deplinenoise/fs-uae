//
// UAE - The Un*x Amiga Emulator
//
// GDB Stub for UAE.
//
// (c) 1995 Bernd Schmidt
// (c) 2006 Toni Wilen
// (c) 2016 Daniel Collin (this file: GDB Implementation/remote debugger interface)
//
// This implementation is done from scratch and doesn't use any existing gdb-stub code. 
// The idea is to supply a fairly minimal implementation in order to reduce maintaince.
//
// This is what according to the GDB protocol dock over here https://sourceware.org/gdb/current/onlinedocs/gdb/Overview.html
// is required of a stub:
//
// "At a minimum, a stub is required to support the 'g' and 'G' commands for register access, and the 'm' and 'M' commands for memory access. 
// Stubs that only control single-threaded targets can implement run control with the 'c' (continue), and 's' (step) commands. 
// Stubs that support multi-threading targets should support the 'vCont' command.
//
// All other commands are optional."
//
// This stub implements a set of extensions that isn't really used by GDB but makes sense in terms of Amiga. 
// Some of these are copper debugging, blitter, dma, custom chipset stats, etc
//
// TODO: List and implement extensions
//

#include "remote_debug.h"
#ifdef REMOTE_DEBUGGER

#include <string.h>
#include <stdint.h>
#if defined(_MSC_VER)
#pragma warning(disable: 4496)
#include <winsock2.h>
#pragma warning(default: 4496)
#include <winsock2.h>
#include <Ws2tcpip.h>
#endif

#if !defined(_WIN32)
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif

#if defined(__linux__)
#include <sys/time.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "defines.h"
#include "debug.h"
#include "newcpu.h"
#include "custom.h"

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

#if !defined(_WIN32)
#define closesocket close
#endif

//
// Internal socket code
//

static bool step_cpu = false;
static uae_u8 s_lastSent[1024];
static int s_lastSize = 0;

extern "C" { int remote_debugging = 0; }

enum ConnectionType
{
    ConnectionType_Listener,
    ConnectionType_Connect
};

typedef struct rconn
{
    enum ConnectionType type;

    int server_socket;     // used when having a listener socket
    int socket;

} rconn;

void debug_log (const char* fmt, ...)
{
#ifdef DEBUG_LOG
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
#else
    (void)fmt;
#endif
}

static int socket_poll (int socket)
{
    struct timeval to = { 0, 0 };
    fd_set fds;

    FD_ZERO(&fds);

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#endif
    FD_SET(socket, &fds);
#ifdef _MSC_VER
#pragma warning(pop)
#endif

    return select (socket + 1, &fds, NULL, NULL, &to) > 0;
}

static int create_listner (rconn* conn, int port)
{
    struct sockaddr_in sin;
    int yes = 1;

    conn->server_socket = (int)socket (AF_INET, SOCK_STREAM, 0);

    if (conn->server_socket == INVALID_SOCKET)
        return 0;

    memset(&sin, 0, sizeof sin);

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons((unsigned short)port);

    if (setsockopt (conn->server_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(int)) == -1) {
        perror("setsockopt");
        return 0;
    }

    if (-1 == bind (conn->server_socket, (struct sockaddr*)&sin, sizeof(sin))) {
        perror("bind");
        return 0;
    }

    while (listen(conn->server_socket, SOMAXCONN) == -1)
        ;

    debug_log("created listener\n");

    return 1;
}

static struct rconn* rconn_create (enum ConnectionType type, int port)
{
    rconn* conn = 0;

#if defined(_WIN32)
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0)
        return 0;
#endif

    conn = xmalloc(struct rconn, 1);

    conn->type = type;
    conn->server_socket = INVALID_SOCKET;
    conn->socket = INVALID_SOCKET;

    if (type == ConnectionType_Listener) {
        if (!create_listner(conn, port)) {
            xfree(conn);
            return 0;
        }
    }

    return conn;
}

static void rconn_destroy (struct rconn* conn)
{
    if (conn->socket != INVALID_SOCKET)
        closesocket(conn->socket);

    if (conn->server_socket != INVALID_SOCKET)
        closesocket(conn->server_socket);

    xfree(conn);
}

static int rconn_connected (struct rconn* conn)
{
    return conn->socket != INVALID_SOCKET;
}

static int client_connect (rconn* conn, struct sockaddr_in* host)
{
    struct sockaddr_in hostTemp;
    unsigned int hostSize = sizeof(struct sockaddr_in);

    debug_log("Trying to accept\n");

    conn->socket = (int)accept (conn->server_socket, (struct sockaddr*)&hostTemp, (socklen_t*)&hostSize);

    if (INVALID_SOCKET == conn->socket) {
        perror("accept");
        debug_log("Unable to accept connection..\n");
        return 0;
    }

    if (NULL != host)
        *host = hostTemp;

    debug_log("Accept done\n");

    return 1;
}

static int rconn_is_connected (rconn* conn)
{
    if (conn == NULL)
        return 0;

    return conn->socket != INVALID_SOCKET;
}

static void rconn_update_listner (rconn* conn)
{
    struct timeval timeout;
    struct sockaddr_in client;
    fd_set fds;

    FD_ZERO(&fds);

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#endif
    FD_SET (conn->server_socket, &fds);
#ifdef _MSC_VER
#pragma warning(pop)
#endif

    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    if (rconn_is_connected (conn))
        return;

    // look for new clients

    if (select (conn->server_socket + 1, &fds, NULL, NULL, &timeout) > 0)
    {
        if (client_connect (conn, &client))
            debug_log ("Connected to %s\n", inet_ntoa(client.sin_addr));
    }
}

static int rconn_disconnect (rconn* conn)
{
    debug_log("Disconnected\n");

    if (conn->socket != INVALID_SOCKET)
        closesocket(conn->socket);

    conn->socket = INVALID_SOCKET;

    return 1;
}

static int rconn_recv (rconn* conn, char* buffer, int length, int flags)
{
    int ret;

    if (!rconn_connected(conn))
        return 0;

    ret = (int)recv(conn->socket, buffer, (size_t)length, flags);

    if (ret <= 0)
    {
        debug_log("recv %d %d\n", ret, length);
        rconn_disconnect(conn);
        return 0;
    }

    return ret;
}

static int rconn_send(rconn* conn, const void* buffer, int length, int flags)
{
    int ret;

    if (!rconn_connected(conn))
        return 0;

#if 0
	printf("About to send\n");

	char* c = (char*)buffer;

	for (int i = 0; i < length; ++i)
		printf("%c", c[i]); 

	printf("\n");
#endif

    if ((ret = (int)send(conn->socket, buffer, (size_t)length, flags)) != (int)length)
    {
        rconn_disconnect(conn);
        return 0;
    }

    // take a copy of what we sent last if we need to resend it

	memcpy (s_lastSent, buffer, length);
	s_lastSize = length;

    return ret;
}

static int rconn_poll_read(rconn* conn)
{
    if (!rconn_connected(conn))
        return 0;

    return !!socket_poll(conn->socket);
}

static rconn* s_conn = 0;

// 
// time_out allows to set the time UAE will wait at startup for a connection. 
// This is useful when wanting to debug things at early startup.
// If this is zero no time-out is set and if -1 no remote connection will be setup
//

static void remote_debug_init_ (int time_out)
{
	if (s_conn || time_out < 0) 
		return;

	if (!(s_conn = rconn_create (ConnectionType_Listener, 6860)))
		return;

	remote_debugging = 1;

	// if time_out > 0 we wait that number of seconds for a connection to be made. If
	// none has been done within the given time-frame we just continue
	
	for (int i = 0; i < time_out * 10; i++) {
		rconn_update_listner (s_conn);

		if (rconn_is_connected (s_conn))
			return;

		sleep_millis (100);	// sleep for 100 ms to not hammer on the socket while waiting
	}
}

static int hex(char ch)
{
	if ((ch >= 'a') && (ch <= 'f'))
		return ch - 'a' + 10;

	if ((ch >= '0') && (ch <= '9'))
		return ch - '0';

	if ((ch >= 'A') && (ch <= 'F'))
		return ch - 'A' + 10;

	return -1;
}

const int find_marker(const char* packet, const int offset, const char c, const int length)
{
	for (int i = 0; i < length; ++i) {
		if (packet[i] == c)
			return i;
	}

	return -1;
}

static const char s_hexchars [] = "0123456789abcdef";
static const char* s_ok = "$OK#9a";
static bool need_ack = true;

static int safe_addr (uaecptr addr, int size)
{
	addrbank* ab = &get_mem_bank (addr);

	if (!ab)
		return 0;

	if (ab->flags & ABFLAG_SAFE)
		return 1;

	if (!ab->check (addr, size))
		return 0;

	if (ab->flags & (ABFLAG_RAM | ABFLAG_ROM | ABFLAG_ROMIN | ABFLAG_SAFE))
		return 1;

	return 0;
}

static bool reply_ok()
{
	return rconn_send (s_conn, s_ok, 6, 0) == 6;
}

static uae_u8* write_reg_32 (unsigned char* dest, uae_u32 v)
{
	uae_u8 c0 = (v >> 24) & 0xff;
	uae_u8 c1 = (v >> 16) & 0xff;
	uae_u8 c2 = (v >> 8) & 0xff;
	uae_u8 c3 = (v >> 0) & 0xff;

	*dest++ = s_hexchars[c0 >> 4];
	*dest++ = s_hexchars[c0 & 0xf];
	*dest++ = s_hexchars[c1 >> 4];
	*dest++ = s_hexchars[c1 & 0xf];
	*dest++ = s_hexchars[c2 >> 4];
	*dest++ = s_hexchars[c2 & 0xf];
	*dest++ = s_hexchars[c3 >> 4];
	*dest++ = s_hexchars[c3 & 0xf];

	return dest;
}

static uae_u8* write_reg_double (uae_u8* dest, double v)
{
	union
	{
		double fp64;
		uae_u8 u8[8];
	} t;

	t.fp64 = v;

	for (int i = 0; i < 8; ++i)
	{
		uae_u8 c = t.u8[i];
		*dest++ = s_hexchars[c >> 4];
		*dest++ = s_hexchars[c & 0xf];
	}

    return dest;
}

//
// This code assumes that '$' has been added at the start and the length is subtrackted to not include it
//

static bool send_packet_in_place (unsigned char* t, int length)
{
	uae_u8 cs = 0;

	for (int i = 1; i < length; ++i)
		cs += t[i];

	t[length + 1] = '#';
	t[length + 2] = s_hexchars[cs >> 4]; 
	t[length + 3] = s_hexchars[cs & 0xf]; 

	return rconn_send(s_conn, t, length + 4, 0) == length + 4; 
}

static void send_packet_string (const char* string)
{
	uae_u8* s;
	uae_u8* t;
	uae_u8 cs = 0;
	int len = (int)strlen (string);
	s = t = xmalloc (uae_u8, len + 5);

	for (int i = 0; i < len; ++i)
		cs += string[i];

	*t++ = '$';
	memcpy (t, string, len);

	t[len + 0] = '#';
	t[len + 1] = s_hexchars[cs >> 4]; 
	t[len + 2] = s_hexchars[cs & 0xf]; 
	t[len + 3] = 0; 

	rconn_send(s_conn, s, len + 4, 0); 

	printf("sending packet %s\n", s);

	xfree(s);
}

static bool send_registers (void)
{
	uae_u8 registerBuffer[((18 * 4) + (8 * 8)) + (3 * 4) + 5]; // 16+2 regs + 8 (optional) FPU regs + 3 FPU control regs + space for tags
	uae_u8* t = registerBuffer; 
	uae_u8* buffer = registerBuffer; 

	*buffer++ = '$';

	for (int i = 0; i < 8; ++i)
		buffer = write_reg_32 (buffer, m68k_dreg (regs, i));

	for (int i = 0; i < 8; ++i)
		buffer = write_reg_32 (buffer, m68k_areg (regs, i));

	buffer = write_reg_32 (buffer, regs.sr);
	buffer = write_reg_32 (buffer, m68k_getpc ());

#ifdef FPUEMU
	if (currprefs.fpu_model) 
	{
		for (int i = 0; i < 8; ++i)
			buffer = write_reg_double (buffer, regs.fp[i].fp);

		buffer = write_reg_32 (buffer, regs.fpcr);
		buffer = write_reg_32 (buffer, regs.fpsr);
		buffer = write_reg_32 (buffer, regs.fpiar);
	}
#endif

	return send_packet_in_place(t, (int)((uintptr_t)buffer - (uintptr_t)t) - 1);
}

static bool send_memory (char* packet)
{
	uae_u8* t;
	uae_u8* mem;

	uaecptr address;
	int size;

	if (sscanf (packet, "%x,%x:", &address, &size) != 2)
	{
		printf("failed to parse memory packet: %s\n", packet);
		send_packet_string ("E01");
		return false;
	}

	t = mem = xmalloc(uae_u8, (size * 2) + 6);
	
	*t++ = '$';

	for (int i = 0; i < size; ++i)
	{
		uae_u8 v = '?';

		if (safe_addr (address, 1)) 
			v = get_byte (address);

		t[0] = s_hexchars[v >> 4];
		t[1] = s_hexchars[v & 0xf];
		
		address++; t += 2;
	}

	send_packet_in_place(mem, size * 2);

	xfree(mem);

	return true;
}

bool set_memory (char* packet, int packet_length)
{
	uae_u8* t;
	uae_u8* mem;

	uaecptr address;
	int size;
	int memory_start = 0;

	if (sscanf (packet, "%x,%x:", &address, &size) != 2) {
		printf("failed to parse set_memory packet: %s\n", packet);
		send_packet_string ("E01");
		return false;
	}

	for (int i = 0; i < packet_length; ++i) {
		const uae_u8 t = packet[i];

		if (t == ':' || t == '#') {
			memory_start = i + 1;
			break;
		}
	}

	if (memory_start == 0) {
		printf ("Unable to find end tag for packet %s\n", packet);
		send_packet_string ("E01");
		return false;
	}

	packet += memory_start;

	printf ("memory start %d - %s\n", memory_start, packet);
	
	for (int i = 0; i < size; ++i) 
	{
		if (!safe_addr (address, 1)) {
			send_packet_string ("E01");
			return false;
		}
		
		uae_u8 t = hex(packet[0]) << 4 | hex(packet[1]); 

		printf("setting memory %x-%x [%x] to %x\n", packet[0], packet[1], t, address);
		packet += 2;

		put_byte (address++, t); 
	}

	return reply_ok ();
}

static uae_u32 get_u32 (const uae_u8** data)
{
	const uae_u8* temp = *data;

	uae_u32 t[4];

	for (int i = 0; i < 4; ++i) {
		t[i] = hex(temp[0]) << 4 | hex(temp[1]);
		temp += 2;
	}

	*data = temp;

	return (t[0] << 24) | (t[1] << 16) | (t[2] << 8) | t[3];
}

static uae_u32 get_double (const uae_u8** data)
{
	const uae_u8* temp = *data;

	union {
		double d;
		uae_u8 u8[4];
	} t;

	for (int i = 0; i < 8; ++i) {
		t.u8[i] = hex(temp[0]) << 4 | hex(temp[1]);
		temp += 2;
	}

	*data = temp;

	return t.d; 
}

static bool set_registers (const uae_u8* data)
{
	// order of registers are assumed to be
	// d0-d7, a0-a7, sr, pc [optional fp0-fp7, control, sr, iar) 

	for (int i = 0; i < 8; ++i)
		m68k_dreg (regs, i) = get_u32(&data); 

	for (int i = 0; i < 8; ++i)
		m68k_areg (regs, i) = get_u32(&data); 

	regs.sr = get_u32 (&data);
	regs.pc = get_u32 (&data);

#ifdef FPUEMU
	if (currprefs.fpu_model) 
	{
		for (int i = 0; i < 8; ++i)
			regs.fp[i].fp = get_double (&data);

		regs.fpcr = get_u32 (&data);
		regs.fpsr = get_u32 (&data);
		regs.fpiar = get_u32 (&data);
	}
#endif

	reply_ok();

	return false;
}


static int map_68k_exception(int exception) {
	int sig = 0;

	switch (exception)
	{
		case 2: sig = 10; break; // bus error
		case 3: sig = 10; break; // address error
		case 4: sig = 4; break; // illegal instruction
		case 5: sig = 8; break; // zero divide
		case 6: sig = 8; break; // chk instruction
		case 7: sig = 8; break; // trapv instruction
		case 8: sig = 11; break; // privilege violation
		case 9: sig = 5; break; // trace trap
		case 10: sig = 4; break; // line 1010 emulator
		case 11: sig = 4; break; // line 1111 emulator
		case 13: sig = 10; break; // Coprocessor protocol violation.  Using a standard MMU or FPU this cannot be triggered by software.  Call it a SIGBUS.
		case 31: sig = 2; break; // interrupt
		case 33: sig = 5; break; // breakpoint
		case 34: sig = 5; break; // breakpoint
		case 40: sig = 8; break; // floating point err
		case 48: sig = 8; break; // floating point err
		case 49: sig = 8; break; // floating point err
		case 50: sig = 8; break; // zero divide
		case 51: sig = 8; break; // underflow
		case 52: sig = 8; break; // operand error
		case 53: sig = 8; break; // overflow
		case 54: sig = 8; break; // NAN
		default: sig = 7; // "software generated"
	}

	return sig; 
}


static bool send_exception (void) {

	unsigned char buffer[10];

	int sig = map_68k_exception (regs.exception);

	buffer[0] = '$';
	buffer[1] = 'S';
	buffer[2] = s_hexchars[(sig >> 4) & 0xf]; 
	buffer[3] = s_hexchars[(sig) & 0xf]; 

	return send_packet_in_place(buffer, 3);
}

static bool step()
{
	set_special (SPCFLAG_BRK);
	step_cpu = true;
	exception_debugging = 1;
	return true;
}

static void mem2hex(unsigned char* output, const unsigned char* input, int count)
{
	for (int i = 0; i < count; ++i)
	{
		unsigned char ch = *input++;
		*output++ = s_hexchars[ch >> 4];
		*output++ = s_hexchars[ch & 0xf];
	}

	*output = 0;
}

static bool handle_multi_letter_packet (char* packet, int length)
{
	int i = 0;

	// ‘v’ Packets starting with ‘v’ are identified by a multi-letter name, up to the first ‘;’ or ‘?’ (or the end of the packet). 
	
	for (i = 0; i < length; ++i)
	{
		const char c = packet[i];

		if (c == ';' || c == '?' || c == '#')
			break;
	}

	// fine to assume that i is valid here as we have already checked that # is present

	packet[i] = 0;

	send_packet_string ("");

	return false;
}

static bool handle_query_packet(char* packet, int length)
{
	int i = 0;

	// ‘v’ Packets starting with ‘v’ are identified by a multi-letter name, up to the first ‘;’ or ‘?’ (or the end of the packet). 
	
	for (i = 0; i < length; ++i)
	{
		const char c = packet[i];

		if (c == ':' || c == '?' || c == '#')
			break;
	}

	packet[i] = 0;

	printf("-------- query %s\n", packet);

	if (!strcmp ("QStartNoAckMode", packet)) {
		need_ack = false;
		return reply_ok ();
	}
	else if (!strcmp (packet, "qSupported"))
		send_packet_string ("QStartNoAckMode+");
	else
		send_packet_string ("");

	return true;
}

static bool handle_thread ()
{
	send_packet_string ("OK");

	return true;
}

static bool continue_exec (char* packet)
{
	// 'c [addr] Continue at addr, which is the address to resume. If addr is omitted, resume at current address.
	
	if (*packet != '#')
	{
		uae_u32 address;
	
		if (sscanf (packet, "%x#", &address) != 1)
		{
			printf("Unable to parse continnue packet %s\n", packet);
			return false;
		}

		m68k_setpci(address);
	}

	//send_packet_string ("S00");
	reply_ok ();
	deactivate_debugger ();
	step_cpu = true;

	return true;
}

static bool handle_packet(char* packet, int length)
{
	const char command = *packet;

	// ‘v’ Packets starting with ‘v’ are identified by a multi-letter name, up to the first ‘;’ or ‘?’ (or the end of the packet). 

	if (command == 'v')
		return handle_multi_letter_packet(packet, length);

	if (command == 'q' || command == 'Q')
		return handle_query_packet(packet, length);

	switch (command)
	{
		case 'g' : return send_registers ();
		case 's' : return step ();
		case 'H' : return handle_thread ();
		case 'G' : return set_registers ((const uae_u8*)packet + 1);
		case '?' : return send_exception ();
		case 'm' : return send_memory (packet + 1);
		case 'M' : return set_memory (packet + 1, length - 1);
		case 'c' : return continue_exec (packet + 1);

		default : send_packet_string ("");
	}

	return false;
}

static bool parse_packet(char* packet, int size)
{
	uae_u8 calc_checksum = 0;
	uae_u8 read_checksum = 0;
	int start, end;

	if (*packet == '-' && size == 1)
	{
		printf("*** Resending\n");
		rconn_send (s_conn, s_lastSent, s_lastSize, 0);
		return true;
	}

	// TODO: Do we need to handle data that strides several packtes?

	if ((start = find_marker(packet, 0, '$', size)) == -1)
		return false;

	if ((end = find_marker(packet, start, '#', size - start)) == -1)
		return false;

	// calc checksum

	for (int i = start + 1; i < end; ++i) 
		calc_checksum += packet[i];

	// Read read the checksum and make sure they match

	read_checksum = hex(packet[end + 1]) << 4;
	read_checksum += hex(packet[end + 2]);

	if (read_checksum != calc_checksum) {
		if (need_ack) {
			rconn_send (s_conn, "-", 1, 0);
		}

		printf("mismatching checksum (calc 0x%x read 0x%x)\n", calc_checksum, read_checksum);
		return false;
	}

	if (need_ack)
		rconn_send (s_conn, "+", 1, 0);

	// set end of string on the end marker

	return handle_packet(&packet[start + 1], size - 1);
}

// Main function that will be called when doing the actual debugging

static void remote_debug_ (void)
{
	// send exception

	send_exception();

	while (1)
	{
		if (rconn_poll_read(s_conn)) {
			char temp[1024];

			memset(temp, 0, sizeof(temp));

			int size = rconn_recv(s_conn, temp, sizeof(temp), 0);

			printf("got data %s (%d)\n", temp, size);

			if (size > 0)
				parse_packet(temp, size);
		}

		// if this has been set > 0 it means that we need to loop back to uae and step some code

		if (step_cpu)
			break;

		sleep_millis (10);	// don't hammer
	}

	step_cpu = false;

	printf("jumping back to uae for cpu step\n");
}

// This function needs to be called at regular interval to keep the socket connection alive

static void remote_debug_update_ (void)
{
	if (!s_conn)
		return;

	rconn_update_listner (s_conn);

	if (rconn_poll_read(s_conn))
		activate_debugger ();
}


//
// These are just wrappers to expose the code to C from C++
//

extern "C" 
{

void remote_debug_init (int time_out) { remote_debug_init_ (time_out); }
void remote_debug (void) { remote_debug_ (); }
void remote_debug_update (void) { remote_debug_update_ (); }

}

#endif


