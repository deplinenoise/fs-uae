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
//-----------------
//
// QDmaLine
//
// GDB Extension for Amiga that shows DMA timings on one raster-line
//
// u16 line,xsize,
// x size * u16 event, u16 type
//
// QDmaFrame
//
// Send a full-frame worth of timing data

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

#include "sysconfig.h"
#include "sysdeps.h"
#include "options.h"
#include "memory.h"
#include "custom.h"
#include "newcpu.h"
#include "traps.h"
#include "autoconf.h"
#include "execlib.h"
#include "uae/debuginfo.h"
#include "uae/segtracker.h"
#include "uae.h"

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

#if !defined(_WIN32)
#define closesocket close
#endif


extern void debugger_boot();

extern int segtracker_enabled;
extern int debug_dma;
static char s_exe_to_run[4096];

typedef struct dma_info {
	uae_u32 event;
	uae_u32 type;
} dma_info;

typedef struct segment_info {
	uae_u32 address;
	uae_u32 size;
} segment_info;

static struct dma_rec* dma_record[2];
static struct dma_info* dma_info_rec[2];
static int dma_record_toggle;
static int live_mode = 0;
static int debug_dma_frame = 0;
static int dma_max_sizes[2][2];
static segment_info s_segment_info[512];
static int s_segment_count = 0;

#define MAX_BREAKPOINT_COUNT 512

enum DebuggerState
{
	Running,
	Tracing,
	// Used to step the CPU until we endup in the program we are debugging
	TraceToProgram,
};

static DebuggerState s_state = Running;

//
// Internal socket code
//

static bool step_cpu = false;
static bool did_step_cpu = false;
static uae_u8 s_lastSent[1024];
static int s_lastSize = 0;
static bool need_ack = true;
static unsigned int s_socket_update_count = 0;

extern "C" {
	int fs_emu_is_quitting();
	int remote_debugging = 0;
}

#define DEBUG_LOG

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
	if (!conn)
		return;

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

    // If we got an connection we need to switch to tracing mode directly as this is required by gdb

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

	// reset the ack mode if client disconnected
	need_ack = true;

    if (conn->socket != INVALID_SOCKET)
        closesocket(conn->socket);

    debug_log("set invalid socket\n");

    conn->socket = INVALID_SOCKET;

    return 1;
}

static int rconn_recv (rconn* conn, char* buffer, int length, int flags)
{
    int ret;

    if (!rconn_connected(conn))
        return 0;

    ret = (int)recv(conn->socket, buffer, (size_t)length, flags);

    printf("recv %d\n", ret);

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
    	printf("disconnected because length doesn't match (expected %d but got %d)\n", length, ret);
        rconn_disconnect(conn);
        return 0;
    }

    // take a copy of what we sent last if we need to resend it

	//memcpy (s_lastSent, buffer, length);
	s_lastSize = 0;

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

	printf("creating connection...\n");

	if (!(s_conn = rconn_create (ConnectionType_Listener, 6860)))
		return;

	printf("remote debugger active\n");

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

struct Breakpoint {
	uaecptr address;
	uaecptr seg_address;
	uaecptr seg_id;
	bool enabled;
	bool needs_resolve;
	bool temp_break;
};

// used when skipping an instruction 
static uaecptr s_skip_to_pc = 0xffffffff;

static Breakpoint s_breakpoints[MAX_BREAKPOINT_COUNT];
static int s_breakpoint_count = 0;

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
	printf("[<----] %s\n", s_ok);
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

static uae_u8* write_u16 (unsigned char* dest, uae_u16 v)
{
	uae_u8 c0 = (v >> 8) & 0xff;
	uae_u8 c1 = (v >> 0) & 0xff;

	dest[0] = s_hexchars[c0 >> 4];
	dest[1] = s_hexchars[c0 & 0xf];
	dest[2] = s_hexchars[c1 >> 4];
	dest[3] = s_hexchars[c1 & 0xf];

	return dest + 4;
}

static uae_u8* write_u8 (unsigned char* dest, uae_u8 v)
{
	dest[0] = s_hexchars[v >> 4];
	dest[1] = s_hexchars[v & 0xf];

	return dest + 2;
}

static uae_u8* write_string (unsigned char* dest, const char* name)
{
	int len = strlen(name);
	memcpy(dest, name, len);
	return dest + len;
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

	// + 1 as we calculate the cs one byte into the stream
	for (int i = 1; i < length+1; ++i) {
		uae_u8 temp = t[i];
		cs += t[i];
	}

	t[length + 1] = '#';
	t[length + 2] = s_hexchars[cs >> 4];
	t[length + 3] = s_hexchars[cs & 0xf];
	t[length + 4] = 0;

	//printf("[<----] <inplace>\n");
	//printf("[<----] %s\n", t);

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

	printf("[<----] %s\n", s);

	xfree(s);
}

static bool send_registers (void)
{
	uae_u8 registerBuffer[((18 * 4) + (8 * 8)) + (3 * 4) + 5 + 1] = { 0 }; // 16+2 regs + 8 (optional) FPU regs + 3 FPU control regs + space for tags
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
	/*
	if (currprefs.fpu_model)
	{
		for (int i = 0; i < 8; ++i)
			buffer = write_reg_double (buffer, regs.fp[i].fp);

		buffer = write_reg_32 (buffer, regs.fpcr);
		buffer = write_reg_32 (buffer, regs.fpsr);
		buffer = write_reg_32 (buffer, regs.fpiar);
	}
	*/
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

	t = mem = xmalloc(uae_u8, (size * 2) + 7);

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
	/*
	if (currprefs.fpu_model)
	{
		for (int i = 0; i < 8; ++i)
			regs.fp[i].fp = get_double (&data);

		regs.fpcr = get_u32 (&data);
		regs.fpsr = get_u32 (&data);
		regs.fpiar = get_u32 (&data);
	}
	*/
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

	unsigned char buffer[16] = { 0 };

	printf("send exception\n");

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
	did_step_cpu = true;

	if (s_segment_count > 0)
		s_state = TraceToProgram;
	else
		s_state = Tracing;

	exception_debugging = 1;
	return true;
}

static bool step_next_instruction () {
	uaecptr nextpc = 0;
	uaecptr pc = m68k_getpc ();
	m68k_disasm (pc, &nextpc, 1);

	step_cpu = true;
	did_step_cpu = true;
	exception_debugging = 1;

	printf("current pc 0x%08x - next pc 0x%08x\n", pc, nextpc);

	s_skip_to_pc = nextpc;
	s_state = Running;

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

static bool handle_vrun (char* packet)
{
	// extract the args for vRun
	char* pch = strtok (packet, ";");

    printf("%s:%d\n", __FILE__, __LINE__);

	if (pch) {
		strcpy(s_exe_to_run, pch);
		pch = strtok (0, pch);
		printf("exe to run %s\n", s_exe_to_run);
	}

	printf("%s:%d\n", __FILE__, __LINE__);

	if (s_segment_count > 0) {
	    printf("%s:%d\n", __FILE__, __LINE__);
	    printf("Is a program already running? Skip executing\n");
	    return true;
	}

    printf("%s:%d\n", __FILE__, __LINE__);

	printf("running debugger_boot\n");

	debugger_boot ();

	// TODO: Extract args

	return true;
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

	if (!strcmp(packet, "vRun")) {
		return handle_vrun (packet + 5);
	} else {

		send_packet_string ("");
	}

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

	printf("[query] %s\n", packet);
	printf("handle_query_packet %d\n", __LINE__);

	if (!strcmp ("QStartNoAckMode", packet)) {
		printf("handle_query_packet %d\n", __LINE__);
		need_ack = false;
		return reply_ok ();
	}
	else if (!strcmp (packet, "qSupported")) {
		printf("handle_query_packet %d\n", __LINE__);
		send_packet_string ("QStartNoAckMode+");
	} else if (!strcmp (packet, "QDmaTimeEnable")) {
		printf("Enable dma debugging\n");
		bool ret = reply_ok ();
		debug_dma_frame = 1;
		debug_dma = 2;
		return ret;
	} else {
		printf("handle_query_packet %d\n", __LINE__);
		send_packet_string ("");
	}

	printf("handle_query_packet %d\n", __LINE__);

	return true;
}

static bool handle_thread ()
{
	send_packet_string ("OK");

	return true;
}

static void deactive_debugger () {
	set_special (SPCFLAG_BRK);
	s_state = Running;
	exception_debugging = 0;
	debugger_active = 0;
	step_cpu = true;
}

static bool kill_program () {
	deactive_debugger ();
	uae_reset (0, 0);
    s_segment_count = 0;

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

	printf("start running...\n");

	deactive_debugger ();

	reply_ok ();

	return true;
}

static int has_breakpoint_address(uaecptr address)
{
	for (int i = 0; i < s_breakpoint_count; ++i)
	{
		if (s_breakpoints[i].address == address)
			return i;
	}

	return -1;
}

static void resolve_breakpoint_seg_offset (Breakpoint* breakpoint)
{
    uaecptr seg_id = breakpoint->seg_id;
    uaecptr seg_address = breakpoint->seg_address;

    if (seg_id >= s_segment_count)
    {
        printf("Segment id >= segment_count (%d - %d)\n", seg_id, s_segment_count);
        breakpoint->needs_resolve = true;
        return;
    }

    breakpoint->address = s_segment_info[seg_id].address + seg_address;
    breakpoint->needs_resolve = false;

    printf("resolved breakpoint (%x - %x) -> 0x%08x\n", seg_address, seg_id, breakpoint->address);
}

static bool set_offset_seg_breakpoint (uaecptr address, uae_u32 segment_id, int add)
{
    // Remove breakpoint

    if (!add)
    {
        for (int i = 0; i < s_breakpoint_count; ++i)
        {
            if (s_breakpoints[i].seg_address == address && s_breakpoints[i].seg_id == segment_id) {
                s_breakpoints[i] = s_breakpoints[s_breakpoint_count - 1];
                s_breakpoint_count--;
                return reply_ok ();
            }
        }
    }

	s_breakpoints[s_breakpoint_count].seg_address = address;
	s_breakpoints[s_breakpoint_count].seg_id = segment_id;

    resolve_breakpoint_seg_offset (&s_breakpoints[s_breakpoint_count]);

	s_breakpoint_count++;

    return reply_ok ();
}

static bool set_breakpoint_address (char* packet, int add)
{
	uaecptr address;
	uaecptr segment;

	printf("parsing breakpoint\n");

	// if we have two args it means that the data is of type offset,segment and we need to resolve that.
	// if we are in running state we try to resolve it directly otherwise we just add it to the list
	// and resolve it after we loaded the executable

	int scan_res = sscanf (packet, "%x,%d", &address, &segment);

	if (scan_res == 2)
	{
	    printf("offset 0x%x seg_id %d\n", address, segment);
        return set_offset_seg_breakpoint (address, segment, add);
	}

	if (scan_res != 1)
	{
		printf("failed to parse memory packet: %s\n", packet);
		send_packet_string ("");
		return false;
	}

	printf("parsed 0x%x\n", address);

	printf("%s:%d\n", __FILE__, __LINE__);

	int bp_offset = has_breakpoint_address(address);

	printf("%s:%d\n", __FILE__, __LINE__);

	// Check if we already have a breakpoint at the address, if we do skip it

	if (!add)
	{
		printf("%s:%d\n", __FILE__, __LINE__);
		if (bp_offset != -1)
		{
			printf("%s:%d\n", __FILE__, __LINE__);
			printf("Removed breakpoint at 0x%8x\n", address);
			s_breakpoints[bp_offset] = s_breakpoints[s_breakpoint_count - 1];
			s_breakpoint_count--;
		}

		printf("%s:%d\n", __FILE__, __LINE__);
		return reply_ok ();
	}

	printf("%s:%d\n", __FILE__, __LINE__);

	if (s_breakpoint_count + 1 >= MAX_BREAKPOINT_COUNT)
	{
		printf("Max number of breakpoints (%d) has been reached. Removed some to add new ones", MAX_BREAKPOINT_COUNT);
		send_packet_string ("");
		return false;
	}

	printf("%s:%d\n", __FILE__, __LINE__);

	printf("Added breakpoint at 0x%08x\n", address);

	s_breakpoints[s_breakpoint_count].address = address;
	s_breakpoint_count++;

	return reply_ok ();
}

static bool set_breakpoint (char* packet, int add)
{
	switch (*packet)
	{
		case '0' :
		{
			// skip zero and  ,
			return set_breakpoint_address(packet + 2, add);
		}

		// Only 0 is supported now

		default:
		{
			printf("unknown breakpoint type\n");
			send_packet_string ("");
			return false;
		}
	}
}


static bool handle_packet(char* packet, int length)
{
	const char command = *packet;

	printf("handle packet %s\n", packet);

	// ‘v’ Packets starting with ‘v’ are identified by a multi-letter name, up to the first ‘;’ or ‘?’ (or the end of the packet).

	if (command == 'v')
		return handle_multi_letter_packet(packet, length);

	if (command == 'q' || command == 'Q')
		return handle_query_packet(packet, length);

	switch (command)
	{
		case 'g' : return send_registers ();
		case 's' : return step ();
		case 'n' : return step_next_instruction ();
		case 'H' : return handle_thread ();
		case 'G' : return set_registers ((const uae_u8*)packet + 1);
		case '?' : return send_exception ();
		case 'k' : return kill_program ();
		case 'm' : return send_memory (packet + 1);
		case 'M' : return set_memory (packet + 1, length - 1);
		case 'c' : return continue_exec (packet + 1);
		case 'Z' : return set_breakpoint (packet + 1, 1);
		case 'z' : return set_breakpoint (packet + 1, 0);

		default : send_packet_string ("");
	}

	return false;
}

static bool parse_packet(char* packet, int size)
{
	uae_u8 calc_checksum = 0;
	uae_u8 read_checksum = 0;
	int start, end;

	printf("parsing packet %s\n", packet);

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
			printf("[<----] -\n");
			rconn_send (s_conn, "-", 1, 0);
		}

		printf("mismatching checksum (calc 0x%x read 0x%x)\n", calc_checksum, read_checksum);
		return false;
	}

	if (need_ack) {
		printf("[<----] +\n");
		rconn_send (s_conn, "+", 1, 0);
	}

	// set end of string on the end marker

	return handle_packet(&packet[start + 1], size - 1);
}


static void update_connection (void)
{
	if (fs_emu_is_quitting())
		return;

	//printf("updating connection\n");

	// this function will just exit if already connected
	rconn_update_listner (s_conn);

	if (rconn_poll_read(s_conn)) {
		char temp[1024] = { 0 };

		int size = rconn_recv(s_conn, temp, sizeof(temp), 0);

		printf("[---->] %s\n", temp);

		if (size > 0)
			parse_packet(temp, size);
	}
}

// Main function that will be called when doing the actual debugging

static void remote_debug_ (void)
{
	uaecptr pc = m68k_getpc ();

	// used when stepping over an instruction (useful to skip bsr/jsr/etc)

	if (s_skip_to_pc != 0xffffffff)
	{
		set_special (SPCFLAG_BRK);

		if (s_skip_to_pc == pc) {
			send_exception ();
			s_state = Tracing;
			s_skip_to_pc = 0xffffffff; 
		}
	}

	//printf("update remote-Debug %d\n", s_state);

	for (int i = 0; i < s_breakpoint_count; ++i)
	{
		set_special (SPCFLAG_BRK);

		printf("checking breakpoint %08x - %08x\n", s_breakpoints[i].address, pc);

		if (s_breakpoints[i].address == pc)
		{
			send_exception ();
			printf("switching to tracing\n");
			s_state = Tracing;
			break;
		}
	}

	if (s_state == TraceToProgram)
	{
		set_special (SPCFLAG_BRK);

		for (int i = 0, end = s_segment_count; i < end; ++i) {
			const segment_info* seg = &s_segment_info[i];

			uae_u32 seg_start = seg->address;
			uae_u32 seg_end = seg->address + seg->size;

			if (pc >= seg_start && pc < seg_end) {
				//send_exception ();
				printf("switching to tracing\n");
				s_state = Tracing;
				break;
			}
		}
	}

	// Check if we hit some breakpoint and then switch to tracing if we do

	switch (s_state)
	{
		case Running:
		{
			update_connection ();
			s_socket_update_count = 0;

			break;
		}

		case Tracing:
		{
			if (did_step_cpu) {
				printf("did step cpu\n");
				send_exception ();
				did_step_cpu = false;
			}

			while (1)
			{
				update_connection ();

				if (step_cpu)
				{
					printf("jumping back to uae for cpu step\n");
					step_cpu = false;
					break;
				}

				if (fs_emu_is_quitting())
				{
					printf("request quit\n");
					s_state = Running;
					rconn_destroy(s_conn);
					s_conn = 0;
					break;
				}

				sleep_millis (1);	// don't hammer
			}

			break;
		}

		default:
			break;
	}
}

// This function needs to be called at regular interval to keep the socket connection alive

static void remote_debug_update_ (void)
{
	/*
	static int counter = 0;
	counter++;
	//printf("counter %d\n", counter++);
	if (counter == 1000) {
		printf("activate debug_dma\n");
		debug_dma = 2;
	}
	*/

	//debug_dma = 2;

	if (!s_conn)
		return;

	rconn_update_listner (s_conn);

	remote_debug_ ();
	activate_debugger ();

	if (rconn_poll_read(s_conn)) {
		activate_debugger ();
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static void rec_dma_event (int evt, int hpos, int vpos)
{
	if (!dma_record[0])
		return;

	if (hpos >= NR_DMA_REC_HPOS || vpos >= NR_DMA_REC_VPOS)
		return;

	dma_rec* dr = &dma_record[dma_record_toggle][vpos * NR_DMA_REC_HPOS + hpos];
	dr->evt |= evt;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static void rec_dma_reset (void)
{
	if (!dma_record[0])
		return;

	dma_record_toggle ^= 1;

	int t = dma_record_toggle;

	if (debug_dma_frame) {
		if (dma_max_sizes[t][0] != 0) { // make sure we have valid data before sending it
			uae_u8* buffer = (uae_u8*)dma_info_rec[t];
			uae_u8* store = buffer;

			uae_u16 line = dma_max_sizes[t][0];
			uae_u16 hcount = dma_max_sizes[t][1];

			buffer = write_string(buffer, "$QDmaFrame:");
			buffer = write_u16(buffer, hcount);
			buffer = write_u16(buffer, line);

			for (int y = 0; y < line; y++) {
				for (int x = 0; x < hcount; x++) {
					dma_rec* dr = &dma_record[t][y * NR_DMA_REC_HPOS + x];
					buffer = write_u8(buffer, (uae_u8)dr->evt);
					buffer = write_u8(buffer, (uae_u8)dr->type);
				}
			}

			int len = (int)((uintptr_t)buffer - (uintptr_t)store);

			send_packet_in_place(store, len);
		}
	}

	dma_max_sizes[dma_record_toggle][0] = 0;
	dma_max_sizes[dma_record_toggle][1] = 0;

	dma_rec* dr = dma_record[dma_record_toggle];
	for (int v = 0; v < NR_DMA_REC_VPOS; v++) {
		for (int h = 0; h < NR_DMA_REC_HPOS; h++) {
			dma_rec* dr2 = &dr[v * NR_DMA_REC_HPOS + h];
			memset (dr2, 0, sizeof (struct dma_rec));
			dr2->reg = 0xffff;
			dr2->addr = 0xffffffff;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void draw_cycles (int line, int width, int height)
{
	if (!dma_record[0]) {
		return;
	}

	int y = line;

	if (y < 0)
		return;
	if (y > maxvpos)
		return;
	if (y >= height)
		return;

	int t = dma_record_toggle ^ 1;

	// only track stuff and send later

	if (debug_dma_frame) {
		if (line > dma_max_sizes[t][0])
			dma_max_sizes[t][0] = line;

		if (maxhpos > dma_max_sizes[t][1])
			dma_max_sizes[t][1] = maxhpos;

		return;
	}

	uae_u8 temp[(NR_DMA_REC_HPOS * sizeof(dma_rec) * 2) + 256] = { 0 };
	uae_u8* buffer = temp;

	const int tag_size = 10;

	memcpy(buffer, "$QDmaTime:", tag_size);
	buffer += tag_size;

	//*buffer++ = '$';

	buffer = write_u16(buffer, line);
	buffer = write_u16(buffer, maxhpos);

	for (int x = 0; x < maxhpos; x++) {
		dma_rec* dr = &dma_record[t][y * NR_DMA_REC_HPOS + x];
		buffer = write_u16(buffer, dr->evt);
		buffer = write_u16(buffer, dr->type);
	}

	int buffer_size = tag_size + 8 + (maxhpos * 8);

	printf("buffer_size size to send (%d - %d) - %d\n", line, maxhpos, buffer_size);

	// TODO: Handle error

	(void)send_packet_in_place(temp, buffer_size - 1);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct dma_rec* remote_record_dma (uae_u16 reg, uae_u16 dat, uae_u32 addr,
								   int hpos, int vpos, int type)
{
	if (!dma_record[0]) {
		dma_record[0] = xmalloc (struct dma_rec, NR_DMA_REC_HPOS * NR_DMA_REC_VPOS);
		dma_record[1] = xmalloc (struct dma_rec, NR_DMA_REC_HPOS * NR_DMA_REC_VPOS);
		dma_info_rec[0] = xmalloc (struct dma_info, (NR_DMA_REC_HPOS * (NR_DMA_REC_VPOS + 1) * 2)); // + 1 for extra dataO
		dma_info_rec[1] = xmalloc (struct dma_info, (NR_DMA_REC_HPOS * (NR_DMA_REC_VPOS + 1) * 2)); // + 1 for extra data

		dma_record_toggle = 0;
		record_dma_reset ();
	}

	if (hpos >= NR_DMA_REC_HPOS || vpos >= NR_DMA_REC_VPOS)
		return NULL;

	dma_rec* dr = &dma_record[dma_record_toggle][vpos * NR_DMA_REC_HPOS + hpos];

	if (dr->reg != 0xffff) {
		write_log (_T("DMA conflict: v=%d h=%d OREG=%04X NREG=%04X\n"), vpos, hpos, dr->reg, reg);
		return dr;
	}

	dr->reg = reg;
	dr->dat = dat;
	dr->addr = addr;
	dr->type = type;
	dr->intlev = regs.intmask;

	return dr;
}

extern uaecptr get_base (const uae_char *name, int offset);

// Called from debugger_helper. At this point CreateProcess has been called
// and we are resposible for filling out the data needed by the "RunCommand"
// that looks like this:
//
//    rc = RunCommand(seglist, stacksize, argptr, argsize)
//    D0                D1         D2       D3      D4
//
//    LONG RunCommand(BPTR, ULONG, STRPTR, ULONG)
//
void remote_debug_start_executable (struct TrapContext *context)
{
	uaecptr filename = ds (s_exe_to_run);
	uaecptr args = ds ("");

	// so this is a hack to say that we aren't running from cli

	m68k_areg (regs, 1) = 0;
	uae_u32 curr_task = CallLib (context, get_long (4), -0x126); /* FindTask */
	char* task_ptr = au((char*)get_real_address (get_long (curr_task)));

	// Clear WB message
	*((uae_u32*)(task_ptr + 0xac)) = 0;

	uaecptr dosbase = get_base ("dos.library", 378);

	if (dosbase == 0) {
		printf("Unable to get dosbase\n");
		return;
	}

	segtracker_clear ();

    m68k_dreg (regs, 1) = filename;
	CallLib (context, dosbase, -150 );

    uaecptr segs = m68k_dreg (regs, 0);

    if (segs == 0) {
    	printf("Unable to load segs\n");
    	return;
	}

	char buffer[1024] = { 0 };
	strcpy(buffer, "AS");

	// Gather segments from segment tracker so we can send them back to fontend
	// which needs to know about them to matchup the debug info

	seglist* sl = segtracker_pool.first;
	s_segment_count = 0;

	while (sl) {
		segment *s = sl->segments;
		while (s->addr) {
			char temp[64];
			s_segment_info[s_segment_count].address = s->addr;
			s_segment_info[s_segment_count].size = s->size;
			s_segment_count++;

			//sprintf(temp, ";%08x;%d", s->addr, s->size);
			sprintf(temp, ";%d;%d", s->addr, s->size);
			strcat(buffer, temp);
			s++;
		}
		sl = sl->next;
	}

	// Resolving breakpoints before we start running. The allows us to have breakpoints before
	// the execution of the program (such stop at "main")

	for (int i = 0; i < s_breakpoint_count; ++i)
	{
	    Breakpoint* bp = &s_breakpoints[i];

	    if (!bp->needs_resolve)
	        continue;

        resolve_breakpoint_seg_offset (bp);
	}

	send_packet_string (buffer);

	printf("segs to send back %s\n", buffer);

	context_set_areg(context, 6, dosbase);
	context_set_dreg(context, 1, segs);
	context_set_dreg(context, 2, 4096);
	context_set_dreg(context, 3, args);
	context_set_dreg(context, 4, 0);

	deactive_debugger ();

	printf("remote_debug_start_executable\n");
}

void remote_debug_end_executable (struct TrapContext *context)
{
	printf("remote_debug_end_executable\n");
}

//
// These are just wrappers to expose the code to C from C++
//

extern "C"
{

void remote_debug_init (int time_out) { remote_debug_init_ (time_out); }
void remote_debug (void) { remote_debug_ (); }
void remote_debug_update (void) { remote_debug_update_ (); }
void remote_record_dma_event (int evt, int hpos, int vpos) { rec_dma_event(evt, hpos, vpos); }
void remote_record_dma_reset (void) { rec_dma_reset (); }
void remote_debug_draw_cycles (int line, int width, int height) { draw_cycles(line, width, height); }
struct dma_rec* remote_record_dma (uae_u16 reg, uae_u16 dat, uae_u32 addr,
								   int hpos, int vpos, int type);
int fs_emu_is_quitting();


}

#endif


