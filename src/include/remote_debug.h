 /*
  * UAE - The Un*x Amiga Emulator
  *
  * Debugger
  *
  * (c) 1995 Bernd Schmidt
  * 
  * Remote debugger code (c) 2016 Daniel Collin.
  */

#ifndef UAE_REMOTE_DEBUG_H
#define UAE_REMOTE_DEBUG_H

#define REMOTE_DEBUGGER

#ifdef REMOTE_DEBUGGER

struct TrapContext;

#ifdef __cplusplus
extern "C" {
#endif


//
// Set to 1 if remote debugging is enabled otherwise 0
//

extern int remote_debugging;

// 
// time_out allows to set the time UAE will wait at startup for a connection. 
// This is useful when wanting to debug things at early startup.
// If this is zero no time-out is set and if -1 no remote connection will be setup
//

void remote_debug_init (int time_out);

// Main function that will be called when doing the actual debugging

void remote_debug (void);

// This function needs to be called at regular interval to keep the socket connection alive

void remote_debug_update (void);

// 

#ifdef __cplusplus
}
#endif

void remote_debug_start_executable (struct TrapContext *context);
void remote_debug_end_executable (struct TrapContext *context);

#endif // REMOTE_DEBUGGER

#endif // UAE_REMOTE_DEBUG

