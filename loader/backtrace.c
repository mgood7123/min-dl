#ifndef M
#include <stdio.h>
#include "libbacktrace/backtrace.h"
#include "libbacktrace/backtrace-supported.h"
int i = 0;
struct bt_ctx {
	struct backtrace_state *state;
	int error;
};

static void error_callback(void *data, const char *msg, int errnum)
{
	struct bt_ctx *ctx = data;
	fprintf(stderr, "ERROR: %s (%d)", msg, errnum);
	ctx->error = 1;
}

static void syminfo_callback (void *data, uintptr_t pc, const char *symname, uintptr_t symval, uintptr_t symsize)
{
	//struct bt_ctx *ctx = data;
    printf(": %035s", symname?symname:"???????????????????????????????????");
	symval?printf(": %018p", symval):printf(": %18s", "0x????????????????");
}

static int full_callback(void *data, uintptr_t pc, const char *filename, int lineno, const char *function)
{
    i++;
	struct bt_ctx *ctx = data;
    printf("#%6d ", i);
    (unsigned long)pc?printf("%018p", (unsigned long)pc):printf(": %18s", "0x????????????????");
    backtrace_syminfo (ctx->state, pc, syminfo_callback, error_callback, data);
	lineno?printf(":  %004d ", lineno):printf(":  %4s ", "????");
    printf(": %31s\n", filename?filename:"???????????????????????????????");
	return 0;
}

static int simple_callback(void *data, uintptr_t pc)
{
	struct bt_ctx *ctx = data;
	backtrace_pcinfo(ctx->state, pc, full_callback, error_callback, data);
	return 0;
}

static inline void bt_(struct backtrace_state *state)
{
	struct bt_ctx ctx = {state, 0};
    fprintf(stderr, "\
-----------------------------------------------------start of backtrace-----------------------------------------------------\n");
    fprintf(stderr, "%7s %018s  %35s  %18s   %4s   %31s\n", "depth", "address", "function name", "function value", "line", "filename");
    backtrace_full(state, 2, full_callback, error_callback, &ctx);
    i = 0;
    fprintf(stderr, "\
------------------------------------------------------end of backtrace------------------------------------------------------\n");
}
extern char ** argv;
void bt(void) {
	struct backtrace_state *state = backtrace_create_state (argv[0], BACKTRACE_SUPPORTS_THREADS, error_callback, NULL);
	bt_(state);
}
#endif
#ifdef M
int main()
{
    bt();
	return 0;
}
#endif
