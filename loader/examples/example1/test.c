#ifdef C
struct l { char * test; int num; } T[1];
#endif
#ifdef CPP
extern struct l T[1];
#endif

// struct l { char * test; } T[1];T * k = a(); // the return of a() would fill both k.test and k.num with values
