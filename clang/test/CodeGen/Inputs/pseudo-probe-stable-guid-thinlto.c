// The module that provides the inlined-through-ThinLTO chain: inner and mid are
// static + always_inline, so in this module's prelink they are inlined into
// outer and dropped as functions, but their probes and DISubprograms live on
// inside outer's body.
static int __attribute__((always_inline)) inner(int x) { return x + 1; }
static int __attribute__((always_inline)) mid(int x) { return inner(x) * 2; }
int outer(int x) { return mid(x) + 3; }
