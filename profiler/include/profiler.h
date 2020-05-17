/* global profiler 
   when parallel decoing: this profiler has
   profiling results of the whole
 */
struct pt_profiler;

/* thread exclusive profiler 
 * when parallel decoding: this profiler has
 * its thread's currently profiling infomation
 */
struct pt_excl_profiler;

/* alloc globall profiler */
extern struct pt_profiler *pt_profiler_alloc();
/* free global profiler */
extern void pt_profiler_free(struct pt_profiler *profiler);

/* alloc thread exclusive profiler */
extern struct pt_excl_profiler *pt_excl_profiler_alloc();
/* free thread-exclusive profiler */
extern void pt_excl_profiler_free(struct pt_excl_profiler *excl_profiler);

/* the instruction to add to the profiler */
struct pt_insn;
/* add an instruction to the profiler */
extern int pt_profiler_add(struct pt_profiler *profiler, 
                           struct pt_excl_profiler *excl_profiler,
                           struct pt_insn *insn);

/* print profiling result */
extern void pt_profiler_print(struct pt_profiler *profiler);