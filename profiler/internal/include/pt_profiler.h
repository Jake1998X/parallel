#include "addr2line.h"
#include "threads.h"

#include <inttypes.h>

#define INITIAL_LINE_VOL 64
#define CNT_SIZE 4


/* binary file struct */
struct binaryfile{
    char *filename;

    /* binary file description
     * it is used to change addresses to lines
     */
    struct bfd_desc desc;

    struct binaryfile *next;
};

/* function struct
 * save function profiling result
 */
struct function{
    char *functionname;

    /* called times */
    uint32_t cnt;

    struct function *next;
};

/* source file struct
 * used to save the source code profiling result
 */
struct sourcefile{
    char *filename;

    /* functions lying in this source file */
    struct function *func_list;
    
    /* line count statistics */
    uint32_t *cnt;
    /* line volume */
    uint32_t vol;

    struct sourcefile *next;
};

/* global profiler
   when parallel decoing: this profiler has
   profiling results of the whole
 */
struct pt_profiler{
    /* binary file list */
    struct binaryfile *binary_list;

    /* source file list*/
    struct sourcefile *source_list;

    mtx_t lock;
};

/* thread exclusive profiler 
 * when parallel decoding: this profiler has
 * its thread's currently profiling infomation
 */
struct pt_excl_profiler{
    struct binaryfile *binary;
    struct sourcefile *source;
    struct function *func;

    uint32_t line;

    /* just called another function */
    uint32_t call;
};
