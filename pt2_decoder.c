#include "pt_cpu.h"
#include "intel_pt.h"
#include "libipt_sb.h"
#include "profiler.h"
#include "threads.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <time.h>

#define PARALLEL_LEVEL 8

/* thread exclusive decoder */
struct pt2_excl_decoder{
    /* thread exclusive identifier */
    uint32_t  id;
    
    /* the actual decoder. */
    struct pt_insn_decoder *insn;

    /* the sideband session */
    struct pt_sb_session *session;

    /* The image section cache. */
    struct pt_image_section_cache *iscache;

    /* thread exectuion status */
    int retStatus;

    uint8_t *begin;
    uint8_t *end;
};

/* The decoder to use. */
struct pt2_decoder {

    /* A collection of decoder-specific flags. */
    struct pt_conf_flags flags;

    /* The perf event sideband decoder configuration. */
    struct pt_sb_pevent_config pevent;

    /* decoder exclusive for each thread parallel decoding*/
    struct pt2_excl_decoder excl_decoder[PARALLEL_LEVEL];

    thrd_t threads[PARALLEL_LEVEL];
};

/* profilers */
struct pt_profiler *profiler[PARALLEL_LEVEL];

static int pt2_have_decoder(struct pt2_decoder *decoder){
    if (!decoder)
        return 0;
    
    for (int i = 0; i < PARALLEL_LEVEL; i++){
        if (decoder->excl_decoder[i].insn)
            return 1;
    }
    return 0;
}

static int pt2_init_decoder(struct pt2_decoder *decoder)
{
    if (!decoder)
        return -pte_internal;

    memset(decoder, 0, sizeof(*decoder));

    struct pt2_excl_decoder *excl_decoder;
    for (int i = 0; i < PARALLEL_LEVEL; i++){
        excl_decoder = &decoder->excl_decoder[i];

        excl_decoder->id = i;
        excl_decoder->iscache = pt_iscache_alloc(NULL);
        if (!excl_decoder->iscache)
            return -pte_nomem;
        
        excl_decoder->session = pt_sb_alloc(excl_decoder->iscache);
        if (!excl_decoder->session) {
            pt_iscache_free(excl_decoder->iscache);
            return -pte_nomem;
        }
    }

    memset(&decoder->pevent, 0, sizeof(decoder->pevent));
    decoder->pevent.size = sizeof(decoder->pevent);
    decoder->pevent.kernel_start = UINT64_MAX;
    decoder->pevent.time_mult = 1;

    return 0;
}

static void pt2_free_decoder(struct pt2_decoder *decoder)
{
    if (!decoder)
        return;

    struct pt2_excl_decoder *excl_decoder;

    for (int i = 0; i < PARALLEL_LEVEL; i++){
        excl_decoder = &decoder->excl_decoder[i];
        pt_insn_free_decoder(excl_decoder->insn);
        pt_sb_free(excl_decoder->session);
        pt_iscache_free(excl_decoder->iscache);
    }

}

static int extract_base(char *arg, uint64_t *base)
{
    char *sep, *rest;

    sep = strrchr(arg, ':');
    if (sep) {
        uint64_t num;

        if (!sep[1])
            return 0;

        errno = 0;
        num = strtoull(sep+1, &rest, 0);
        if (errno || *rest)
            return 0;

        *base = num;
        *sep = 0;
        return 1;
    }

    return 0;
}

static int parse_range(const char *arg, uint64_t *begin, uint64_t *end)
{
    char *rest;

    if (!arg || !*arg)
        return 0;

    errno = 0;
    *begin = strtoull(arg, &rest, 0);
    if (errno)
        return -1;

    if (!*rest)
        return 1;

    if (*rest != '-')
        return -1;

    *end = strtoull(rest+1, &rest, 0);
    if (errno || *rest)
        return -1;

    return 2;
}

/* Preprocess a filename argument.
 *
 * A filename may optionally be followed by a file offset or a file range
 * argument separated by ':'.  Split the original argument into the filename
 * part and the offset/range part.
 *
 * If no end address is specified, set @size to zero.
 * If no offset is specified, set @offset to zero.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int preprocess_filename(char *filename, uint64_t *offset, uint64_t *size)
{
    uint64_t begin, end;
    char *range;
    int parts;

    if (!filename || !offset || !size)
        return -pte_internal;

    /* Search from the end as the filename may also contain ':'. */
    range = strrchr(filename, ':');
    if (!range) {
        *offset = 0ull;
        *size = 0ull;

        return 0;
    }

    /* Let's try to parse an optional range suffix.
     *
     * If we can, remove it from the filename argument.
     * If we can not, assume that the ':' is part of the filename, e.g. a
     * drive letter on Windows.
     */
    parts = parse_range(range + 1, &begin, &end);
    if (parts <= 0) {
        *offset = 0ull;
        *size = 0ull;

        return 0;
    }

    if (parts == 1) {
        *offset = begin;
        *size = 0ull;

        *range = 0;

        return 0;
    }

    if (parts == 2) {
        if (end <= begin)
            return -pte_invalid;

        *offset = begin;
        *size = end - begin;

        *range = 0;

        return 0;
    }

    return -pte_internal;
}

static int load_file(uint8_t **buffer, size_t *psize, const char *filename,
		     uint64_t offset, uint64_t size, const char *prog)
{
    uint8_t *content;
    size_t read;
    FILE *file;
    long fsize, begin, end;
    int errcode;

    if (!buffer || !psize || !filename || !prog) {
        fprintf(stderr, "%s: internal error.\n", prog ? prog : "");
        return -1;
    }

    errno = 0;
    file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "%s: failed to open %s: %d.\n",
            prog, filename, errno);
        return -1;
    }

    errcode = fseek(file, 0, SEEK_END);
    if (errcode) {
        fprintf(stderr, "%s: failed to determine size of %s: %d.\n",
            prog, filename, errno);
        goto err_file;
    }

    fsize = ftell(file);
    if (fsize < 0) {
        fprintf(stderr, "%s: failed to determine size of %s: %d.\n",
            prog, filename, errno);
        goto err_file;
    }

    begin = (long) offset;
    if (((uint64_t) begin != offset) || (fsize <= begin)) {
        fprintf(stderr,
            "%s: bad offset 0x%" PRIx64 " into %s.\n",
            prog, offset, filename);
        goto err_file;
    }

    end = fsize;
    if (size) {
        uint64_t range_end;

        range_end = offset + size;
        if ((uint64_t) end < range_end) {
            fprintf(stderr,
                "%s: bad range 0x%" PRIx64 " in %s.\n",
            prog, range_end, filename);
            goto err_file;
        }

        end = (long) range_end;
    }

    fsize = end - begin;

    content = malloc((size_t) fsize);
    if (!content) {
        fprintf(stderr, "%s: failed to allocated memory %s.\n",
            prog, filename);
        goto err_file;
    }

    errcode = fseek(file, begin, SEEK_SET);
    if (errcode) {
        fprintf(stderr, "%s: failed to load %s: %d.\n",
            prog, filename, errno);
        goto err_content;
    }

    read = fread(content, (size_t) fsize, 1u, file);
    if (read != 1) {
        fprintf(stderr, "%s: failed to load %s: %d.\n",
            prog, filename, errno);
        goto err_content;
    }

    fclose(file);

    *buffer = content;
    *psize = (size_t) fsize;

    return 0;

err_content:
    free(content);

err_file:
    fclose(file);
    return -1;
}

static int load_pt(struct pt_config *config, char *arg, const char *prog)
{
    uint64_t foffset, fsize;
    uint8_t *buffer;
    size_t size;
    int errcode;

    errcode = preprocess_filename(arg, &foffset, &fsize);
    if (errcode < 0) {
        fprintf(stderr, "%s: bad file %s: %s.\n", prog, arg,
            pt_errstr(pt_errcode(errcode)));
        return -1;
    }

    errcode = load_file(&buffer, &size, arg, foffset, fsize, prog);
    if (errcode < 0)
        return errcode;

    config->begin = buffer;
    config->end = buffer + size;

    return 0;
}

static int load_raw(struct pt_image_section_cache *iscache,
		    struct pt_image *image, char *arg, const char *prog)
{
    uint64_t base, foffset, fsize;
    int isid, errcode, has_base;

    has_base = extract_base(arg, &base);
    if (has_base <= 0) {
        fprintf(stderr, "%s: failed to parse base address"
            "from '%s'.\n", prog, arg);
        return -1;
    }

    errcode = preprocess_filename(arg, &foffset, &fsize);
    if (errcode < 0) {
        fprintf(stderr, "%s: bad file %s: %s.\n", prog, arg,
            pt_errstr(pt_errcode(errcode)));
        return -1;
    }

    if (!fsize)
        fsize = UINT64_MAX;

    isid = pt_iscache_add_file(iscache, arg, foffset, fsize, base);
    if (isid < 0) {
        fprintf(stderr, "%s: failed to add %s at 0x%" PRIx64 ": %s.\n",
            prog, arg, base, pt_errstr(pt_errcode(isid)));
        return -1;
    }

    errcode = pt_image_add_cached(image, iscache, isid, NULL);
    if (errcode < 0) {
        fprintf(stderr, "%s: failed to add %s at 0x%" PRIx64 ": %s.\n",
            prog, arg, base, pt_errstr(pt_errcode(errcode)));
        return -1;
    }

    return 0;
}

static int pt2_sb_event(struct pt2_excl_decoder *decoder,
			  const struct pt_event *event)
{
    struct pt_image *image;
    int errcode;

    if (!decoder || !event)
        return -pte_internal;

    image = NULL;

    errcode = pt_sb_event(decoder->session, &image, event, sizeof(*event),
                    stdout, 0);

    if (errcode < 0)
        return errcode;
    
    if (!image)
        return 0;

    if (decoder->insn){
        return pt_insn_set_image(decoder->insn, image);
    }

    return -pte_internal;
}

static void diagnose(struct pt2_excl_decoder *decoder, uint64_t ip,
		     const char *errtype, int errcode)
{
	int err;
	uint64_t pos;

	err = -pte_internal;
	pos = 0ull;

	
	err = pt_insn_get_offset(decoder->insn, &pos);
	
	if (err < 0) {
		fprintf(stderr, "%u could not determine offset: %s\n",
		       decoder->id, pt_errstr(pt_errcode(err)));
		fprintf(stderr, "%u [?, %" PRIx64 ": %s: %s]\n", decoder->id,
                ip, errtype, pt_errstr(pt_errcode(errcode)));
	} else{
		fprintf(stderr, "%u [%" PRIx64 ", %" PRIx64 ": %s: %s]\n", decoder->id, 
               pos, ip, errtype, pt_errstr(pt_errcode(errcode)));
    }
}

static int drain_events_insn(struct pt2_excl_decoder *decoder, 
                            uint64_t *time, int status)
{
    struct pt_insn_decoder *ptdec;
    int errcode;

    if (!decoder || !time)
        return -pte_internal;

    ptdec = decoder->insn;

    while (status & pts_event_pending) {
        struct pt_event event;

        status = pt_insn_event(ptdec, &event, sizeof(event));
        if (status < 0)
            return status;

        *time = event.tsc;

        errcode = pt2_sb_event(decoder, &event);
        if (errcode < 0)
            return errcode;
    }

    return status;
}

static int decode_insn(void *data){
    if (!data){
        fprintf(stderr, "[internal error]\n");
        return -1;
    }
    struct pt2_excl_decoder *decoder = (struct pt2_excl_decoder *)data;

    struct pt_excl_profiler *excl_profiler = pt_excl_profiler_alloc();
    if (!excl_profiler){
        fprintf(stderr, "failed alloc excl profiler\n");
        return -pte_nomem;
    }

    struct pt_insn_decoder *ptdec;
    uint64_t offset, sync, time;

    int status;
    ptdec = decoder->insn;
    offset = 0ull;
    sync = 0ull;
    time = 0ull;
    const char *binary_name;
    for (;;) {
        struct pt_insn insn;

        /* Initialize the IP - we use it for error reporting. */
        insn.ip = 0ull;

        status = pt_insn_sync_forward(ptdec);
        
        if (status < 0) {
            uint64_t new_sync;
            int errcode;

            if (status == -pte_eos)
                break;

            diagnose(decoder, insn.ip, "sync error", status);

            /* Let's see if we made any progress.  If we haven't,
             * we likely never will.  Bail out.
             *
             * We intentionally report the error twice to indicate
             * that we tried to re-sync.  Maybe it even changed.
             */
            errcode = pt_insn_get_offset(ptdec, &new_sync);
            if (errcode < 0 || (new_sync <= sync))
                break;

            sync = new_sync;
            continue;
        }

        for (;;) {
            status = drain_events_insn(decoder, &time, status);
            if (status < 0)
                break;

            if (status & pts_eos) {
                status = -pte_eos;
                
                break;
            }

            status = pt_insn_next(ptdec, &insn, sizeof(insn));
            if (status < 0) {
                /* Even in case of errors, we may have succeeded
                 * in decoding the current instruction.
                */
                /*if (insn.iclass != ptic_error){
                    pt_profiler_add(profiler[decoder->id], 
                                    excl_profiler, &insn);
                }*/

                break;
            }
            //pt_profiler_add(profiler[decoder->id], excl_profiler, &insn);
            
        }

        /* We shouldn't break out of the loop without an error. */
        if (!status)
            status = -pte_internal;

        /* We're done when we reach the end of the trace stream. */
        if (status == -pte_eos)
            break;

        diagnose(decoder, insn.ip, "error", status);
    }
    
    pt_excl_profiler_free(excl_profiler);
    return status;
}

static void decode(struct pt2_decoder *decoder, struct pt_config *config){
    if (!decoder){
        fprintf(stderr, "[internal error]\n");
        return;
    }

    struct pt2_excl_decoder *excl_decoder;
    
    /* parallel decode */
    for (int i = 0; i < PARALLEL_LEVEL; i++){
        excl_decoder = &decoder->excl_decoder[i];
        if (excl_decoder->insn){
            int ret = thrd_create(&decoder->threads[i],
                          decode_insn, excl_decoder);
            if (ret < 0){
                fprintf(stderr, "create parallel decoding thread fails\n");
                //break;
            }
        }
    }

    for (int i = 0; i < PARALLEL_LEVEL; i++){
        excl_decoder = &decoder->excl_decoder[i];
        thrd_join(&decoder->threads[i], &excl_decoder->retStatus);
    }
}

/* split trace stream into segments */
static int split_trace(struct pt2_decoder *decoder,
                       struct pt_config *config){
    struct pt_packet_decoder *pktdec;
    
    pktdec = pt_pkt_alloc_decoder(config);
    if (!pktdec){
        fprintf(stderr,
                "failed to create pkt decoder.\n");
        return -pte_nomem;
    }

    /* count synchronnizing points */
    int cnt = 0;
    /* default max synchronizing points */
    uint32_t size = 64;
    /* memorize synchronizing point offsets */
    uint64_t *offset_buf = malloc( 8 * size );
    if (!offset_buf){
        fprintf(stderr, "failed to create offset buffer\n");
        return -pte_nomem;
    }
    memset(offset_buf, 0, 8*size);

    int status, errcode;
    uint64_t offset = 0ull;
    for (;;) {
        status = pt_pkt_sync_forward(pktdec);
        if (status < 0){
            if (status != -pte_eos)
                fprintf(stderr, "pkt sync error: %s\n", 
                    pt_errstr(pt_errcode(status)));
            break;
        }

        errcode = pt_pkt_get_sync_offset(pktdec, &offset);
        if (errcode < 0){
            fprintf(stderr, "pkt get sync error %s\n", 
                    pt_errstr(pt_errcode(errcode)));
            break;
        }
        
        if (cnt+1 >= size){
            uint32_t new_size = 2*size;
            uint64_t *new_buf = malloc(8*new_size);
            if (!new_buf){
                free(offset_buf);
                fprintf(stderr, "failed to create offset buffer\n");
                return -pte_nomem;
            }
            memset(new_buf, 0, new_size * 8);
            memcpy(new_buf, offset_buf, size * 8);
            free(offset_buf);
            offset_buf = new_buf;
            size = new_size;
        }
        offset_buf[cnt++] = offset;
    }
    /* we also memorize the end's offset */
    offset_buf[cnt++] = config->end - config->begin;
    
    pt_pkt_free_decoder(pktdec);

    struct pt2_excl_decoder *excl_decoder;
    int ind = 0;
    for (int i = 0; i < PARALLEL_LEVEL; i++){
        excl_decoder = &decoder->excl_decoder[i];
        excl_decoder->begin = config->begin + offset_buf[ind];
        ind += ((cnt-1) / PARALLEL_LEVEL);
        if (i < (cnt-1) % PARALLEL_LEVEL)
            ind++;
        if (ind >= cnt)
            break;
        excl_decoder->end = config->begin + offset_buf[ind];
    }

    free(offset_buf);
    return 0;
}

/* parallel decoder alloc */
static int alloc_decoder(struct pt2_decoder *decoder,
            const struct pt_config *conf, const char *prog)
{
    struct pt_config config;
    int errcode;

    if (!decoder || !conf || !prog)
        return -pte_internal;

    config = *conf;

    config.flags = decoder->flags;

    /* split trace stream */
    if (split_trace(decoder, &config) < 0)
        return -1;

    /* alloc parallel decoder */
    struct pt2_excl_decoder *excl_decoder;
    for (int i = 0; i < PARALLEL_LEVEL; i++){
        excl_decoder = &decoder->excl_decoder[i];
        if (!excl_decoder->end)
            break;
        config.begin = excl_decoder->begin;
        config.end = excl_decoder->end;

        excl_decoder->insn = pt_insn_alloc_decoder(&config);
        if (!excl_decoder->insn)
            return -pte_nomap;
    }

    return 0;
}

static int pt2_sb_output_error(int errcode, const char *filename,
			     uint64_t offset, void *priv)
{
	const char *errstr, *severity;

    int id = -1;
    if (priv)
        id = *(uint32_t *)priv;
    
	if (errcode >= 0)
		return 0;

	if (!filename)
		filename = "<unknown>";

	severity = errcode < 0 ? "error" : "warning";

	errstr = errcode < 0
		? pt_errstr(pt_errcode(errcode))
		: pt_sb_errstr((enum pt_sb_error_code) errcode);

	if (!errstr)
		errstr = "<unknown error>";

	fprintf(stderr, "[%s:%016" PRIx64 " sideband %d %s: %s]\n", filename, offset,
	       id, severity, errstr);

	return 0;
}

static int pt2_sb_pevent(struct pt2_decoder *decoder, char *filename,
			   const char *prog)
{
    struct pt_sb_pevent_config config;
    uint64_t foffset, fsize, fend;
    int errcode;

    if (!decoder || !prog) {
        fprintf(stderr, "%s: internal error.\n", prog ? prog : "?");
        return -1;
    }

    errcode = preprocess_filename(filename, &foffset, &fsize);
    if (errcode < 0) {
        fprintf(stderr, "%s: bad file %s: %s.\n", prog, filename,
            pt_errstr(pt_errcode(errcode)));
        return -1;
    }

    if (SIZE_MAX < foffset) {
        fprintf(stderr,
            "%s: bad offset: 0x%" PRIx64 ".\n", prog, foffset);
        return -1;
    }

    config = decoder->pevent;
    config.filename = filename;
    config.begin = (size_t) foffset;
    config.end = 0;

    if (fsize) {
        fend = foffset + fsize;
        if ((fend <= foffset) || (SIZE_MAX < fend)) {
            fprintf(stderr,
                "%s: bad range: 0x%" PRIx64 "-0x%" PRIx64 ".\n",
                prog, foffset, fend);
            return -1;
        }

        config.end = (size_t) fend;
    }

    struct pt2_excl_decoder *excl_decoder;
    for (int i = 0; i < PARALLEL_LEVEL; i++){
        excl_decoder = &decoder->excl_decoder[i];
        errcode = pt_sb_alloc_pevent_decoder(
                            excl_decoder->session, &config);
        if (errcode < 0) {
            fprintf(stderr, "%s: error loading %s: %s.\n", prog, 
                    filename, pt_errstr(pt_errcode(errcode)));
            return -1;
        }    
    }

    return 0;
}

static int get_arg_uint64(uint64_t *value, const char *option, const char *arg,
			  const char *prog)
{
    char *rest;

    if (!value || !option || !prog) {
        fprintf(stderr, "%s: internal error.\n", prog ? prog : "?");
        return 0;
    }

    if (!arg || arg[0] == 0 || (arg[0] == '-' && arg[1] == '-')) {
        fprintf(stderr, "%s: %s: missing argument.\n", prog, option);
        return 0;
    }

    errno = 0;
    *value = strtoull(arg, &rest, 0);
    if (errno || *rest) {
        fprintf(stderr, "%s: %s: bad argument: %s.\n", prog, option,
            arg);
        return 0;
    }

    return 1;
}

static int get_arg_uint32(uint32_t *value, const char *option, const char *arg,
                const char *prog)
{
    uint64_t val;

    if (!get_arg_uint64(&val, option, arg, prog))
        return 0;

    if (val > UINT32_MAX) {
        fprintf(stderr, "%s: %s: value too big: %s.\n", prog, option,
            arg);
        return 0;
    }

    *value = (uint32_t) val;

    return 1;
}


static int get_arg_uint16(uint16_t *value, const char *option, const char *arg,
			  const char *prog)
{
    uint64_t val;

    if (!get_arg_uint64(&val, option, arg, prog))
        return 0;

    if (val > UINT16_MAX) {
        fprintf(stderr, "%s: %s: value too big: %s.\n", prog, option,
            arg);
        return 0;
    }

    *value = (uint16_t) val;

    return 1;
}


static int get_arg_uint8(uint8_t *value, const char *option, const char *arg,
			 const char *prog)
{
    uint64_t val;

    if (!get_arg_uint64(&val, option, arg, prog))
        return 0;

    if (val > UINT8_MAX) {
        fprintf(stderr, "%s: %s: value too big: %s.\n", prog, option,
            arg);
        return 0;
    }

    *value = (uint8_t) val;

    return 1;
}

int pt2_decode(const char *config_filename, int primary, char* pt_filename)
{
    struct pt2_decoder decoder;
    struct pt_config config;
    const char *prog = "pt2_decoder";
    int errcode, i;

    if (!config_filename){
        fprintf(stderr, "%s: error config file %s not set\n",
                prog, config_filename);
        return -1;
    }

    pt_config_init(&config);

    errcode = pt2_init_decoder(&decoder);
    if (errcode < 0) {
        fprintf(stderr,
            "%s: error initializing decoder: %s.\n", prog,
            pt_errstr(pt_errcode(errcode)));
        goto err;
    }

    FILE *config_file = fopen(config_filename, "r");
    if (!config_file){
        fprintf(stderr, "%s: error config file : %s\n",
                prog, config_filename);
        goto err;
    }

    int argc;
    char arg[256];
    for (;;){
        argc = fscanf(config_file, "%s", arg);
        if (argc != 1)
            break;
        
        if (strcmp(arg, "--sideband") == 0) {
            int cpu_num;
            argc = fscanf(config_file, "%d%s", &cpu_num, arg);
            if (argc != 2) {
                fprintf(stderr, "%s: sideband: "
                    "missing argument.\n", prog);
                goto err;
            }
            decoder.pevent.primary = (cpu_num == primary)? 1 : 0;
            errcode = pt2_sb_pevent(&decoder, arg, prog);
            if (errcode < 0)
                goto err;

            continue;
        }
        
        if (strcmp(arg, "--sample-type") == 0) {
            argc = fscanf(config_file, "%s", arg);
            if (argc != 1)
                goto err;

            if (!get_arg_uint64(&decoder.pevent.sample_type,
                            "sample-type",
                            arg, prog))
                goto err;

            continue;
        }
        if (strcmp(arg, "--time-zero") == 0) {
            argc = fscanf(config_file, "%s", arg);
            if (argc != 1)
                goto err;

            if (!get_arg_uint64(&decoder.pevent.time_zero,
                            "time-zero",
                            arg, prog))
                goto err;

            continue;
        }
        if (strcmp(arg, "--time-shift") == 0) {
            argc = fscanf(config_file, "%s", arg);
            if (argc != 1)
                goto err;
            if (!get_arg_uint16(&decoder.pevent.time_shift,
                            "time-shift", arg, prog))
                goto err;

            continue;
        }
        if (strcmp(arg, "--time-mult") == 0) {
            argc = fscanf(config_file, "%s", arg);
            if (argc != 1)
                goto err;
		    if (!get_arg_uint32(&decoder.pevent.time_mult,
                            "time-mult", arg, prog))
                goto err;

            continue;
        }

        if (strcmp(arg, "--cpu") == 0) {
            /* override cpu information before the decoder
             * is initialized.
             */
            if (pt2_have_decoder(&decoder)) {
                fprintf(stderr,
                    "%s: please specify cpu before the pt source file.\n",
                    prog);
                goto err;
            }

            argc = fscanf(config_file, "%s", arg);
            if (argc != 1) {
                fprintf(stderr,
                    "%s: --cpu: missing argument.\n", prog);
                goto out;
            }
 
            errcode = pt_cpu_parse(&config.cpu, arg);
            if (errcode < 0) {
                fprintf(stderr,
                    "%s: cpu must be specified as f/m[/s]\n",
                    prog);
                goto err;
            }
            continue;
        }

        if (strcmp(arg, "--mtc-freq") == 0) {
            argc = fscanf(config_file, "%s", arg);
            if (argc != 1)
                goto err;

            if (!get_arg_uint8(&config.mtc_freq, "--mtc-freq",
                            arg, prog))
                goto err;

            continue;
        }
        if (strcmp(arg, "--nom-freq") == 0) {
            argc = fscanf(config_file, "%s", arg);
            if (argc != 1)
                goto err;

            if (!get_arg_uint8(&config.nom_freq, "--nom-freq",
                        arg, prog))
                goto err;

            continue;
        }
        if (strcmp(arg, "--cpuid-0x15.eax") == 0) {
            argc = fscanf(config_file, "%s", arg);
            if (argc != 1)
                goto err;

            if (!get_arg_uint32(&config.cpuid_0x15_eax,
                            "--cpuid-0x15.eax", arg,
                            prog))
                goto err;

            continue;
        }
        if (strcmp(arg, "--cpuid-0x15.ebx") == 0) {
            argc = fscanf(config_file, "%s", arg);
            if (argc != 1)
                goto err;

            if (!get_arg_uint32(&config.cpuid_0x15_ebx,
                            "--cpuid-0x15.ebx", arg,
                            prog))
                goto err;

            continue;
        }
    }
    fclose(config_file);

    /*request event tick for finer grain sideband correlation */
    decoder.flags.variant.insn.enable_tick_events = 1;
    
    for (i = 0; i < PARALLEL_LEVEL; i++){
        struct pt2_excl_decoder *excl_decoder;
        excl_decoder = &decoder.excl_decoder[i];

        pt_sb_notify_error(excl_decoder->session, pt2_sb_output_error, 
                           (void *)&excl_decoder->id);
        errcode = pt_sb_init_decoders(excl_decoder->session);
        if (errcode < 0) {
            fprintf(stderr,
                "%s: error initializing sideband decoders: %s.\n",
                prog, pt_errstr(pt_errcode(errcode)));
            goto err;
        }
    }

    /* pt decoder */
    if (config.cpu.vendor) {
        errcode = pt_cpu_errata(&config.errata,
                        &config.cpu);
        if (errcode < 0)
            fprintf(stderr, "[0, 0: config error: %s]\n",
                pt_errstr(pt_errcode(errcode)));
    }

    errcode = load_pt(&config, pt_filename, prog);
    if (errcode < 0)
        goto err;

    errcode = alloc_decoder(&decoder, &config, prog);
    if (errcode < 0)
        goto err;

    if (!pt2_have_decoder(&decoder)) {
        fprintf(stderr, "%s: no pt file.\n", prog);
        goto err;
    }
    
    decode(&decoder, &config);

out:
    pt2_free_decoder(&decoder);
    free(config.begin);
    return 0;

err:
    pt2_free_decoder(&decoder);
    free(config.begin);
    return -1;
}

int main(){

    for(int i = 0; i < PARALLEL_LEVEL; i++)
        profiler[i] = pt_profiler_alloc();
    
    pt2_decode("perf-attr-config", 0, "perf.data-aux-idx0.bin");
    pt2_decode("perf-attr-config", 1, "perf.data-aux-idx1.bin");
    pt2_decode("perf-attr-config", 2, "perf.data-aux-idx2.bin");
    pt2_decode("perf-attr-config", 3, "perf.data-aux-idx3.bin");
    pt2_decode("perf-attr-config", 4, "perf.data-aux-idx4.bin");
    pt2_decode("perf-attr-config", 5, "perf.data-aux-idx5.bin");
    pt2_decode("perf-attr-config", 6, "perf.data-aux-idx6.bin");
    pt2_decode("perf-attr-config", 7, "perf.data-aux-idx7.bin");

    for(int i = 0; i < PARALLEL_LEVEL; i++)
        pt_profiler_print(profiler[i]);
    for(int i = 0; i < PARALLEL_LEVEL; i++)
        pt_profiler_free(profiler[i]);
}
