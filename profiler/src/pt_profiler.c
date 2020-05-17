#include "profiler.h"
#include "pt_profiler.h"
#include "intel_pt.h"

struct pt_profiler *pt_profiler_alloc(){
    struct pt_profiler *profiler = malloc(sizeof(struct pt_profiler));
    if (!profiler)
        return NULL;
    
    memset(profiler, 0, sizeof(*profiler));
    return profiler;
}

static void function_free(struct function *func){
    if (!func)
        return;
    
    if (func->functionname)
        free(func->functionname);
    
    free(func);
}

static void sourcefile_free(struct sourcefile *source){
    if (!source)
        return;
    
    struct function *func = source->func_list;
    while(func){
        source->func_list = func->next;

        function_free(func);

        func = source->func_list;
    }

    if (source->filename)
        free(source->filename);
    
    if (source->cnt)
        free(source->cnt);
    
    free(source);
}

static void binaryfile_free(struct binaryfile *binary){
    if (!binary)
        return;
    
    bfd_desc_free(&binary->desc);

    if (binary->filename)
        free(binary->filename);
    
}

void pt_profiler_free(struct pt_profiler *profiler){
    if (!profiler){
        return;
    }

    struct binaryfile *binary = profiler->binary_list;
    while (binary){
        profiler->binary_list = binary->next;

        binaryfile_free(binary);

        binary = profiler->binary_list;
    }

    struct sourcefile *source = profiler->source_list;
    while(source){
        profiler->source_list = source->next;

        sourcefile_free(source);

        source = profiler->source_list;
    }

    free(profiler);
}

struct pt_excl_profiler *pt_excl_profiler_alloc(){
    struct pt_excl_profiler *excl_profiler;
    excl_profiler = malloc(sizeof(struct pt_excl_profiler));
    if (!excl_profiler)
        return NULL;
    
    memset(excl_profiler, 0, sizeof(*excl_profiler));
    return excl_profiler;
}

void pt_excl_profiler_free(struct pt_excl_profiler *excl_profiler){
    if (!excl_profiler)
        return;

    free(excl_profiler);
}

static int find_binaryfile(struct pt_profiler *profiler,
                           const char *filename,
                           struct binaryfile **binary){
    if (!profiler || !filename || !binary){
        return 0;
    }

    struct binaryfile *bin = profiler->binary_list;
    while(bin){
        if (0 == strcmp(filename, bin->filename))
            break;
        bin = bin->next;
    }
    
    if (!bin){
        bin = malloc(sizeof(struct binaryfile));
        if (!bin)
            return 0;
        memset(bin, 0, sizeof(*bin));
        bin->filename = malloc(strlen(filename)+1);
        if (!bin->filename){
            free(bin);
            return 0;
        }
        strcpy(bin->filename, filename);
        bfd_desc_init(bin->filename, &bin->desc);

        bin->next = profiler->binary_list;
        profiler->binary_list = bin;
    }
    
    *binary = bin;
    return 1;
}

static int find_sourcefile(struct pt_profiler *profiler,
                           const char *filename,
                           struct sourcefile **source){
    if (!profiler || !filename || !source)
        return 0;
    
    struct sourcefile *src = profiler->source_list;
    while(src){
        if (0 == strcmp(filename, src->filename))
            break;
        src = src->next;
    }

    if (!src){
        src = malloc(sizeof(struct sourcefile));
        if (!src)
            return 0;
        memset(src, 0, sizeof(*src));
        src->filename = malloc(strlen(filename) + 1);
        if (!src->filename){
            free(src);
            return 0;
        }
        strcpy(src->filename, filename);
        src->cnt = malloc(CNT_SIZE * INITIAL_LINE_VOL);
        if (!src->cnt){
            free(src->filename);
            free(src);
            return 0;
        }
        memset(src->cnt, 0, CNT_SIZE * INITIAL_LINE_VOL);
        src->vol = INITIAL_LINE_VOL;
        src->next = profiler->source_list;
        profiler->source_list = src;
    }
    *source = src;
    return 1;
}

static int find_function(struct sourcefile *source,
                         const char *functionname,
                         struct function **func){
    if (!source || !functionname || !func)
        return 0;
    
    struct function *f = source->func_list;
    while(f){
        if (0 == strcmp(f->functionname, functionname))
            break;
        f = f->next;
    }

    if (!f){
        f = malloc(sizeof(struct function));
        if (!f)
            return 0;
        memset(f, 0, sizeof(*f));
        f->functionname = malloc(strlen(functionname)+1);
        strcpy(f->functionname, functionname);
        if (!f->functionname)
            return 0;
        f->next = source->func_list;
        source->func_list = f;
    }
    *func = f;
    return 1;
}


static int cnt_line(struct sourcefile *source, uint32_t line){
    if (!source)
        return -1;
    
    uint32_t *cnt = source->cnt;
    uint32_t vol = source->vol;
    
    if (vol <= line){
        while (vol <= line)
            vol *= 2;
    
        cnt = malloc(vol * CNT_SIZE);
        if (!cnt)
            return -1;
        memset(cnt, 0, vol * CNT_SIZE);
        memcpy(cnt, source->cnt, source->vol * CNT_SIZE);
        free(source->cnt);
        source->cnt = cnt;
        source->vol = vol;
    }
    cnt[line]++;
}

static int cnt_function(struct function *func){
    if (!func)
        return -1;
    
    func->cnt++;
    return 0;
}

static int call_stack;
int pt_profiler_add(struct pt_profiler *profiler, 
                    struct pt_excl_profiler *excl_profiler,
                    struct pt_insn *insn){
    if (!profiler || !excl_profiler || !insn){
        fprintf(stderr, "profiler: internal error\n");
        return -1;
    }
    
    if (!insn->filename){
        fprintf(stderr, "profiler: insn belongs to nowhere\n");
        return -1;
    }

    struct binaryfile **binary = &excl_profiler->binary;
    if (!(*binary) || strcmp((*binary)->filename, insn->filename)){
        if (!find_binaryfile(profiler, insn->filename, binary)){
            fprintf(stderr, "profiler: faile to find binaryfile\n");
            return -1;
        }
    }
    
    struct line_info line;
    if ( !translate_addresses(&(*binary)->desc, insn->offset, &line)
         || !line.filename || !line.functionname)
        return -1;
    
    
    struct sourcefile **source = &excl_profiler->source;
    if (!(*source) || strcmp((*source)->filename, line.filename)){
        if (!find_sourcefile(profiler, line.filename, source)){
            fprintf(stderr, "profiler: fail to find soucefile\n");
        }
    }

    if (line.line != excl_profiler->line){
        cnt_line(*source, line.line);
        excl_profiler->line = line.line;
    }

    struct function **func = &excl_profiler->func;
    if (excl_profiler->call){
        excl_profiler->call = 0;
        for (int i = 0; i < call_stack; i++){
            printf("\t");
        }
        printf("%s\n", line.functionname);
        if (!find_function(*source, line.functionname, func)){
            fprintf(stderr, "profiler: fail to find function\n");
            return -1;
        }
        cnt_function(*func);
    }

    if (insn->iclass == ptic_call || insn->iclass == ptic_far_call){
        call_stack++;
        excl_profiler->call = 1;
    }else if (insn->iclass == ptic_far_return || insn->iclass == ptic_return){
        call_stack--;
        excl_profiler->call = 0;
    }
    
    return 0;
}

void pt_profiler_print(struct pt_profiler *profiler){
    struct sourcefile *source = profiler->source_list;
    
    while(source){
        printf("%s\n", source->filename);
        for (int i = 0; i < source->vol; i++){
            if (source->cnt[i])
                printf("\t\tline:%d\t\t%d\n",i, source->cnt[i]);
        }
        struct function *func = source->func_list;
        while(func){
            printf("\t\t\t%s:  %d\n", func->functionname, func->cnt);
            func = func->next;    
        }
        source = source->next;
    }
}
