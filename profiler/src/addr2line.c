#include "addr2line.h"

static int slurp_symtab(struct bfd_desc *desc)
{
    long storage;
    long symcount;
    bfd_boolean dynamic = FALSE;

    if ((bfd_get_file_flags (desc->abfd) & HAS_SYMS) == 0)
        return 0;

    storage = bfd_get_symtab_upper_bound (desc->abfd);
    if (storage == 0){
      storage = bfd_get_dynamic_symtab_upper_bound (desc->abfd);
      dynamic = TRUE;
    }
    if (storage < 0)
        return -1;//bfd_fatal (bfd_get_filename (abfd));

    desc->syms = (asymbol **) malloc (storage); //xmalloc
    if (dynamic)
        symcount = bfd_canonicalize_dynamic_symtab (desc->abfd, desc->syms);
    else
        symcount = bfd_canonicalize_symtab (desc->abfd, desc->syms);
    if (symcount < 0)
        return -1;//bfd_fatal (bfd_get_filename (abfd));
    return 0;
}

/* Look for an address in a section.  This is called directly or via
   bfd_map_over_sections. */
static void
find_address_in_section (bfd *abfd, asection *section,
                         void *data)
{
    bfd_vma vma;
    bfd_size_type size;

    if (!data)
        return;
    struct wrapped *arg = (struct wrapped *)data;
    struct line_info *result = arg->result;
    asymbol **syms = arg->syms;
    if (!result)
        return;

    if (arg->found)
        return;

    if ((bfd_get_section_flags (abfd, section) & SEC_ALLOC) == 0)
        return;

    bfd_vma pc = arg->pc;
    vma = bfd_get_section_vma (abfd, section);
    if (pc < vma)
        return;

    size = bfd_get_section_size (section);
    if (pc >= vma + size)
        return;

    arg->section = section;

    arg->found = bfd_find_nearest_line_discriminator (abfd, section, syms, pc - vma, 
                                            &result->filename, &result->functionname, 
                                            &result->line, &result->discriminator);
}

int
translate_addresses (struct bfd_desc *desc, unsigned long addr, 
                     struct line_info *result)
{
    if (!result)
        return FALSE;
    memset(result, 0, sizeof(*result));

    bfd_vma pc = addr;

    if (bfd_get_flavour (desc->abfd) == bfd_target_elf_flavour)
    {
        bfd_vma sign = (bfd_vma) 1 << (bfd_get_arch_size (desc->abfd) - 1);

        pc &= (sign << 1) - 1;
        if (bfd_get_sign_extend_vma (desc->abfd))
            pc = (pc ^ sign) - sign;
    }
    
    struct wrapped arg;
    arg.found = FALSE;
    arg.result = result;
    arg.syms = desc->syms;
    arg.pc = pc;

    if (desc->section)
        find_address_in_section(desc->abfd, desc->section, &arg);

    if (!arg.found){
        bfd_map_over_sections (desc->abfd, find_address_in_section, &arg);
        desc->section = arg.section;
    }

    return arg.found;
}

static long
get_file_size (const char * file_name)
{
    struct stat statbuf;
  
    if (stat (file_name, &statbuf) < 0)
    {
        if (errno == ENOENT)
	        fprintf (stderr, "BFD: '%s': No such file\n", file_name);
        else
	        fprintf (stderr, "BFD Warning: could not locate '%s'.  reason: %s\n",
		        file_name, strerror (errno));
    }  
    else if (! S_ISREG (statbuf.st_mode))
        fprintf (stderr, "BFD Warning: '%s' is not an ordinary file\n", file_name);
    else if (statbuf.st_size < 0)
        fprintf (stderr, "BFD Warning: '%s' has negative size, probably it is too large\n",
               file_name);
    else
        return statbuf.st_size;

    return (long) -1;
}

/* Process a file. */
static int 
process_file (const char *file_name, struct bfd_desc *desc)
{
    char **matching;

    if (get_file_size (file_name) < 1){
        return -1;
    }

    desc->abfd = bfd_openr (file_name, NULL);
    if (desc->abfd == NULL){
        return -1;
    }
    
    /* Decompress sections.  */
    desc->abfd->flags |= BFD_DECOMPRESS;

    if (bfd_check_format (desc->abfd, bfd_archive))
        return -1;

    if (! bfd_check_format_matches (desc->abfd, bfd_object, &matching))
    {
        if (bfd_get_error () == bfd_error_file_ambiguously_recognized)
        {
            fprintf (stderr, "BFD format not surpported. Support: ");
            while(matching)
                fprintf(stderr, "%s ", *matching++);
            fprintf(stderr, "\n");
            free (matching);
        }
        bfd_close(desc->abfd);
        return -1;
    }
    
    slurp_symtab (desc);
    return 0;
}

int bfd_desc_init(const char *file_name, struct bfd_desc *desc)
{
    if (!desc || !file_name)
        return -1;
    
    bfd_init ();

    return process_file (file_name, desc);
}

void bfd_desc_free(struct bfd_desc *desc){
    if (!desc)
        return;
    
    if (desc->abfd)
        bfd_close(desc->abfd);
    if (desc->syms)
        free(desc->syms);
    memset(desc, 0, sizeof(*desc));
}