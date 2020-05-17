#include "bfd.h"
#include <stdio.h>
#include <bfd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

struct bfd_desc{
    bfd *abfd;
    asymbol **syms;
    asection *section;
};

/* filename/functioname pointers that cannot be freed */
struct line_info{
    const char *filename;
    const char *functionname;
    unsigned int line;
    unsigned int discriminator;
};

/* the wrapped void *argument passed onto find_address_in_section */
struct wrapped{
    struct line_info *result;
    bfd_vma pc;
    bfd_boolean found;
    asymbol **syms;
    asection *section;
};

extern int translate_addresses (struct bfd_desc *desc, unsigned long addr,
                     struct line_info *result);

extern int bfd_desc_init(const char *file_name, struct bfd_desc *desc);

extern void bfd_desc_free(struct bfd_desc *desc);
