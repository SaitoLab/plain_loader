/*
    Copyright (c) 2016 Meiji University Information Security Laboratory (SaitoLab)

    Released under the MIT license
    http://opensource.org/licenses/mit-license.php

    We developed this software by making some changes and additions to Shinichiro Hamaji's one, which is also released under the MIT license.
    The original copyright and license are shown below: 

    Copyright (c) 2015 Shinichiro Hamaji

    Released under the MIT license
    http://opensource.org/licenses/mit-license.php

    Here is Shinichiro Hamaji's license page: 
    https://github.com/shinh/tel_ldr/blob/master/LICENSE
*/

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <elf.h>
#include <unistd.h> 
#include <time.h>

#include "link.h"

#include "dynamic.h"
#include "values.h"
#include "load.h"
#include "replace.h"
#include "init.h"
#include "print.h"


static int g_argc;
static char** g_argv;
/* for shared object */
int so_flag=0; /* flag whether shared object or not */
int so_base= 0x8048000; /* base address for load shared object */

static int H__libc_start_main(int (*m)(int, char**, char**),
                       int argc, char** argv,
                       void (*init)(void)/*, void (*fini)(void),
                       void (*rtld_fini)(void),
                       void (*stack_end)*/
                  
                       ) {
  char **envp= g_argc+g_argv+1;

  if (g_argc) {
    argc= g_argc;
    argv= g_argv;
  }
  (*init)(); 
  exit(m(argc, argv, envp));
}

struct {
  const char* n;
  void* f;
} T[]= {
#define H(n) { #n, (void*)&H ## n },
#include "replace.data"
  {0,0},
};

int main(int argc, char* argv[]) {
  Elf32_Ehdr *ehdr;
  Elf32_Phdr *phdr;
  int i;
  int fd, len;
  char* elf;
  int* ph;

  /* for setuid program */
  struct stat sb; /* state buffer of protected binary */
  seteuid(getuid()); /* load of protected binary is executed as user */

  ElfW(Phdr) *addr_of_phdr_seg=NULL;

  if (argc < 2)
    el_error("Usage: el <elf>");
  el_print("loading %s\n", argv[1]);
  fd= open(argv[1], O_RDONLY);
  if (fd < 0)
    el_error("Usage: el <elf>"); 
  len= lseek(fd, 0, SEEK_END);
  elf = (char*)malloc(len);
  ehdr = (Elf32_Ehdr*)elf;
  el_print("elf:%p, ehdr:%p\n", elf, ehdr);
  lseek(fd, 0, SEEK_SET);
  read(fd, elf, len);

  if( memcmp( ehdr->e_ident, ELFMAG, SELFMAG ) != 0)
    el_error("not elf");

  /* validate whether i386 or not */
  if ( ehdr->e_machine != EM_386 ) {
    el_error(ERRM);
  }

  /* check whether shared object or not */
  if ( ehdr->e_type == ET_DYN ){
    el_print("this is shared object: %s\n", argv[1]);
    so_flag=1;
  }
  
  /* if this file is not shared object and not exec file, error */
  else if ( ehdr->e_type != ET_EXEC ){
    el_error(ERRM);
  }

  if (so_flag == 1){
    ehdr->e_entry += so_base;
  }

  ph= (int*)(elf + ehdr->e_phoff);
  for (i = 0; i < ehdr->e_phnum; i++) {
    phdr = (Elf32_Phdr *)( elf + ehdr->e_phoff + ehdr->e_phentsize * i );
    el_print("elf: %p, e_phoff: %p, e_phentsize: %p, pdhr: %p\n",elf, ehdr->e_phoff, ehdr->e_phentsize, phdr);
    switch (ph[0]) {
      case 1: {
        load(phdr, fd);
        break;
      }
      case 2: {
        relocate(elf, phdr);
        break;
      }

      /* for rewrite link_map */
      case 6: {
        addr_of_phdr_seg = (ElfW(Phdr) *)ph[2];
        break;
      }
 
      default: {
        el_print("unknown PT %d\n", ph[0]);
        break;
      }
    }
    ph += PHSEG_OFFSET;
  }

  g_argc= argc-1;
  g_argv= argv+1;
  el_print("start!: %s %x\n", argv[1], ehdr->e_entry);

  /* for rewrite link_map */
  struct link_map *link_map = (struct link_map *)(*((ElfW(Addr) *)dlsym(RTLD_DEFAULT, "_r_debug") + 1)); /* head addr of the link_map list */

  link_map->l_phdr = addr_of_phdr_seg;
  link_map->l_phnum = ehdr->e_phnum;
  link_map->l_entry = ehdr->e_entry;

  /* for setuid program */
  /* if protected binary is set the setuid bit, the code is executed as root */
  if(stat(argv[1], &sb) == 0) {
    if(sb.st_mode & S_ISUID) {
      seteuid(0);
    }
  }

  el_init(ehdr);
  ((void*(*)())ehdr->e_entry)();
  return 1;
}
