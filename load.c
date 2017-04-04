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
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/mman.h>
#include "values.h"
#include "el_mv1.h"
#include "print.h"


void load(Elf32_Phdr *phdr, int fd){
  Elf32_Phdr *tmp = malloc(sizeof(Elf32_Phdr));
  unsigned int pafsize;

  if (so_flag == 1) {
    phdr->p_vaddr += so_base;
  }
  int prot= 0;
  if (phdr->p_flags & PF_X)
    prot |= PROT_EXEC;
  if (phdr->p_flags & PF_W)
    prot |= PROT_WRITE;
  if (phdr->p_flags & PF_R)
    prot |= PROT_READ;
  
  tmp->p_memsz = phdr->p_memsz + ( phdr->p_vaddr & 0xfff );
  tmp->p_filesz = phdr->p_filesz + ( phdr->p_vaddr & 0xfff );
  tmp->p_offset = phdr->p_offset - (phdr->p_vaddr & 0xfff);
  tmp->p_vaddr = phdr->p_vaddr & ~0xfff;
  pafsize = (tmp->p_filesz + 0xfff ) & ~0xfff;
  tmp->p_memsz = ( tmp->p_memsz + 0xfff ) & ~0xfff;
  
  el_print("PT_LOAD memsz=%d filesz=%d flags=%d vaddr=%x prot=%d offset=%d\n",
         tmp->p_memsz, tmp->p_filesz, phdr->p_flags, tmp->p_vaddr, prot, tmp->p_offset);
  if (mmap((void*)tmp->p_vaddr, pafsize, prot, MAP_FILE|MAP_PRIVATE|MAP_FIXED,
               fd, tmp->p_offset) == MAP_FAILED) {
    el_error("mmap(file)");
  }
  if ((prot & PROT_WRITE)) {
    el_print("%p\n", (char*)tmp->p_vaddr);
    for (; tmp->p_filesz < pafsize; tmp->p_filesz++) {
      char* p= (char*)tmp->p_vaddr;
      p[tmp->p_filesz]= 0;
    }
    if (tmp->p_filesz != tmp->p_memsz) {
      if (mmap((void*)(tmp->p_vaddr + tmp->p_filesz),
               tmp->p_memsz - tmp->p_filesz, prot, MAP_ANON|MAP_PRIVATE,
               -1, 0) == MAP_FAILED) {
        el_error("mmap(anon)");
      }
    }
  }
}
