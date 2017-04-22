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

#include "values.h"
#include "dynamic_segment.h"
#include "utility.h"
#include "el.h"
#include "print.h"

extern struct {
  const char* n;
  void* f;
} T[];

static int mapped_area[999];

void undefined() {
  el_error("undefined function is called\n");
}

static void do_relocate(const char *reloc_type, Elf32_Rel *rel, int relsz,
              Elf32_Sym *dsym, char *dstr);

void relocate(char* elf, Elf32_Phdr *phdr){
  Elf32_Dyn *dyn = (Elf32_Dyn *)(elf + phdr->p_offset);
  int i;
  int relsz = get_relsz(dyn);
  int pltrelsz = get_pltrelsz(dyn);
  int needed[999]={};
  char *dstr = get_dstr(dyn);
  Elf32_Sym *dsym = get_dsym(dyn);
  Elf32_Rel *rel = get_rel(dyn);
  Elf32_Rel *pltrel = get_pltrel(dyn);

  el_print("PT_DYNAMIC");

  get_needed(dyn, needed);
  for ( i=0; *(needed+i) != -1; i++){
    dlopen(dstr + *(needed+i), RTLD_NOW | RTLD_GLOBAL);
  }
  
  dl_iterate_phdr(callback, &mapped_area);  
  for ( i=0; *(mapped_area+i); i++)
    el_print("PT_LOAD:%x\n", *(mapped_area+i));

  do_relocate(   "rel",    rel,    relsz, dsym, dstr);
  do_relocate("pltrel", pltrel, pltrelsz, dsym, dstr);
}

static void do_copy_symbol(Elf32_Rel *rel, int relsz, Elf32_Sym *dsym, char *dstr, int val, char *name, unsigned int base){
  int i, entry_num = relsz/sizeof(Elf32_Rel);
  for( i = 0; i < entry_num; rel++, i++){
     unsigned int *addr = (unsigned int *)(rel->r_offset + base);
     Elf32_Sym *sym = dsym + ELF32_R_SYM(rel->r_info);
     int type = ELF32_R_TYPE(rel->r_info);
     char *sname = dstr + sym->st_name;

     
     if(type == 6 && !strcmp(sname, name)){
       el_print("**************%x %p %s %d => %x\n",base,  addr, sname, type, val);
       unsigned int tmp = (unsigned int)addr & 0xfffff000;
       mprotect((void*)tmp, 0x1000, PROT_WRITE|PROT_READ|PROT_EXEC);
       *addr = val;
       mprotect((void*)tmp, 0x1000, PROT_READ);
     }
  }
}

static void copy_symbol(int val, char *name){
  int i;
  
  for ( i=1; *(mapped_area+i); i++){
    Elf32_Phdr *ddyn=segHeadAddress((char*)*(mapped_area+i), PT_DYNAMIC);
    Elf32_Dyn *dyn = (Elf32_Dyn *)(mapped_area[i] + ddyn->p_vaddr);
    do_copy_symbol( get_rel(dyn), get_relsz(dyn), get_dsym(dyn), get_dstr(dyn), val, name, *(mapped_area+i) );
  }
}

static void do_relocate(const char *reloc_type, Elf32_Rel *rel, int relsz,
              Elf32_Sym *dsym, char *dstr){
  int i, entry_num = relsz/sizeof(Elf32_Rel);
  for( i = 0; i < entry_num; rel++, i++){
  
    int *val=0, *addr = (int*)(rel->r_offset + (so_flag?so_base:0));
    Elf32_Sym *sym = dsym + ELF32_R_SYM(rel->r_info);
    int type = ELF32_R_TYPE(rel->r_info);
    char *sname = dstr + sym->st_name;
    int k;

    /* シンボルのサイズを取得 */
    int sym_size = sym->st_size;

    
    for(k=0;T[k].n;k++){
      if(!strcmp(sname,T[k].n)){
         val= T[k].f;
         break;
      }
    }

    if(!val){
      val= dlsym(RTLD_DEFAULT, sname);
    }

    el_print("%s: %p %s(%d) %d => %p\n", 
           reloc_type, addr, sname, ELF32_R_SYM(rel->r_info), type, val);
    switch ( type ) {
      case 1: {
        if (val){
          *addr += (int)val;
        } else {
          *addr += sym->st_value + (so_flag?so_base:0);
        }
        break;
      }
      case R_386_COPY: {
        if (val) {
          /* 取得しておいたサイズの分だけ値をコピーする */
          unsigned int l;
          for(l = 0; l < sym_size / sizeof(int); l++) {
            *(addr + l) = *(val + l);
          }
          copy_symbol((int)addr, sname);
          el_print("%s\n", sname);
        } else {
          el_print("undefined: %s\n", sname);
          abort();
        }
        break;
      }
      case 6: {
        if (val) {
          *addr= (int)val;
        } else {
          el_print("undefined data %s\n", sname);
        }
        break;
      }
      case 7: {
        if (val) {
          *addr= (int)val;
          el_print("sname: %s, %p\n",sname, (char *)val);
        } else {
          *addr= (int)&undefined;
        }
        break;
      }
      case 8: {
        *addr += (int)so_base;
        break;
      }
    }
  }
}
