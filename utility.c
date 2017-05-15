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
#include <link.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <elf.h>

#include "print.h"

Elf32_Shdr *secHeadAddress(char *head, char *str){
  int i;
  char *sname;
  Elf32_Ehdr *ehdr = (Elf32_Ehdr *)head;
  Elf32_Shdr *shdr, *shstr;
  
  shstr = (Elf32_Shdr *)(head + ehdr->e_shoff + ehdr->e_shentsize * ehdr->e_shstrndx);
  el_print("%p\n", shstr);  
  for(i = 0; i < ehdr->e_shnum ; i++){
    shdr = (Elf32_Shdr *)(head + ehdr->e_shoff + ehdr->e_shentsize * i);
    sname = (char *)(head + shstr->sh_offset + shdr->sh_name);
    if(!strcmp(sname,str))
      return shdr; 
  }
  return NULL;
}

Elf32_Phdr *segHeadAddress(char *head, unsigned int type){
  int i;
  Elf32_Ehdr *ehdr = (Elf32_Ehdr *)head;
  Elf32_Phdr *phdr;
  for(i = 0; i < ehdr->e_phnum; i++){
    phdr = (Elf32_Phdr *)(head + ehdr->e_phoff + ehdr->e_phentsize * i);
    if(phdr->p_type == type)return phdr;
  }
  return NULL;
}

int callback(struct dl_phdr_info *info, size_t size, void *data)
{
  int j, *addr=(int *)data;
  for (j = 0; j < info->dlpi_phnum; j++){
    if( info->dlpi_phdr[j].p_type == PT_LOAD ){
      if(sizeof(struct dl_phdr_info) != size) return 1;
      while(*addr)addr++;
      *addr = (int)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
      break;
    }
  }
  return 0;
}
