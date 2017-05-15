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

#include "dynamic_segment.h"

static void get_index(Elf32_Dyn *head, int dt, int *array);

static void get_index(Elf32_Dyn *head, int dt, int *array){
  int i, count = 0;
  for( i = 0; (head+i)->d_tag != DT_NULL; i++){
    if( (head+i)->d_tag == dt ){
      *(array + count) = i;
      count++;
    }
  }
  *(array + count) = -1;
}

void get_needed(Elf32_Dyn *head, int *list){
  int i;
  get_index(head, DT_NEEDED, list);
  for( i = 0; *(list+i) != -1; i++){
    *(list+i) = (int)(head+ *(list+i))->d_un.d_val;
  }
}

Elf32_Rel *get_rel(Elf32_Dyn *head){
  int array[2];
  get_index(head, DT_REL, array);
  return (Elf32_Rel *)( (head+array[0])->d_un.d_ptr );
}

Elf32_Rel *get_pltrel(Elf32_Dyn *head){
  int relsz = get_relsz(head);
  char *rel = (char *)get_rel(head);
  return (Elf32_Rel *)(rel + relsz);
}

Elf32_Sym *get_dsym(Elf32_Dyn *head){
  int array[2];
  get_index(head, DT_SYMTAB, array);
  return (Elf32_Sym *)( (head+array[0])->d_un.d_ptr );
}

int get_relsz(Elf32_Dyn *head){
  int array[2];
  get_index(head, DT_RELSZ, array);
  return (int)( (head+array[0])->d_un.d_val );
}

int get_pltrelsz(Elf32_Dyn *head){
  int array[2];
  get_index(head, DT_PLTRELSZ, array);
  return (int)( (head+array[0])->d_un.d_val );
}

char *get_dstr(Elf32_Dyn *head){
  int array[2];
  get_index(head, DT_STRTAB, array);
  return (char *)( (head+array[0])->d_un.d_ptr );
}
