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

#ifndef __EL_DYNAMICSEGMENT
#define __EL_DYNAMICSEGMENT

#include<elf.h>

void get_needed(Elf32_Dyn *head, int *list);
Elf32_Rel *get_rel(Elf32_Dyn *head);
Elf32_Rel *get_pltrel(Elf32_Dyn *head);
Elf32_Sym *get_dsym(Elf32_Dyn *head);
int get_relsz(Elf32_Dyn *head);
int get_pltrelsz(Elf32_Dyn *head);
char *get_dstr(Elf32_Dyn *head);

#endif
