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

#ifndef __EL_UTILITY
#define __EL_UTILITY

#include<elf.h>
#include<link.h>

Elf32_Shdr *secHeadAddress(char *head, char *str);
Elf32_Phdr *segHeadAddress(char *head, unsigned int type);

int callback(struct dl_phdr_info *info, size_t size, void *data);

#endif
