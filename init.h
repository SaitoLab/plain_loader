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

#ifndef __EL_INIT
#define __EL_INIT

#include<elf.h>

#ifdef EL_COUNTER

#include "../counter/init.h"

#endif

void el_init(Elf32_Ehdr *ehdr);

#endif
