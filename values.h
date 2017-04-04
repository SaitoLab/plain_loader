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

#ifndef __ELLOADER
#define __ELLOADER

#ifdef __x86_64__
  #define ELF_ARCH 0x3e0002
  #define ERRM "not x86_64"
  #define ENTRY_OFFSET 24
  #define PHOFF_OFFSET 32
  #define PHNUM_OFFSET 54
  #define PH1 2
  #define PH2 4
  #define PH3 8
  #define PH4 10
  #define PH5 1
  #define PH6 12
  #define DVAL_OFFSET 8
  #define DYN_OFFSET 16
  #define REL 7
  #define RELSZ 8
  #define RELENT 9
  #define PHSEG_OFFSET 14
  #define INFO_SHIFT 32
  #define DS_OFFSET 24
#elif __GNUC__ || __linux__ || __i386__
  #define ELF_ARCH 0x30002
  #define ERRM "not i386"
  #define ENTRY_OFFSET 24
  #define PHOFF_OFFSET 28
  #define PHNUM_OFFSET 42
  #define PH1 1
  #define PH2 2
  #define PH3 4
  #define PH4 5
  #define PH5 6
  #define PH6 7
  #define DVAL_OFFSET 4
  #define DYN_OFFSET 8
  #define REL 17
  #define RELSZ 18
  #define RELENT 19
  #define PHSEG_OFFSET 8
  #define INFO_SHIFT 8
  #define DS_OFFSET 16
#else
  #define ERRM "not supported"
#endif


#endif
