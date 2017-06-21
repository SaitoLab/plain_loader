#ifndef	_PRIVATE_LINK_H
#define	_PRIVATE_LINK_H	1

#ifdef _LINK_H
# error this should be impossible
#endif

/* Get most of the contents from the public header, but we define a
	 different `struct link_map' type for private use.	The la_objopen
	 prototype uses the type, so we have to declare it separately.	*/
#define link_map	link_map_public
#define la_objopen	la_objopen_wrongproto
#include <link.h>
#undef	link_map
#undef	la_objopen

struct link_map;

//#define _GNU_SOURCE
//#include <dlfcn.h> // for Lmid_t 

#include "linkmap.h"

// FIXME glibc/sysdeps/generic/dl-dtprocnum.h
#define DT_THISPROCNUM	0

// FIXME glibc/sysdeps/generic/dl-lookupcfg.h
/* The type of the return value of fixup/profile_fixup.	*/
#define DL_FIXUP_VALUE_TYPE ElfW(Addr)

#include "stddef.h"

/* Some internal data structures of the dynamic linker used in the
	 linker map.	We only provide forward declarations.	*/
// FIXME
struct libname_list;	//linkmap.h
// FIXME glibc/sysdeps/generic/ldsodefs.h
struct r_found_version;	//linkmap.h
// FIXME
struct r_search_path_elem;	//linkmap.h

/* Forward declaration.	*/
struct link_map;

/* Structure to describe a single list of scope elements.	The lookup
	 functions get passed an array of pointers to such structures.	*/
struct r_scope_elem
{
	/* Array of maps for the scope.	*/
	struct link_map **r_list;
	/* Number of entries in the scope.	*/
	unsigned int r_nlist;
};


/* Structure to record search path and allocation mechanism.	*/
struct r_search_path_struct
	{
		struct r_search_path_elem **dirs;
		int malloced;
	};


/* Structure describing a loaded shared object.	The `l_next' and `l_prev'
	 members form a chain of all the shared objects loaded at startup.
	 These data structures exist in space used by the run-time dynamic linker;
	 modifying them may have disastrous results.
	 This data structure might change in future, if necessary.	User-level
	 programs must avoid defining objects of this type.	*/

struct link_map
	{
		/* These first few members are part of the protocol with the debugger.
			 This is the same format used in SVR4.	*/

		ElfW(Addr) l_addr;		/* Base address shared object is loaded at.	*/
		char *l_name;		/* Absolute file name object was found in.	*/
		ElfW(Dyn) *l_ld;		/* Dynamic section of the shared object.	*/
		struct link_map *l_next, *l_prev; /* Chain of loaded objects.	*/

		/* All following members are internal to the dynamic linker.
			 They may change without notice.	*/

		/* This is an element which is only ever different from a pointer to
			 the very same copy of this type for ld.so when it is used in more
			 than one namespace.	*/
		struct link_map *l_real;

		/* Number of the namespace this link map belongs to.	*/
		Lmid_t l_ns;

		struct libname_list *l_libname;
		/* Indexed pointers to dynamic section.
			 [0,DT_NUM) are indexed by the processor-independent tags.
			 [DT_NUM,DT_NUM+DT_THISPROCNUM) are indexed by the tag minus DT_LOPROC.
			 [DT_NUM+DT_THISPROCNUM,DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM) are
			 indexed by DT_VERSIONTAGIDX(tagvalue).
			 [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM,
	DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM) are indexed by
			 DT_EXTRATAGIDX(tagvalue).
			 [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM,
	DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM) are
			 indexed by DT_VALTAGIDX(tagvalue) and
			 [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM,
	DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM+DT_ADDRNUM)
			 are indexed by DT_ADDRTAGIDX(tagvalue), see <elf.h>.	*/

		ElfW(Dyn) *l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
					+ DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
		const ElfW(Phdr) *l_phdr;	/* Pointer to program header table in core.	*/
		ElfW(Addr) l_entry;		/* Entry point location.	*/
		ElfW(Half) l_phnum;		/* Number of program header entries.	*/
		ElfW(Half) l_ldnum;		/* Number of dynamic segment entries.	*/

		/* Array of DT_NEEDED dependencies and their dependencies, in
			 dependency order for symbol lookup (with and without
			 duplicates).	There is no entry before the dependencies have
			 been loaded.	*/
		struct r_scope_elem l_searchlist;

		/* We need a special searchlist to process objects marked with
			 DT_SYMBOLIC.	*/
		struct r_scope_elem l_symbolic_searchlist;

		/* Dependent object that first caused this object to be loaded.	*/
		struct link_map *l_loader;

		/* Array with version names.	*/
		struct r_found_version *l_versions;
		unsigned int l_nversions;

		/* Symbol hash table.	*/
		Elf_Symndx l_nbuckets;
		Elf32_Word l_gnu_bitmask_idxbits;
		Elf32_Word l_gnu_shift;
		const ElfW(Addr) *l_gnu_bitmask;
		union
		{
			const Elf32_Word *l_gnu_buckets;
			const Elf_Symndx *l_chain;
		};
		union
		{
			const Elf32_Word *l_gnu_chain_zero;
			const Elf_Symndx *l_buckets;
		};

		unsigned int l_direct_opencount; /* Reference count for dlopen/dlclose.	*/
		enum			/* Where this object came from.	*/
			{
				lt_executable,		/* The main executable program.	*/
				lt_library,		/* Library needed by main executable.	*/
				lt_loaded		/* Extra run-time loaded shared object.	*/
			} l_type:2;
		unsigned int l_relocated:1;	/* Nonzero if object's relocations done.	*/
		unsigned int l_init_called:1; /* Nonzero if DT_INIT function called.	*/
		unsigned int l_global:1;	/* Nonzero if object in _dl_global_scope.	*/
		unsigned int l_reserved:2;	/* Reserved for internal use.	*/
		unsigned int l_phdr_allocated:1; /* Nonzero if the data structure pointed
					to by `l_phdr' is allocated.	*/
		unsigned int l_soname_added:1; /* Nonzero if the SONAME is for sure in
							the l_libname list.	*/
		unsigned int l_faked:1;	/* Nonzero if this is a faked descriptor
					 without associated file.	*/
		unsigned int l_need_tls_init:1; /* Nonzero if GL(dl_init_static_tls)
							 should be called on this link map
							 when relocation finishes.	*/
		unsigned int l_auditing:1;	/* Nonzero if the DSO is used in auditing.	*/
		unsigned int l_audit_any_plt:1; /* Nonzero if at least one audit module
							 is interested in the PLT interception.*/
		unsigned int l_removed:1;	/* Nozero if the object cannot be used anymore
					 since it is removed.	*/
		unsigned int l_contiguous:1; /* Nonzero if inter-segment holes are
						mprotected or if no holes are present at
						all.	*/
		unsigned int l_symbolic_in_local_scope:1; /* Nonzero if l_local_scope
						 during LD_TRACE_PRELINKING=1
						 contains any DT_SYMBOLIC
						 libraries.	*/

		/* Collected information about own RPATH directories.	*/
		struct r_search_path_struct l_rpath_dirs;

		/* Collected results of relocation while profiling.	*/
		struct reloc_result
		{
			DL_FIXUP_VALUE_TYPE addr;
			struct link_map *bound;
			unsigned int boundndx;
			uint32_t enterexit;
			unsigned int flags;
		} *l_reloc_result;

		/* Pointer to the version information if available.	*/
		ElfW(Versym) *l_versyms;

		/* String specifying the path where this object was found.	*/
		const char *l_origin;

		/* Start and finish of memory map for this object.	l_map_start
			 need not be the same as l_addr.	*/
		ElfW(Addr) l_map_start, l_map_end;
		/* End of the executable part of the mapping.	*/
		ElfW(Addr) l_text_end;

		/* Default array for 'l_scope'.	*/
		struct r_scope_elem *l_scope_mem[4];
		/* Size of array allocated for 'l_scope'.	*/
		size_t l_scope_max;
		/* This is an array defining the lookup scope for this link map.
			 There are initially at most three different scope lists.	*/
		struct r_scope_elem **l_scope;

		/* A similar array, this time only with the local scope.	This is
			 used occasionally.	*/
		struct r_scope_elem *l_local_scope[2];

		/* This information is kept to check for sure whether a shared
			 object is the same as one already loaded.	*/
		dev_t l_dev;
		ino64_t l_ino;

		/* Collected information about own RUNPATH directories.	*/
		struct r_search_path_struct l_runpath_dirs;

		/* List of object in order of the init and fini calls.	*/
		struct link_map **l_initfini;
		/* The init and fini list generated at startup, saved when the
			 object is also loaded dynamically.	*/
		struct link_map **l_orig_initfini;

		/* List of the dependencies introduced through symbol binding.	*/
		struct link_map_reldeps
			{
	unsigned int act;
	struct link_map *list[];
			} *l_reldeps;
		unsigned int l_reldepsmax;

		/* Nonzero if the DSO is used.	*/
		unsigned int l_used;

		/* Various flag words.	*/
		ElfW(Word) l_feature_1;
		ElfW(Word) l_flags_1;
		ElfW(Word) l_flags;

		/* Temporarily used in `dl_close'.	*/
		int l_idx;

		//FIXME linkmap.h
		struct link_map_machine l_mach;

		struct
		{
			const ElfW(Sym) *sym;
			int type_class;
			struct link_map *value;
			const ElfW(Sym) *ret;
		} l_lookup_cache;

		/* Thread-local storage related info.	*/

		/* Start of the initialization image.	*/
		void *l_tls_initimage;
		/* Size of the initialization image.	*/
		size_t l_tls_initimage_size;
		/* Size of the TLS block.	*/
		size_t l_tls_blocksize;
		/* Alignment requirement of the TLS block.	*/
		size_t l_tls_align;
		/* Offset of first byte module alignment.	*/
		size_t l_tls_firstbyte_offset;
#ifndef NO_TLS_OFFSET
# define NO_TLS_OFFSET	0
#endif
#ifndef FORCED_DYNAMIC_TLS_OFFSET
# if NO_TLS_OFFSET == 0
#	define FORCED_DYNAMIC_TLS_OFFSET 1
# elif NO_TLS_OFFSET == -1
#	define FORCED_DYNAMIC_TLS_OFFSET -2
# else
#	error "FORCED_DYNAMIC_TLS_OFFSET is not defined"
# endif
#endif
		/* For objects present at startup time: offset in the static TLS block.	*/
		ptrdiff_t l_tls_offset;
		/* Index of the module in the dtv array.	*/
		size_t l_tls_modid;

		/* Information used to change permission after the relocations are
			 done.	*/
		ElfW(Addr) l_relro_addr;
		size_t l_relro_size;

		unsigned long long int l_serial;

		/* Audit information.	This array apparent must be the last in the
			 structure.	Never add something after it.	*/
		struct auditstate
		{
			uintptr_t cookie;
			unsigned int bindflags;
		} l_audit[0];
	};


#if __ELF_NATIVE_CLASS == 32
# define symbind symbind32
#elif __ELF_NATIVE_CLASS == 64
# define symbind symbind64
#else
# error "__ELF_NATIVE_CLASS must be defined"
#endif

#include <stdio.h>
void dump_dyn(ElfW(Dyn) **dyn)
{
	size_t idx;
	idx = DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM;
	printf("link_map->l_info[%d]:\t\t %p\n", idx, dyn[idx]);
	idx = DT_INIT;
	printf("link_map->l_info[%d]:\t\t %p\n", idx, dyn[idx]);
	idx = DT_PREINIT_ARRAY;
	printf("link_map->l_info[%d]:\t\t %p\n", idx, dyn[idx]);
	idx = DT_PREINIT_ARRAYSZ;
	printf("link_map->l_info[%d]:\t\t %p\n", idx, dyn[idx]);

}

void dump_link_map(struct link_map *link_map)
{
	printf("---------------------------------------------------\n");
//	size_t idx;
	//NOTE if #include <link.h>, sizeof(struct link_map) eq 20 ob 32bit (40 on 64bit)
	printf("sizeof(struct link_map):\t %d\n", sizeof(struct link_map));

	printf("link_map:\t\t\t %p\n", link_map);
	printf("link_map->l_addr:\t\t %p\n", (void *)link_map->l_addr);
	printf("link_map->l_name:\t\t %s\n", link_map->l_name);
	printf("link_map->l_ld:\t\t\t %p\n", link_map->l_ld);

	printf("link_map->l_info:\t\t %p\n", link_map->l_info);
	dump_dyn(link_map->l_info);
	/*
	idx = DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM;
	printf("link_map->l_info[%d]:\t\t %p\n", idx, link_map->l_info[idx]);
	idx = DT_INIT;
	printf("link_map->l_info[%d]:\t\t %p\n", idx, link_map->l_info[idx]);
	idx = DT_PREINIT_ARRAY;
	printf("link_map->l_info[%d]:\t\t %p\n", idx, link_map->l_info[idx]);
	idx = DT_PREINIT_ARRAYSZ;
	printf("link_map->l_info[%d]:\t\t %p\n", idx, link_map->l_info[idx]);
	*/

	printf("link_map->l_phdr:\t\t %p\n", link_map->l_phdr);
	printf("link_map->l_entry:\t\t %p\n", (void *)link_map->l_entry);
	printf("link_map->l_phnum:\t\t %d\n", link_map->l_phnum);
	printf("link_map->l_ldnum:\t\t %d\n", link_map->l_ldnum);

	printf("link_map->l_mach.plt:\t\t %p\n", (void *)link_map->l_mach.plt);
	printf("link_map->l_mach.gotplt:\t %p\n", (void *)link_map->l_mach.gotplt);
	printf("link_map->l_mach.tlsdesc_table:\t %p\n", link_map->l_mach.tlsdesc_table);
	printf("link_map->l_loader:\t\t %p\n", link_map->l_loader);
	printf("link_map->l_type:\t\t %d\n", link_map->l_type);

	printf("link_map->l_map_start:\t\t %p - %p\n", (void *)link_map->l_map_start, (void *)link_map->l_map_end);
	printf("link_map->l_text_end:\t\t %p\n", (void *)link_map->l_text_end);
}

#endif /* include/link.h */