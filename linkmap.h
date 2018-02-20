/* For the version handling we need an array with only names and their
   hash values.  */
struct r_found_version
  {
    const char *name;
    ElfW(Word) hash;

    int hidden;
    const char *filename;
  };

/* We want to cache information about the searches for shared objects.  */
enum r_dir_status { unknown, nonexisting, existing };

struct r_search_path_elem
  {
    /* This link is only used in the `all_dirs' member of `r_search_path'.  */
    struct r_search_path_elem *next;

    /* Strings saying where the definition came from.  */
    const char *what;
    const char *where;

    /* Basename for this search path element.  The string must end with
       a slash character.  */
    const char *dirname;
    size_t dirnamelen;

    enum r_dir_status status[0];
  };

#if __WORDSIZE == 64
struct link_map_machine
  {
    Elf64_Addr plt; /* Address of .plt + 0x16 */
    Elf64_Addr gotplt; /* Address of .got + 0x18 */
    void *tlsdesc_table; /* Address of TLS descriptor hash table.  */
  };

#else
struct link_map_machine
  {
    Elf32_Addr plt; /* Address of .plt + 0x16 */
    Elf32_Addr gotplt; /* Address of .got + 0x0c */
    void *tlsdesc_table; /* Address of TLS descriptor hash table.  */
  };
#endif
