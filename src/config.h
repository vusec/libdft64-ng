#ifndef LIBDFT_CONFIG_H
#define LIBDFT_CONFIG_H

/* Pointer/offset labels. */
#define PTROFF_SIZE 4
typedef uint32_t ptroff_t;

/* Tag type selection. */
#if defined(LIBDFT_TAG_U8)
#define LIBDFT_TAG_TYPE libdft_tag_uint8
#define TAG_SIZE 1
#else // Default tag type.
#ifndef LIBDFT_TAG_BDD
#define LIBDFT_TAG_BDD
#endif
#define LIBDFT_TAG_TYPE libdft_bdd_tag
#define TAG_SIZE 4
#endif

#endif /* LIBDFT_CONFIG_H */
