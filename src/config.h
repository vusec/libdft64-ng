#ifndef LIBDFT_CONFIG_H
#define LIBDFT_CONFIG_H

/* Pointer tag support. */
#ifdef LIBDFT_TAG_PTR_32
#ifndef LIBDFT_TAG_PTR
#define LIBDFT_TAG_PTR
#endif
#ifndef LIBDFT_PTR_32
#define LIBDFT_PTR_32
#endif
#endif

#ifdef LIBDFT_TAG_PTR
#ifndef LIBDFT_SHADOW
#define LIBDFT_SHADOW
#endif
#ifndef LIBDFT_TAG_SSET
#define LIBDFT_TAG_SSET
#endif
#endif

/* Pointer/offset labels. */
#if !defined(LIBDFT_TAG_PTR) || defined(LIBDFT_PTR_32)
#define PTROFF_SIZE 4
typedef uint32_t ptroff_t;
#else
#define PTROFF_SIZE 8
typedef uint64_t ptroff_t;
#endif

/* Small set tags. */
#ifndef LIBDFT_TAG_SSET_MAX
#if defined(LIBDFT_TAG_SSET) && defined(LIBDFT_PTR_32)
// 8 32-bit tags per set
#define LIBDFT_TAG_SSET_MAX 8
#else
// 4 64-bit tags per set
#define LIBDFT_TAG_SSET_MAX 4
#endif
#endif

/* Tag type selection. */
#if defined(LIBDFT_TAG_U8)
#define LIBDFT_TAG_TYPE libdft_tag_uint8
#define TAG_SIZE 1
#elif defined(LIBDFT_TAG_SSET)
#define LIBDFT_TAG_TYPE libdft_sset_tag
#define TAG_SIZE (PTROFF_SIZE * LIBDFT_TAG_SSET_MAX)
#else // Default tag type.
#ifndef LIBDFT_TAG_BDD
#define LIBDFT_TAG_BDD
#endif
#define LIBDFT_TAG_TYPE libdft_bdd_tag
#define TAG_SIZE 4
#endif

#endif /* LIBDFT_CONFIG_H */
