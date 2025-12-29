
// read "rinq" as "ring-queue"

struct rinq {
    struct rinq *next;
    struct rinq *prev;
    void *ref;
};

// Free list for recycling rinq nodes (avoids malloc/free per node)
#define RINQ_FREELIST_MAX 64
static struct rinq *rinq_freelist = NULL;
static int rinq_freelist_count = 0;

#define RINQ_IS_UNINIT(x_) ((x_)->next == NULL && (x_)->prev == NULL)
#define RINQ_IS_DETACHED(x_) ((x_)->next == (x_))
#define RINQ_IS_ATTACHED(x_) ((x_)->next != (x_))

// Allocate a rinq node, preferring the free list over malloc
#define RINQ_NEW(x_,ref_) do { \
    if (rinq_freelist != NULL) { \
        x_ = rinq_freelist; \
        rinq_freelist = rinq_freelist->next; \
        rinq_freelist_count--; \
    } else { \
        x_ = (struct rinq *)malloc(sizeof(struct rinq)); \
        if (unlikely(!x_)) croak("Out of memory in rinq"); \
    } \
    x_->next = x_->prev = x_; \
    x_->ref = ref_; \
} while(0)

// Return a rinq node to the free list
#define RINQ_FREE(x_) do { \
    if (rinq_freelist_count < RINQ_FREELIST_MAX) { \
        (x_)->next = rinq_freelist; \
        rinq_freelist = (x_); \
        rinq_freelist_count++; \
    } else { \
        free(x_); \
    } \
} while(0)

#define RINQ_DETACH(x_) do { \
    (x_)->next->prev = (x_)->prev; \
    (x_)->prev->next = (x_)->next; \
    (x_)->next = (x_)->prev = (x_); \
} while(0)

INLINE_UNLESS_DEBUG
static void
rinq_push (struct rinq **head, void *ref)
{
    struct rinq *x;
    RINQ_NEW(x,ref);

    if ((*head) == NULL) {
        (*head) = x;
    }
    else {
        x->next = (*head);
        x->prev = (*head)->prev;
        x->next->prev = x->prev->next = x;
    }
}

// remove element from head of rinq
INLINE_UNLESS_DEBUG
static void *
rinq_shift (struct rinq **head) {
    void *ref;
    struct rinq *x;

    if ((*head) == NULL) return NULL;

    if (RINQ_IS_DETACHED((*head))) {
        x = (*head);
        (*head) = NULL;
    }
    else {
        x = (*head);
        (*head) = (*head)->next;
        RINQ_DETACH(x);
    }

    ref = x->ref;
    RINQ_FREE(x);
    return ref;
}
