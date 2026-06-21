
#include "qemu/osdep.h"
#include <sys/ioctl.h>

#include "nyx/debug.h"
#include "nyx/helpers.h"
#include "nyx/snapshot/helper.h"
#include "nyx/snapshot/memory/backend/nyx_dirty_ring.h"

#include "sysemu/kvm.h"
#include "sysemu/kvm_int.h"

#include <linux/kvm.h>
#include <pthread.h>  /* T5a: parallel restore prototype */

#define FAST_IN_RANGE(address, start, end) (address < end && address >= start)

/* dirty ring specific defines */
#define KVM_DIRTY_LOG_PAGE_OFFSET 64
#define KVM_EXIT_DIRTY_RING_FULL  31
#define KVM_RESET_DIRTY_RINGS     _IO(KVMIO, 0xc7)
#define KVM_CAP_DIRTY_LOG_RING    192

/* global vars */
int                   dirty_ring_size            = 0;
int                   dirty_ring_max_size_global = 0;
struct kvm_dirty_gfn *kvm_dirty_gfns             = NULL; /* dirty ring mmap ptr */
uint32_t              kvm_dirty_gfns_index       = 0;
uint32_t              kvm_dirty_gfns_index_mask  = 0;


static int vm_enable_dirty_ring(int vm_fd, uint32_t ring_size)
{
    struct kvm_enable_cap cap = { 0 };

    cap.cap     = KVM_CAP_DIRTY_LOG_RING;
    cap.args[0] = ring_size;

    int ret = ioctl(vm_fd, KVM_ENABLE_CAP, &cap);
    if (ret != 0) {
        nyx_error("KVM_ENABLE_CAP ioctl failed\n");
    }

    return ring_size;
}

static int check_dirty_ring_size(int kvm_fd, int vm_fd)
{
    int ret = ioctl(kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_DIRTY_LOG_RING);
    if (ret < 0) {
        nyx_abort("KVM_CAP_DIRTY_LOG_RING failed (dirty ring not supported?)\n");
    }

    nyx_printf("Max Dirty Ring Size -> %d (Entries: %d)\n", ret,
               ret / (int)sizeof(struct kvm_dirty_gfn));

    uint64_t dirty_ring_max_size =
        ret; // kvm_dirty_ring_size * sizeof(struct kvm_dirty_gfn);

    /* DIRTY RING -> 1MB in size results in 256M trackable memory */
    ret = vm_enable_dirty_ring(vm_fd, dirty_ring_max_size);

    if (ret < 0) {
        nyx_abort("Enabling dirty ring (size: %ld) failed\n", dirty_ring_max_size);
    }

    dirty_ring_max_size_global = dirty_ring_max_size;
    return ret;
}

static void allocate_dirty_ring(int kvm_vcpu, int vm_fd)
{
    assert(dirty_ring_size);

    if (dirty_ring_size) {
        kvm_dirty_gfns = mmap(NULL, dirty_ring_size, PROT_READ | PROT_WRITE,
                              MAP_SHARED, kvm_vcpu,
                              PAGE_SIZE * KVM_DIRTY_LOG_PAGE_OFFSET);
        if (kvm_dirty_gfns == MAP_FAILED) {
            nyx_abort("Dirty ring mmap failed!\n");
        }
    }
    nyx_printf("Dirty ring mmap region located at %p\n", kvm_dirty_gfns);

    int ret = ioctl(vm_fd, KVM_RESET_DIRTY_RINGS, 0);
    assert(ret == 0);
}

/* pre_init operation */
void nyx_dirty_ring_early_init(int kvm_fd, int vm_fd)
{
    dirty_ring_size = check_dirty_ring_size(kvm_fd, vm_fd);
}

void nyx_dirty_ring_pre_init(int kvm_fd, int vm_fd)
{
    allocate_dirty_ring(kvm_fd, vm_fd);

    kvm_dirty_gfns_index = 0;
    kvm_dirty_gfns_index_mask =
        ((dirty_ring_max_size_global / sizeof(struct kvm_dirty_gfn)) - 1);
}

static inline void dirty_ring_collect(nyx_dirty_ring_t          *self,
                                      shadow_memory_t           *shadow_memory_state,
                                      snapshot_page_blocklist_t *blocklist,
                                      uint64_t                   slot,
                                      uint64_t                   gfn)
{
    /* sanity check */
    assert((slot & 0xFFFF0000) == 0);

    slot_t *kvm_region_slot = &self->kvm_region_slots[slot & 0xFFFF];

    if (test_and_set_bit(gfn, (void *)kvm_region_slot->bitmap) == false) {
        kvm_region_slot->stack[kvm_region_slot->stack_ptr] = gfn;
        kvm_region_slot->stack_ptr++;
    }
}

static void dirty_ring_flush_and_collect(nyx_dirty_ring_t *self,
                                         shadow_memory_t  *shadow_memory_state,
                                         snapshot_page_blocklist_t *blocklist,
                                         int                        vm_fd)
{
    struct kvm_dirty_gfn *entry   = NULL;
    int                   cleared = 0;

    while (true) {
        entry = &kvm_dirty_gfns[kvm_dirty_gfns_index & kvm_dirty_gfns_index_mask];

        if ((entry->flags & 0x3) == 0) {
            break;
        }

        if ((entry->flags & 0x1) == 1) {
            dirty_ring_collect(self, shadow_memory_state, blocklist, entry->slot,
                               entry->offset);
            cleared++;
            entry->flags |= 0x2; // reset dirty entry
        } else {
            nyx_abort("[%p] kvm_dirty_gfn -> flags: %d slot: %d offset: %lx\n",
                      entry, entry->flags, entry->slot, entry->offset);
        }

        kvm_dirty_gfns_index++;
    }

    int ret = ioctl(vm_fd, KVM_RESET_DIRTY_RINGS, 0);
    assert(ret == cleared);
}

static void dirty_ring_flush(int vm_fd)
{
    struct kvm_dirty_gfn *entry   = NULL;
    int                   cleared = 0;

    while (true) {
        entry = &kvm_dirty_gfns[kvm_dirty_gfns_index & kvm_dirty_gfns_index_mask];

        if ((entry->flags & 0x3) == 0) {
            break;
        }

        if ((entry->flags & 0x1) == 1) {
            cleared++;
            entry->flags |= 0x2; // reset dirty entry
        } else {
            nyx_abort("[%p] kvm_dirty_gfn -> flags: %d slot: %d offset: %lx\n",
                      entry, entry->flags, entry->slot, entry->offset);
        }

        kvm_dirty_gfns_index++;
    }

    int ret = ioctl(vm_fd, KVM_RESET_DIRTY_RINGS, 0);
    assert(ret == cleared);
}

/* init operation */
nyx_dirty_ring_t *nyx_dirty_ring_init(shadow_memory_t *shadow_memory)
{
    nyx_dirty_ring_t *self = malloc(sizeof(nyx_dirty_ring_t));
    memset(self, 0, sizeof(nyx_dirty_ring_t));

    assert(kvm_state);


    KVMMemoryListener *kml = kvm_get_kml(0);
    KVMSlot           *mem;

    for (int i = 0; i < kvm_get_max_memslots(); i++) {
        mem = &kml->slots[i];

        if (mem->start_addr == 0 && mem->memory_size == 0) {
            break;
        }

        self->kvm_region_slots_num++;
    }

    self->kvm_region_slots = malloc(sizeof(slot_t) * self->kvm_region_slots_num);
    memset(self->kvm_region_slots, 0, sizeof(slot_t) * self->kvm_region_slots_num);

    for (int i = 0; i < kvm_get_max_memslots(); i++) {
        mem = &kml->slots[i];

        if (mem->start_addr == 0 && mem->memory_size == 0) {
            break;
        }

        self->kvm_region_slots[i].enabled = (mem->flags & KVM_MEM_READONLY) == 0;
        self->kvm_region_slots[i].bitmap  = malloc(BITMAP_SIZE(mem->memory_size));
        self->kvm_region_slots[i].stack = malloc(DIRTY_STACK_SIZE(mem->memory_size));

        memset(self->kvm_region_slots[i].bitmap, 0, BITMAP_SIZE(mem->memory_size));
        memset(self->kvm_region_slots[i].stack, 0, DIRTY_STACK_SIZE(mem->memory_size));

        self->kvm_region_slots[i].bitmap_size = BITMAP_SIZE(mem->memory_size);

        self->kvm_region_slots[i].stack_ptr = 0;

        if (self->kvm_region_slots[i].enabled) {
            bool ram_region_found = false;
            for (int j = 0; j < shadow_memory->ram_regions_num; j++) {
                if (FAST_IN_RANGE(mem->start_addr, shadow_memory->ram_regions[j].base,
                                  (shadow_memory->ram_regions[j].base +
                                   shadow_memory->ram_regions[j].size)))
                {
                    assert(FAST_IN_RANGE((mem->start_addr + mem->memory_size - 1),
                                         shadow_memory->ram_regions[j].base,
                                         (shadow_memory->ram_regions[j].base +
                                          shadow_memory->ram_regions[j].size)));

                    self->kvm_region_slots[i].region_id = j;
                    self->kvm_region_slots[i].region_offset =
                        mem->start_addr - shadow_memory->ram_regions[j].base;
                    ram_region_found = true;
                    break;
                }
            }
            assert(ram_region_found);
        }
    }

#ifdef DEBUG__PRINT_DIRTY_RING
    for (int i = 0; i < self->kvm_region_slots_num; i++) {
        nyx_debug("[%d].enabled       = %d\n", i, self->kvm_region_slots[i].enabled);
        nyx_debug("[%d].bitmap        = %p\n", i, self->kvm_region_slots[i].bitmap);
        nyx_debug("[%d].stack         = %p\n", i, self->kvm_region_slots[i].stack);
        nyx_debug("[%d].stack_ptr     = %ld\n", i,
                  self->kvm_region_slots[i].stack_ptr);
        if (self->kvm_region_slots[i].enabled) {
            nyx_debug("[%d].region_id     = %d\n", i,
                      self->kvm_region_slots[i].region_id);
            nyx_debug("[%d].region_offset = 0x%lx\n", i,
                      self->kvm_region_slots[i].region_offset);
        } else {
            nyx_debug("[%d].region_id     = -\n", i);
            nyx_debug("[%d].region_offset = -\n", i);
        }
    }
#endif

    dirty_ring_flush(kvm_get_vm_fd(kvm_state));
    return self;
}

static uint32_t restore_memory(nyx_dirty_ring_t          *self,
                               shadow_memory_t           *shadow_memory_state,
                               snapshot_page_blocklist_t *blocklist)
{
    uint32_t num_dirty_pages   = 0;
    void    *host_addr         = NULL;
    void    *snapshot_addr     = NULL;
    uint64_t physical_addr     = 0;
    uint64_t gfn               = 0;
    uint64_t entry_offset_addr = 0;

    for (uint8_t j = 0; j < self->kvm_region_slots_num; j++) {
        slot_t *kvm_region_slot = &self->kvm_region_slots[j];
        if (kvm_region_slot->enabled && kvm_region_slot->stack_ptr) {
            for (uint64_t i = 0; i < kvm_region_slot->stack_ptr; i++) {
                gfn = kvm_region_slot->stack[i];

                entry_offset_addr = kvm_region_slot->region_offset + (gfn << 12);

                physical_addr =
                    shadow_memory_state->ram_regions[kvm_region_slot->region_id].base +
                    entry_offset_addr;

                if (snapshot_page_blocklist_check_phys_addr(blocklist,
                                                            physical_addr) == true)
                {
                    continue;
                }

                host_addr =
                    shadow_memory_state->ram_regions[kvm_region_slot->region_id]
                        .host_region_ptr +
                    entry_offset_addr;

                if (shadow_memory_state->incremental_enabled) {
                    snapshot_addr =
                        shadow_memory_state->ram_regions[kvm_region_slot->region_id]
                            .incremental_region_ptr +
                        entry_offset_addr;
                } else {
                    snapshot_addr =
                        shadow_memory_state->ram_regions[kvm_region_slot->region_id]
                            .snapshot_region_ptr +
                        entry_offset_addr;
                }

                memcpy(host_addr, snapshot_addr, TARGET_PAGE_SIZE);

                clear_bit(gfn, (void *)kvm_region_slot->bitmap);
                num_dirty_pages++;
            }
            kvm_region_slot->stack_ptr = 0;
        }
    }
    return num_dirty_pages;
}

static void save_root_pages(nyx_dirty_ring_t          *self,
                            shadow_memory_t           *shadow_memory_state,
                            snapshot_page_blocklist_t *blocklist)
{
    void    *host_addr         = NULL;
    void    *incremental_addr  = NULL;
    uint64_t physical_addr     = 0;
    uint64_t gfn               = 0;
    uint64_t entry_offset_addr = 0;

    for (uint8_t j = 0; j < self->kvm_region_slots_num; j++) {
        slot_t *kvm_region_slot = &self->kvm_region_slots[j];
        if (kvm_region_slot->enabled && kvm_region_slot->stack_ptr) {
            for (uint64_t i = 0; i < kvm_region_slot->stack_ptr; i++) {
                gfn = kvm_region_slot->stack[i];

                entry_offset_addr = kvm_region_slot->region_offset + (gfn << 12);

                physical_addr =
                    shadow_memory_state->ram_regions[kvm_region_slot->region_id].base +
                    entry_offset_addr;

                if (snapshot_page_blocklist_check_phys_addr(blocklist,
                                                            physical_addr) == true)
                {
                    continue;
                }

                host_addr =
                    shadow_memory_state->ram_regions[kvm_region_slot->region_id]
                        .host_region_ptr +
                    entry_offset_addr;
                incremental_addr =
                    shadow_memory_state->ram_regions[kvm_region_slot->region_id]
                        .incremental_region_ptr +
                    entry_offset_addr;

                shadow_memory_track_dirty_root_pages(shadow_memory_state,
                                                     entry_offset_addr,
                                                     kvm_region_slot->region_id);
                memcpy(incremental_addr, host_addr, TARGET_PAGE_SIZE);

                clear_bit(gfn, (void *)kvm_region_slot->bitmap);
            }
            kvm_region_slot->stack_ptr = 0;
        }
    }
}

/* T5a restore profiler + parallel-writeback prototype (env-gated, off by default — hot path).
 *  NYX_RESTORE_PROFILE=1  : split per-restore cost into (1) collect+reprotect vs (2) writeback,
 *    and measure re-touch ratio R = |this dirty ∩ prev dirty| / |prev dirty|.
 *  NYX_RESTORE_PARALLEL=N : do the page writeback with N host threads (memcpy is bandwidth-bound;
 *    serial restore is single-core). N=0/unset -> serial restore_memory(). */
static inline uint64_t prof_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

typedef struct {
    nyx_dirty_ring_t          *self;
    shadow_memory_t           *sms;
    snapshot_page_blocklist_t *bl;
    uint8_t  slot;
    uint64_t lo, hi;
    uint32_t count;
} restore_task_t;

static void *restore_worker(void *arg)
{
    restore_task_t  *t   = (restore_task_t *)arg;
    slot_t          *s   = &t->self->kvm_region_slots[t->slot];
    shadow_memory_t *sms = t->sms;
    uint64_t  rid         = s->region_id;
    uint64_t  region_base = sms->ram_regions[rid].base;
    uint64_t  roff        = s->region_offset;
    void     *host_base   = sms->ram_regions[rid].host_region_ptr;
    void     *snap_base   = sms->incremental_enabled
                                ? sms->ram_regions[rid].incremental_region_ptr
                                : sms->ram_regions[rid].snapshot_region_ptr;
    uint32_t c = 0;
    for (uint64_t i = t->lo; i < t->hi; i++) {
        uint64_t eoa = roff + (s->stack[i] << 12);
        if (snapshot_page_blocklist_check_phys_addr(t->bl, region_base + eoa)) {
            continue;
        }
        memcpy(host_base + eoa, snap_base + eoa, TARGET_PAGE_SIZE);
        c++;
    }
    t->count = c;
    return NULL;
}

/* Partition each slot's dirty stack across `nt` threads. Bitmap cleared via one memset at the end
 * (whole dirty set is reverted) to avoid non-atomic clear_bit() races between threads. */
static uint32_t restore_memory_parallel(nyx_dirty_ring_t          *self,
                                        shadow_memory_t           *shadow_memory_state,
                                        snapshot_page_blocklist_t *blocklist,
                                        int                        nt)
{
    uint32_t total = 0;
    for (uint8_t j = 0; j < self->kvm_region_slots_num; j++) {
        slot_t *s = &self->kvm_region_slots[j];
        if (!(s->enabled && s->stack_ptr)) {
            continue;
        }
        uint64_t n  = s->stack_ptr;
        int      tu = (n < 1024) ? 1 : nt; /* tiny dirty set: thread overhead not worth it */
        if (tu > 64) {
            tu = 64;
        }
        pthread_t      th[64];
        restore_task_t tk[64];
        uint64_t       per = (n + tu - 1) / tu;
        for (int k = 0; k < tu; k++) {
            tk[k].self = self; tk[k].sms = shadow_memory_state; tk[k].bl = blocklist;
            tk[k].slot = j; tk[k].lo = (uint64_t)k * per;
            tk[k].hi = ((uint64_t)(k + 1) * per > n) ? n : (uint64_t)(k + 1) * per;
            tk[k].count = 0;
        }
        if (tu == 1) {
            restore_worker(&tk[0]);
            total += tk[0].count;
        } else {
            for (int k = 0; k < tu; k++) {
                pthread_create(&th[k], NULL, restore_worker, &tk[k]);
            }
            for (int k = 0; k < tu; k++) {
                pthread_join(th[k], NULL);
                total += tk[k].count;
            }
        }
        memset(s->bitmap, 0, s->bitmap_size);
        s->stack_ptr = 0;
    }
    return total;
}

/* ---- ping-pong double-buffer load-bearing-cost probe (T5b, env-gated, off by default) ----
 * Plan research/plans/2026-06-21-05-restore-acceleration.md §3.C wants to know if a ping-pong
 * double buffer makes "the restore operation itself" near-free. Its two load-bearing costs are
 *   (a) the KVM memslot switch ioctl, and
 *   (b) the EPT re-fault tax the guest then pays rebuilding its working set on the next run.
 * Crucially, (b) is IDENTICAL whether the guest resumes on the same buffer with a zapped EPT or
 * on a second already-clean buffer (both start from an empty EPT). So we can measure both costs
 * WITHOUT building the full double buffer: after the normal memcpy restore (which keeps guest
 * memory correct), we delete+re-add each writable memslot with the SAME ram pointer. The delete
 * tears down that slot's EPT; the next guest run re-faults its whole working set. This is the
 * exact tax ping-pong would impose every restore (current memcpy restore pays ZERO of it).
 *   NYX_PINGPONG_PROBE=1 : zap EPT only (delete+re-add).
 *   NYX_PINGPONG_PROBE=2 : zap + host-side prefault (touch every page after re-add). NOTE
 *     KVM_PRE_FAULT_MEMORY is unavailable on this kernel, so this only warms HOST page tables,
 *     it cannot pre-build EPT — measuring how little host prefault helps is itself a result. */
static void pingpong_zap_and_prefault(nyx_dirty_ring_t *self, int prefault,
                                      uint64_t *zap_ns, uint64_t *pf_ns)
{
    int                vm_fd = kvm_get_vm_fd(kvm_state);
    KVMMemoryListener *kml   = kvm_get_kml(0);

    uint64_t a = prof_now_ns();
    for (uint8_t i = 0; i < self->kvm_region_slots_num; i++) {
        if (!self->kvm_region_slots[i].enabled) {
            continue;
        }
        KVMSlot *ks = &kml->slots[i];
        if (ks->memory_size == 0) {
            continue;
        }
        struct kvm_userspace_memory_region mem;
        mem.slot            = ks->slot | (kml->as_id << 16);
        mem.guest_phys_addr = ks->start_addr;
        mem.userspace_addr  = (uintptr_t)ks->ram;
        mem.flags           = ks->flags;
        mem.memory_size     = 0; /* delete -> tears down this slot's EPT */
        if (ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &mem) != 0) {
            nyx_abort("pingpong: memslot delete (slot %d) failed\n", ks->slot);
        }
        mem.memory_size = ks->memory_size; /* re-add same ram ptr -> empty EPT */
        if (ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &mem) != 0) {
            nyx_abort("pingpong: memslot re-add (slot %d) failed\n", ks->slot);
        }
    }
    uint64_t b = prof_now_ns();

    if (prefault) {
        for (uint8_t i = 0; i < self->kvm_region_slots_num; i++) {
            if (!self->kvm_region_slots[i].enabled) {
                continue;
            }
            KVMSlot *ks = &kml->slots[i];
            if (ks->memory_size == 0) {
                continue;
            }
            volatile uint8_t *p   = (volatile uint8_t *)ks->ram;
            uint64_t          sz  = ks->memory_size;
            uint64_t          acc = 0;
            for (uint64_t off = 0; off < sz; off += TARGET_PAGE_SIZE) {
                acc += p[off];
            }
            (void)acc;
        }
    }
    uint64_t c = prof_now_ns();

    *zap_ns += (b - a);
    *pf_ns  += (c - b);
}

static void pingpong_tick(nyx_dirty_ring_t *self, int pingpong)
{
    static uint64_t acc_zap = 0, acc_pf = 0, n = 0;
    pingpong_zap_and_prefault(self, pingpong >= 2, &acc_zap, &acc_pf);
    n++;
    if (n % 200 == 0) {
        fprintf(stderr,
                "[pingpong-probe] mode=%d n=%lu zap=%.1fus prefault=%.1fus\n",
                pingpong, (unsigned long)n, acc_zap / 1000.0 / (double)n,
                acc_pf / 1000.0 / (double)n);
    }
}

uint32_t nyx_snapshot_nyx_dirty_ring_restore(nyx_dirty_ring_t *self,
                                             shadow_memory_t  *shadow_memory_state,
                                             snapshot_page_blocklist_t *blocklist)
{
    static int prof = -1, nt = 0, pingpong = 0;
    if (prof < 0) {
        prof = getenv("NYX_RESTORE_PROFILE") ? 1 : 0;
        const char *e = getenv("NYX_RESTORE_PARALLEL");
        nt = e ? atoi(e) : 0;
        const char *pp = getenv("NYX_PINGPONG_PROBE");
        pingpong = pp ? atoi(pp) : 0;
    }

    if (!prof) {
        dirty_ring_flush_and_collect(self, shadow_memory_state, blocklist,
                                     kvm_get_vm_fd(kvm_state));
        uint32_t r = nt > 0 ? restore_memory_parallel(self, shadow_memory_state,
                                                      blocklist, nt)
                            : restore_memory(self, shadow_memory_state, blocklist);
        if (pingpong) {
            pingpong_tick(self, pingpong);
        }
        return r;
    }

    /* ---- profiled path ---- */
    static uint64_t acc_collect_ns = 0, acc_writeback_ns = 0;
    static uint64_t acc_dirty = 0, acc_overlap = 0, acc_prev = 0, n = 0;
    static void    *prev_bm[16]  = { 0 };
    static uint64_t prev_cnt[16] = { 0 };

    uint64_t t0 = prof_now_ns();
    dirty_ring_flush_and_collect(self, shadow_memory_state, blocklist,
                                 kvm_get_vm_fd(kvm_state));
    uint64_t t1 = prof_now_ns();

    /* R: overlap of THIS round's dirty set with the PREVIOUS round's, per slot.
     * Must run BEFORE the writeback clears the per-slot stacks/bitmaps. */
    uint64_t this_dirty = 0;
    for (uint8_t j = 0; j < self->kvm_region_slots_num && j < 16; j++) {
        slot_t *s = &self->kvm_region_slots[j];
        if (!prev_bm[j]) {
            prev_bm[j] = calloc(1, s->bitmap_size);
        }
        for (uint64_t i = 0; i < s->stack_ptr; i++) {
            this_dirty++;
            if (test_bit(s->stack[i], (unsigned long *)prev_bm[j])) {
                acc_overlap++;
            }
        }
        acc_prev += prev_cnt[j];
        memset(prev_bm[j], 0, s->bitmap_size);
        for (uint64_t i = 0; i < s->stack_ptr; i++) {
            set_bit(s->stack[i], (unsigned long *)prev_bm[j]);
        }
        prev_cnt[j] = s->stack_ptr;
    }

    uint64_t t2  = prof_now_ns();
    uint32_t ret = nt > 0 ? restore_memory_parallel(self, shadow_memory_state, blocklist, nt)
                          : restore_memory(self, shadow_memory_state, blocklist);
    uint64_t t3  = prof_now_ns();

    acc_collect_ns   += (t1 - t0);
    acc_writeback_ns += (t3 - t2);
    acc_dirty        += this_dirty;
    n++;

    if (n % 200 == 0) {
        double col_us = acc_collect_ns / 1000.0 / (double)n;
        double wb_us  = acc_writeback_ns / 1000.0 / (double)n;
        double tot    = col_us + wb_us;
        double R      = acc_prev ? (double)acc_overlap / (double)acc_prev : 0.0;
        fprintf(stderr,
                "[restore-prof] nt=%d n=%lu dirty_avg=%.0f collect=%.1fus(%.0f%%) "
                "writeback=%.1fus(%.0f%%) total=%.1fus R_retouch=%.3f\n",
                nt, (unsigned long)n, (double)acc_dirty / (double)n, col_us,
                tot ? 100.0 * col_us / tot : 0.0, wb_us,
                tot ? 100.0 * wb_us / tot : 0.0, tot, R);
    }
    if (pingpong) {
        pingpong_tick(self, pingpong);
    }
    return ret;
}

void nyx_snapshot_nyx_dirty_ring_save_root_pages(nyx_dirty_ring_t *self,
                                                 shadow_memory_t *shadow_memory_state,
                                                 snapshot_page_blocklist_t *blocklist)
{
    dirty_ring_flush_and_collect(self, shadow_memory_state, blocklist,
                                 kvm_get_vm_fd(kvm_state));
    save_root_pages(self, shadow_memory_state, blocklist);
}

void nyx_snapshot_nyx_dirty_ring_flush(void)
{
    dirty_ring_flush(kvm_get_vm_fd(kvm_state));
}

void nyx_snapshot_nyx_dirty_ring_flush_and_collect(nyx_dirty_ring_t *self,
                                                   shadow_memory_t *shadow_memory_state,
                                                   snapshot_page_blocklist_t *blocklist)
{
    dirty_ring_flush_and_collect(self, shadow_memory_state, blocklist,
                                 kvm_get_vm_fd(kvm_state));
}
