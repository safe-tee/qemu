/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QEMU glue for the Hyper-V VSM userspace emulation core (hv-vsm.c).
 *
 * Binds the VMM-agnostic core to QEMU/KVM: plane vCPU fd management on top
 * of the KVM planes accel support, guest memory access, and the forwarded
 * hypercall entry point called from kvm_hv_handle_exit().
 */
#include "qemu/osdep.h"
#include <sys/ioctl.h>
#include "qemu/error-report.h"
#include "system/reset.h"
#include "qemu/main-loop.h"
#include "qemu/thread.h"
#include "system/kvm.h"
#include "system/kvm_int.h"
#include "system/address-spaces.h"
#include "system/physmem.h"
#include "hw/core/boards.h"
#include "hw/hyperv/hyperv.h"
#include "cpu.h"
#include "kvm_i386.h"
#include "hyperv.h"
#include "hyperv-proto.h"

#include "hv-vsm.h"

static bool vsm_dbg(void)
{
    static int on = -1;

    if (on < 0) {
        on = getenv("VSM_DEBUG") ? 1 : 0;
    }
    return on;
}


typedef struct HvVsmGlue {
    /*
     * Serializes every entry into the VSM core (hv_vsm_*()) and the
     * glue-owned state the core reads through its ops callbacks
     * (vsm_simp_ovl[]).  The core keeps shared per-partition state
     * (protection arrays, per-VP VTL state) with no locking of its
     * own, so each entry point takes this lock around the core call.
     *
     * Lock ordering: the BQL, where held (machine reset, vCPU init),
     * is taken before this lock.  Nothing that runs under this lock
     * may call bql_lock(); the vsm_qemu_ops callbacks are all BQL-free
     * (vcpu/vm ioctls routed through run_on_cpu dispatch, RAM access
     * via address_space RCU).  A vCPU thread acquires the lock with
     * vsm_glue_lock_from_vcpu(), never qemu_mutex_lock(), so that it
     * keeps servicing work the lock holder may have dispatched to it.
     */
    QemuMutex lock;
    struct hv_vsm *core;
    uint32_t nr_vps;
    int *plane1_vcpu_fd;        /* indexed by cpu_index, -1 if absent */
} HvVsmGlue;

static HvVsmGlue vsm_glue;
static bool vsm_inkernel_switch;
static uint32_t vsm_trace_vp = (uint32_t)-1;

static void vsm_glue_init_once(void);

/*
 * Plane vCPU state ioctls take the vCPU mutex, which the vCPU's own thread
 * holds for as long as it sits in KVM_RUN; issuing them from another thread
 * deadlocks against a vCPU parked in the guest.  Route any operation on a
 * foreign VP through run_on_cpu() so the owning thread leaves KVM_RUN and
 * performs it itself.
 */
typedef struct VsmVcpuIoctl {
    int fd;
    unsigned long cmd;
    void *arg;
    int ret;
    bool done;
} VsmVcpuIoctl;

/*
 * Acquire the glue lock from a vCPU thread.  The lock holder may be
 * dispatching a vcpu ioctl to THIS thread through run_on_cpu() (KVM
 * vcpu ioctls must be issued by the owning thread), so blocking here
 * deadlocks: service our work queue while contending.
 */
static void vsm_glue_lock_from_vcpu(CPUState *cs)
{
    /* qemu_mutex_trylock() returns 0 when it takes the lock. */
    while (qemu_mutex_trylock(&vsm_glue.lock)) {
        if (cs) {
            process_queued_cpu_work(cs);
        }
        g_usleep(2);
    }
}

static void vsm_vcpu_ioctl_cb(CPUState *cs, run_on_cpu_data data)
{
    VsmVcpuIoctl *x = data.host_ptr;

    x->ret = ioctl(x->fd, x->cmd, x->arg);
    if (x->ret < 0) {
        x->ret = -errno;
    }
    qatomic_store_release(&x->done, true);
}

static int vsm_vcpu_ioctl_on(uint32_t vp, int fd, unsigned long cmd, void *arg)
{
    CPUState *cs = qemu_get_cpu(vp);
    VsmVcpuIoctl x = { .fd = fd, .cmd = cmd, .arg = arg };

    if (fd < 0) {
        return -ENOENT;
    }
    if (!cs || cs == current_cpu) {
        vsm_vcpu_ioctl_cb(cs, RUN_ON_CPU_HOST_PTR(&x));
    } else if (!current_cpu) {
        /*
         * Non-vCPU (main/IO) thread, e.g. machine reset.  The caller
         * holds the BQL; do_run_on_cpu() drops it while waiting on
         * qemu_work_cond so the target thread can take it and run the
         * work.  A busy-wait here would hold the BQL and deadlock the
         * target in qemu_process_cpu_events().
         */
        run_on_cpu(cs, vsm_vcpu_ioctl_cb, RUN_ON_CPU_HOST_PTR(&x));
    } else {
        /*
         * vCPU-to-vCPU dispatch.  run_on_cpu() parks us on
         * qemu_work_cond without servicing OUR work queue, so two vCPU
         * threads dispatching at each other deadlock (both targets sit
         * in a VSM exit handler, not in their event loop).  Queue
         * asynchronously and service our own queue while waiting.
         */
        async_run_on_cpu(cs, vsm_vcpu_ioctl_cb, RUN_ON_CPU_HOST_PTR(&x));
        while (!qatomic_load_acquire(&x.done)) {
            process_queued_cpu_work(current_cpu);
            g_usleep(1);
        }
    }
    return x.ret;
}

static int vsm_vcpu_fd(void *vm, int plane, uint32_t vp)
{
    HvVsmGlue *g = vm;
    CPUState *cs;

    if (vp >= g->nr_vps) {
        return -1;
    }
    if (plane == 0) {
        cs = qemu_get_cpu(vp);
        return cs ? cpu_kvm_plane(cs, 0)->kvm_fd : -1;
    }
    return g->plane1_vcpu_fd[vp];
}

typedef struct VsmPlaneVcpuCreate {
    HvVsmGlue *g;
    CPUState *cs;
    int plane_fd;
    uint32_t vp;
} VsmPlaneVcpuCreate;

typedef struct VsmVcpuCall {
    int (*fn)(void *opaque);
    void *opaque;
    int ret;
    bool done;
} VsmVcpuCall;

static void vsm_vcpu_call_cb(CPUState *cs, run_on_cpu_data data)
{
    VsmVcpuCall *c = data.host_ptr;

    c->ret = c->fn(c->opaque);
    qatomic_store_release(&c->done, true);
}

/* Run fn() on the vCPU's owning thread; same dispatch rules as
 * vsm_vcpu_ioctl_on(). */
static int vsm_vcpu_call_on(uint32_t vp, int (*fn)(void *), void *opaque)
{
    CPUState *cs = qemu_get_cpu(vp);
    VsmVcpuCall c = { .fn = fn, .opaque = opaque };

    if (!cs || cs == current_cpu) {
        return fn(opaque);
    }
    if (!current_cpu) {
        run_on_cpu(cs, vsm_vcpu_call_cb, RUN_ON_CPU_HOST_PTR(&c));
    } else {
        async_run_on_cpu(cs, vsm_vcpu_call_cb, RUN_ON_CPU_HOST_PTR(&c));
        while (!qatomic_load_acquire(&c.done)) {
            process_queued_cpu_work(current_cpu);
            g_usleep(1);
        }
    }
    return c.ret;
}

static int vsm_plane_vcpu_create_fn(void *opaque)
{
    VsmPlaneVcpuCreate *c = opaque;
    int fd;

    fd = ioctl(c->plane_fd, KVM_CREATE_VCPU,
               (unsigned long)kvm_arch_vcpu_id(c->cs));
    if (fd < 0) {
        return -errno;
    }
    c->g->plane1_vcpu_fd[c->vp] = fd;
    return 0;
}

static int vsm_plane_vcpu_create(void *vm, int plane, uint32_t vp)
{
    HvVsmGlue *g = vm;
    CPUState *cs = qemu_get_cpu(vp);
    struct kvm_lapic_state lapic;
    int plane_fd, fd, ret;
    VsmPlaneVcpuCreate c;

    if (!cs || plane != 1) {
        return -EINVAL;
    }
    if (g->plane1_vcpu_fd[vp] >= 0) {
        return -EEXIST;
    }

    plane_fd = kvm_get_or_create_plane_fd(kvm_state, plane);
    if (plane_fd < 0) {
        return plane_fd;
    }

    /*
     * KVM_CREATE_VCPU on a plane fd vcpu_load()s the new twin, which
     * registers the shared preempt notifier: doing that from a foreign
     * thread while the plane-0 twin sits in KVM_RUN hard-locks the
     * host.  Create on the owning thread, like every other vcpu ioctl.
     */
    c = (VsmPlaneVcpuCreate) {
        .g = g, .cs = cs, .plane_fd = plane_fd, .vp = vp,
    };
    ret = vsm_vcpu_call_on(vp, vsm_plane_vcpu_create_fn, &c);
    if (ret < 0) {
        return ret;
    }
    fd = g->plane1_vcpu_fd[vp];

    /*
     * Software-enable the new VTL's local APIC (spurious vector 0xff).
     * The secure kernel never writes SPIV on its VTL1 APICs before
     * taking interrupts on them; on a software-disabled APIC its own
     * synthetic timer interrupt is delivered as spurious, which it
     * treats as a fatal unexpected interrupt.
     */
    if (vsm_vcpu_ioctl_on(vp, fd, KVM_GET_LAPIC, &lapic) == 0) {
        *(uint32_t *)(lapic.regs + 0xf0) = 0x1ff;
        if (vsm_vcpu_ioctl_on(vp, fd, KVM_SET_LAPIC, &lapic) < 0) {
            warn_report("hv-vsm: SPIV init for VP %u plane 1 failed", vp);
        }
    } else {
        warn_report("hv-vsm: KVM_GET_LAPIC for VP %u plane 1 failed", vp);
    }
    return 0;
}

#define VSM_VCPU_GET_IOCTL(getter, cmd, type)                               \
static int vsm_vcpu_##getter(void *vm, int plane, uint32_t vp, type *arg)   \
{                                                                           \
    int ret = vsm_vcpu_ioctl_on(vp, vsm_vcpu_fd(vm, plane, vp), cmd, arg); \
                                                                            \
    return ret < 0 ? ret : 0;                                               \
}

#define VSM_VCPU_SET_IOCTL(setter, cmd, type)                               \
static int vsm_vcpu_##setter(void *vm, int plane, uint32_t vp,              \
                             const type *arg)                               \
{                                                                           \
    int ret = vsm_vcpu_ioctl_on(vp, vsm_vcpu_fd(vm, plane, vp), cmd,       \
                                (void *)arg);                               \
                                                                            \
    return ret < 0 ? ret : 0;                                               \
}

typedef struct VsmSregsPatch {
    int fd;
    void (*patch)(struct kvm_sregs *s, void *opaque);
    void *opaque;
} VsmSregsPatch;

static int vsm_sregs_patch_fn(void *opaque)
{
    VsmSregsPatch *p = opaque;
    struct kvm_sregs sregs;

    if (ioctl(p->fd, KVM_GET_SREGS, &sregs) < 0) {
        return -errno;
    }
    p->patch(&sregs, p->opaque);
    return ioctl(p->fd, KVM_SET_SREGS, &sregs) < 0 ? -errno : 0;
}

static int vsm_vcpu_patch_sregs(void *vm, int plane, uint32_t vp,
                                void (*patch)(struct kvm_sregs *s, void *o),
                                void *opaque)
{
    VsmSregsPatch p = { .fd = vsm_vcpu_fd(vm, plane, vp),
                        .patch = patch, .opaque = opaque };

    if (p.fd < 0) {
        return -ENOENT;
    }
    return vsm_vcpu_call_on(vp, vsm_sregs_patch_fn, &p);
}

typedef struct VsmDbgPatch {
    int fd;
    void (*patch)(struct kvm_debugregs *d, void *opaque);
    void *opaque;
} VsmDbgPatch;

static int vsm_dbg_patch_fn(void *opaque)
{
    VsmDbgPatch *p = opaque;
    struct kvm_debugregs dbg;

    if (ioctl(p->fd, KVM_GET_DEBUGREGS, &dbg) < 0) {
        return -errno;
    }
    p->patch(&dbg, p->opaque);
    return ioctl(p->fd, KVM_SET_DEBUGREGS, &dbg) < 0 ? -errno : 0;
}

static int vsm_vcpu_patch_debugregs(void *vm, int plane, uint32_t vp,
                                    void (*patch)(struct kvm_debugregs *d,
                                                  void *o),
                                    void *opaque)
{
    VsmDbgPatch p = { .fd = vsm_vcpu_fd(vm, plane, vp),
                      .patch = patch, .opaque = opaque };

    if (p.fd < 0) {
        return -ENOENT;
    }
    return vsm_vcpu_call_on(vp, vsm_dbg_patch_fn, &p);
}

VSM_VCPU_GET_IOCTL(get_regs, KVM_GET_REGS, struct kvm_regs)

typedef struct VsmSetRegs {
    CPUState *cs;
    int fd;
    const struct kvm_regs *regs;
} VsmSetRegs;

static int vsm_set_regs_fn(void *opaque)
{
    VsmSetRegs *x = opaque;
    const struct kvm_regs *r = x->regs;

    if (ioctl(x->fd, KVM_SET_REGS, (void *)r) < 0) {
        return -errno;
    }
    /*
     * If QEMU holds a dirty shadow of this vCPU (plane 0 only), the next
     * kvm_arch_put_registers() would overwrite the raw write with the
     * stale env copy.  Refresh the shadow's GPRs so the write survives;
     * leave event/exception state alone.
     */
    if (getenv("VSM_DEBUG")) {
        fprintf(stderr, "vsm-setregs: cpu%d dirty=%d rax=%llx rcx=%llx rip=%llx\n",
                x->cs ? x->cs->cpu_index : -1,
                x->cs ? cpu_active_kvm_plane(x->cs)->vcpu_dirty : -1,
                (unsigned long long)r->rax, (unsigned long long)r->rcx,
                (unsigned long long)r->rip);
    }
    if (x->cs && cpu_active_kvm_plane(x->cs)->vcpu_dirty) {
        X86CPU *cpu = X86_CPU(x->cs);
        CPUX86State *env = &cpu->env;

        env->regs[R_EAX] = r->rax;
        env->regs[R_EBX] = r->rbx;
        env->regs[R_ECX] = r->rcx;
        env->regs[R_EDX] = r->rdx;
        env->regs[R_ESI] = r->rsi;
        env->regs[R_EDI] = r->rdi;
        env->regs[R_ESP] = r->rsp;
        env->regs[R_EBP] = r->rbp;
        env->regs[8] = r->r8;
        env->regs[9] = r->r9;
        env->regs[10] = r->r10;
        env->regs[11] = r->r11;
        env->regs[12] = r->r12;
        env->regs[13] = r->r13;
        env->regs[14] = r->r14;
        env->regs[15] = r->r15;
        env->eip = r->rip;
        env->eflags = r->rflags;
    }
    return 0;
}

static int vsm_vcpu_set_regs(void *vm, int plane, uint32_t vp,
                             const struct kvm_regs *arg)
{
    int fd = vsm_vcpu_fd(vm, plane, vp);
    VsmSetRegs x = {
        .cs = plane == 0 ? qemu_get_cpu(vp) : NULL,
        .fd = fd,
        .regs = arg,
    };

    if (fd < 0) {
        return -ENOENT;
    }
    return vsm_vcpu_call_on(vp, vsm_set_regs_fn, &x);
}
VSM_VCPU_GET_IOCTL(get_sregs, KVM_GET_SREGS, struct kvm_sregs)
VSM_VCPU_SET_IOCTL(set_sregs, KVM_SET_SREGS, struct kvm_sregs)
VSM_VCPU_GET_IOCTL(get_fpu, KVM_GET_FPU, struct kvm_fpu)
VSM_VCPU_SET_IOCTL(set_fpu, KVM_SET_FPU, struct kvm_fpu)
VSM_VCPU_GET_IOCTL(get_debugregs, KVM_GET_DEBUGREGS, struct kvm_debugregs)
VSM_VCPU_SET_IOCTL(set_debugregs, KVM_SET_DEBUGREGS, struct kvm_debugregs)

static int vsm_vcpu_set_msr(void *vm, int plane, uint32_t vp, uint32_t msr,
                            uint64_t value)
{
    int fd = vsm_vcpu_fd(vm, plane, vp);
    struct {
        struct kvm_msrs hdr;
        struct kvm_msr_entry entry;
    } m = {
        .hdr.nmsrs = 1,
        .entry.index = msr,
        .entry.data = value,
    };

    return vsm_vcpu_ioctl_on(vp, fd, KVM_SET_MSRS, &m) == 1 ? 0 : -EINVAL;
}

static int vsm_vcpu_get_msr(void *vm, int plane, uint32_t vp, uint32_t msr,
                            uint64_t *value)
{
    int fd = vsm_vcpu_fd(vm, plane, vp);
    struct {
        struct kvm_msrs hdr;
        struct kvm_msr_entry entry;
    } m = {
        .hdr.nmsrs = 1,
        .entry.index = msr,
    };

    if (vsm_vcpu_ioctl_on(vp, fd, KVM_GET_MSRS, &m) != 1) {
        return -EINVAL;
    }
    *value = m.entry.data;
    return 0;
}

/*
 * Partition clock restore for HvCallRestorePartitionTime.  When the
 * kernel headers carry KVM_SET_CLOCK_GUEST (the KVM clock migration
 * series), anchor the KVM clock to the (guest_tsc, ref_ns) pair exactly.
 * Otherwise, or when the ioctl is unavailable or refuses (-ENODATA: no
 * master clock; -EBUSY: TSC frequency unknown; the KVM clock is only
 * approximate in those modes anyway), step the clock to ref_ns with
 * plain KVM_SET_CLOCK, which costs the latency between the caller's TSC
 * writes and this step.
 */
static int vsm_set_partition_clock(void *vm, uint32_t vp, uint64_t ref_ns,
                                   uint64_t guest_tsc)
{
    struct kvm_clock_data data = { .clock = ref_ns };

#ifdef KVM_SET_CLOCK_GUEST
    if (kvm_check_extension(kvm_state, KVM_CAP_CLOCK_GUEST)) {
        struct pvclock_vcpu_time_info pv;
        int fd = vsm_vcpu_fd(vm, 0, vp);
        int ret;

        ret = vsm_vcpu_ioctl_on(vp, fd, KVM_GET_CLOCK_GUEST, &pv);
        if (!ret) {
            pv.tsc_timestamp = guest_tsc;
            pv.system_time = ref_ns;
            ret = vsm_vcpu_ioctl_on(vp, fd, KVM_SET_CLOCK_GUEST, &pv);
        }
        if (!ret) {
            warn_report("hv-vsm: restored partition time exactly "
                        "(KVM_SET_CLOCK_GUEST)");
            return 0;
        }
        warn_report("hv-vsm: KVM_SET_CLOCK_GUEST failed (%d), stepping the "
                    "clock with KVM_SET_CLOCK instead", ret);
    }
#endif

    warn_report("hv-vsm: restored partition time approximately "
                "(KVM_SET_CLOCK)");
    return kvm_vm_ioctl(kvm_state, KVM_SET_CLOCK, &data);
}

static int vsm_assert_interrupt(void *vm, uint8_t vtl, uint64_t dest_mda,
                                uint32_t vector, uint32_t type, bool logical)
{
    struct kvm_msi msi = {
        .address_lo = 0xfee00000 | ((uint32_t)dest_mda << 12) |
                      (logical ? 0x4 : 0),
        .data = (vector & 0xff) | ((type & 0x7) << 8),
    };
    int fd;

    if (vsm_dbg()) {
        fprintf(stderr, "hv-vsm dbg: ASSERTINT vtl=%u mda=%llx vec=%u type=%u\n",
                vtl, (unsigned long long)dest_mda, vector, type);
    }
    if (vtl == 0) {
        return kvm_vm_ioctl(kvm_state, KVM_SIGNAL_MSI, &msi) < 0 ? -1 : 0;
    }
    fd = kvm_get_or_create_plane_fd(kvm_state, vtl);
    if (fd < 0) {
        return -1;
    }
    return ioctl(fd, KVM_SIGNAL_MSI, &msi) < 0 ? -1 : 0;
}

/*
 * Per-plane SynIC overlay pages.  Each plane's SIMP is backed by a host
 * buffer mapped over the GPA for that plane only (KVM_SET_PLANE_MEMORY_OVERLAY);
 * the guest RAM underneath stays untouched for the other planes.
 */
#define VSM_OVL_MAX_VPS 64
#define VSM_OVL_MSG   0
#define VSM_OVL_EVENT 1

static struct vsm_simp_overlay {
    uint64_t gfn_plus_1;        /* 0 = no overlay installed */
    void *buf;
    bool external;              /* buffer owned by the SynIC device */
} vsm_simp_ovl[2][VSM_OVL_MAX_VPS][2];

static int vsm_overlay_ioctl(uint32_t plane, uint64_t gfn, void *buf)
{
    struct kvm_plane_memory_overlay ov = {
        .plane = plane,
        .gfn = gfn,
        .uaddr = (uintptr_t)buf,
    };

    return kvm_vm_ioctl(kvm_state, KVM_SET_PLANE_MEMORY_OVERLAY, &ov);
}

static void *vsm_overlay_ptr(void *vm, int plane, uint64_t gfn)
{
    int vp, k;

    if (plane < 0 || plane >= 2) {
        return NULL;
    }
    for (vp = 0; vp < VSM_OVL_MAX_VPS; vp++) {
        for (k = 0; k < 2; k++) {
            if (vsm_simp_ovl[plane][vp][k].gfn_plus_1 == gfn + 1) {
                return vsm_simp_ovl[plane][vp][k].buf;
            }
        }
    }
    return NULL;
}

/*
 * Install/move/remove the overlay backing one SynIC page of (plane, vp).
 * ext_buf, when given, is the SynIC device's own buffer (plane 0); the
 * device keeps writing messages there, and the overlay makes the plane
 * read the same memory.  Twins get a locally allocated buffer.
 */
static int vsm_set_synic_overlay_locked(X86CPU *cpu, uint32_t plane, int kind,
                                        uint64_t page_reg, void *ext_buf)
{
    uint32_t vp = hyperv_vp_index(CPU(cpu));
    struct vsm_simp_overlay *o;

    if (plane >= 2 || vp >= VSM_OVL_MAX_VPS || kind >= 2) {
        return -1;
    }
    o = &vsm_simp_ovl[plane][vp][kind];

    if (page_reg & 1) {
        uint64_t gfn = page_reg >> 12;
        void *buf = ext_buf;

        if (!buf) {
            if (!o->buf || o->external) {
                if (posix_memalign(&buf, 4096, 4096)) {
                    return -1;
                }
            } else {
                buf = o->buf;
            }
        }
        if (o->gfn_plus_1 == gfn + 1 && o->buf == buf) {
            return 0;
        }
        if (o->gfn_plus_1 &&
            vsm_overlay_ioctl(plane, o->gfn_plus_1 - 1, NULL) < 0) {
            return -1;
        }
        o->gfn_plus_1 = 0;
        o->buf = buf;
        o->external = (ext_buf != NULL);
        /* A freshly enabled overlay reads as zeroes (TLFS). */
        memset(o->buf, 0, 4096);
        if (vsm_overlay_ioctl(plane, gfn, o->buf) < 0) {
            return -1;
        }
        o->gfn_plus_1 = gfn + 1;
    } else if (o->gfn_plus_1) {
        if (vsm_overlay_ioctl(plane, o->gfn_plus_1 - 1, NULL) < 0) {
            return -1;
        }
        o->gfn_plus_1 = 0;
    }
    return 0;
}

/*
 * SynIC exits arrive on vCPU threads without the BQL; take the glue
 * lock so overlay installation serializes against the core reading
 * vsm_simp_ovl[] through ops->overlay_ptr on other vCPUs.
 */
int kvm_hv_vsm_set_synic_overlay(X86CPU *cpu, uint32_t plane, int kind,
                                 uint64_t page_reg, void *ext_buf)
{
    int ret;

    vsm_glue_init_once();

    vsm_glue_lock_from_vcpu(CPU(cpu));
    ret = vsm_set_synic_overlay_locked(cpu, plane, kind, page_reg, ext_buf);
    qemu_mutex_unlock(&vsm_glue.lock);
    return ret;
}

int kvm_hv_vsm_handle_synic_exit(X86CPU *cpu, uint32_t plane,
                                 uint64_t msg_page)
{
    return kvm_hv_vsm_set_synic_overlay(cpu, plane, VSM_OVL_MSG, msg_page,
                                        NULL);
}

static int64_t vsm_vp_from_apic_id(void *vm, uint32_t apic_id)
{
    CPUState *cs;

    CPU_FOREACH(cs) {
        X86CPU *cpu = X86_CPU(cs);

        if (cpu->apic_id == apic_id) {
            return hyperv_vp_index(cs);
        }
    }
    return -1;
}

/*
 * XCR0 is VTL-shared: the kernel fans a guest XSETBV in either plane
 * out to all plane twins (__kvm_set_xcr).  If QEMU holds a dirty env
 * shadow across a plane transition, the next kvm_put_xcrs() would
 * write the shadow's stale value back - and the kernel fanout would
 * spread the stale value to both planes.  Refresh the dirty shadow
 * from the kernel after any glue-handled transition, following the
 * env-shadow coherence pattern of vsm_vcpu_set_regs().
 */
static void vsm_refresh_env_xcr0(CPUState *cs)
{
    struct kvm_xcrs xcrs;
    int i;

    if (!cs || !cpu_active_kvm_plane(cs)->vcpu_dirty) {
        return;
    }
    if (kvm_vcpu_ioctl(cs, KVM_GET_XCRS, &xcrs) < 0) {
        return;
    }
    for (i = 0; i < xcrs.nr_xcrs; i++) {
        if (xcrs.xcrs[i].xcr == 0) {
            X86_CPU(cs)->env.xcr0 = xcrs.xcrs[i].value;
            break;
        }
    }
}

/*
 * The "reset BSP" in the KVM sense: the vCPU whose id matches the VM's
 * boot-cpu id (apic id 0 unless KVM_SET_BOOT_CPU_ID changed it, which
 * QEMU never does).  Deliberately not cpu_is_bsp(): the guest-visible
 * APIC-base BSP bit is mutable state, while StartVp must refuse the
 * reset BSP whatever the guest has done to its APIC.
 */
static bool vsm_vp_is_bsp(void *vm, uint32_t vp)
{
    CPUState *cs = qemu_get_cpu(vp);

    return cs && X86_CPU(cs)->apic_id == 0;
}

static int vsm_vcpu_translate(void *vm, int plane, uint32_t vp, uint64_t gva,
                              uint64_t *gpa, bool *valid, bool *writeable)
{
    int fd = vsm_vcpu_fd(vm, plane, vp);
    struct kvm_translation tr = {
        .linear_address = gva,
    };

    if (vsm_vcpu_ioctl_on(vp, fd, KVM_TRANSLATE, &tr) < 0) {
        return -EINVAL;
    }
    *gpa = tr.physical_address;
    *valid = tr.valid;
    if (writeable) {
        *writeable = tr.writeable;
    }
    return 0;
}

static int vsm_vcpu_set_run_state(void *vm, int plane, uint32_t vp,
                                  bool runnable)
{
    int fd = vsm_vcpu_fd(vm, plane, vp);
    uint32_t state = runnable ? KVM_PLANE_RUN_STATE_RUNNABLE :
                                KVM_PLANE_RUN_STATE_STOPPED;

    int ret = vsm_vcpu_ioctl_on(vp, fd, KVM_SET_PLANE_RUN_STATE, &state);

    return ret < 0 ? ret : 0;
}

typedef struct VsmEnvException {
    CPUState *cs;
    uint8_t vector;
    bool has_error;
    uint32_t error_code;
    bool has_payload;
    uint64_t payload;
} VsmEnvException;

static int vsm_queue_exception_env_fn(void *opaque)
{
    VsmEnvException *x = opaque;
    X86CPU *cpu = X86_CPU(x->cs);
    CPUX86State *env = &cpu->env;

    /*
     * Queue through QEMU's own event state, not a raw
     * KVM_SET_VCPU_EVENTS: the vCPU is usually dirty here (hypercall
     * handling synchronized it to read guest registers), so the next
     * kvm_arch_put_registers() would overwrite a raw-queued exception
     * with the stale (empty) env copy and silently drop it.
     */
    kvm_cpu_synchronize_state(x->cs);
    if (getenv("VSM_DEBUG")) {
        fprintf(stderr, "vsm-ev0env: vcpu%d eip=%llx rax=%llx dirty-pre=%d vec=0x%x\n",
                x->cs->cpu_index, (unsigned long long)env->eip,
                (unsigned long long)env->regs[R_EAX],
                cpu_active_kvm_plane(x->cs)->vcpu_dirty, x->vector);
    }
    env->exception_nr = x->vector;
    env->exception_pending = 1;
    env->exception_injected = 0;
    env->has_error_code = x->has_error;
    env->error_code = x->error_code;
    env->exception_has_payload = x->has_payload;
    env->exception_payload = x->has_payload ? x->payload : 0;
    return 0;
}

static int vsm_vcpu_queue_exception(void *vm, int plane, uint32_t vp,
                                    uint8_t vector, bool has_error,
                                    uint32_t error_code, bool has_payload,
                                    uint64_t payload)
{
    struct kvm_vcpu_events ev;
    int fd = vsm_vcpu_fd(vm, plane, vp);
    int ret;

    if (plane == 0) {
        CPUState *cs = qemu_get_cpu(vp);

        if (cs) {
            VsmEnvException x = {
                .cs = cs, .vector = vector, .has_error = has_error,
                .error_code = error_code, .has_payload = has_payload,
                .payload = payload,
            };
            return vsm_vcpu_call_on(vp, vsm_queue_exception_env_fn, &x);
        }
    }

    ret = vsm_vcpu_ioctl_on(vp, fd, KVM_GET_VCPU_EVENTS, &ev);
    if (ret < 0) {
        return ret;
    }
    ev.exception.injected = 0;
    ev.exception.pending = 1;
    ev.exception.nr = vector;
    ev.exception.has_error_code = has_error;
    ev.exception.error_code = error_code;
    ev.flags |= KVM_VCPUEVENT_VALID_PAYLOAD;
    ev.exception_has_payload = has_payload;
    ev.exception_payload = has_payload ? payload : 0;
    ret = vsm_vcpu_ioctl_on(vp, fd, KVM_SET_VCPU_EVENTS, &ev);
    return ret < 0 ? ret : 0;
}

static int vsm_vcpu_copy_xstate(void *vm, int from_plane, int to_plane,
                                uint32_t vp)
{
    static int xsave_size;
    static __thread void *buf;
    int ffd = vsm_vcpu_fd(vm, from_plane, vp);
    int tfd = vsm_vcpu_fd(vm, to_plane, vp);
    int ret;

    if (!xsave_size) {
        int sz = kvm_check_extension(kvm_state, KVM_CAP_XSAVE2);

        xsave_size = sz > 4096 ? sz : 4096;
    }
    if (!buf) {
        buf = g_malloc0(xsave_size);
    }
    if (ffd < 0 || tfd < 0) {
        return -ENODEV;
    }
    ret = vsm_vcpu_ioctl_on(vp, ffd, KVM_GET_XSAVE2, buf);
    if (ret < 0) {
        return ret;
    }
    ret = vsm_vcpu_ioctl_on(vp, tfd, KVM_SET_XSAVE, buf);
    return ret < 0 ? ret : 0;
}

static int vsm_vcpu_set_mp_runnable(void *vm, int plane, uint32_t vp)
{
    struct kvm_mp_state mp = { .mp_state = KVM_MP_STATE_RUNNABLE };
    int ret = vsm_vcpu_ioctl_on(vp, vsm_vcpu_fd(vm, plane, vp),
                                KVM_SET_MP_STATE, &mp);

    return ret < 0 ? ret : 0;
}

static int vsm_guest_read(void *vm, uint64_t gpa, void *buf, size_t len)
{
    physical_memory_read(gpa, buf, len);
    return 0;
}

static int vsm_guest_write(void *vm, uint64_t gpa, const void *buf, size_t len)
{
    physical_memory_write(gpa, buf, len);
    return 0;
}

static int vsm_vcpu_arm_reg_intercepts(void *vm, uint32_t vp, uint64_t control)
{
    struct kvm_enable_cap cap = {
        .cap = KVM_CAP_HYPERV_REG_INTERCEPT,
        .args[0] = control,
    };
    int fd = vsm_vcpu_fd(vm, 0, vp);

    /* Arm on the lower VTL (plane 0) vCPU, which executes the writes. */
    return vsm_vcpu_ioctl_on(vp, fd, KVM_ENABLE_CAP, &cap) < 0 ? -EINVAL : 0;
}

static int vsm_set_memory_attributes(void *vm, int plane, uint64_t gpa,
                                     uint64_t size, uint64_t attrs)
{
    struct kvm_memory_attributes attr = {
        .address = gpa,
        .size = size,
        .attributes = attrs,
    };
    int fd = kvm_get_or_create_plane_fd(kvm_state, plane);

    if (fd < 0) {
        return fd;
    }
    return ioctl(fd, KVM_SET_MEMORY_ATTRIBUTES, &attr) ? -errno : 0;
}

static uint64_t vsm_hcall_page_gpa(void *vm, int plane, uint32_t vp)
{
    int fd = vsm_vcpu_fd(vm, plane, vp);
    struct {
        struct kvm_msrs hdr;
        struct kvm_msr_entry entry;
    } m = {
        .hdr.nmsrs = 1,
        .entry.index = HV_X64_MSR_HYPERCALL,
    };

    if (fd < 0 || vsm_vcpu_ioctl_on(vp, fd, KVM_GET_MSRS, &m) != 1) {
        return 0;
    }
    if (!(m.entry.data & HV_HYPERCALL_ENABLE)) {
        return 0;
    }
    return m.entry.data & ~(uint64_t)0xfff;
}

static void vsm_log_op(void *vm, const char *msg)
{
    warn_report("%s", msg);
}

static const struct hv_vsm_host_ops vsm_qemu_ops = {
    .plane_vcpu_create = vsm_plane_vcpu_create,
    .vcpu_get_regs = vsm_vcpu_get_regs,
    .vcpu_set_regs = vsm_vcpu_set_regs,
    .vcpu_get_sregs = vsm_vcpu_get_sregs,
    .vcpu_set_sregs = vsm_vcpu_set_sregs,
    .vcpu_patch_sregs = vsm_vcpu_patch_sregs,
    .vcpu_patch_debugregs = vsm_vcpu_patch_debugregs,
    .vcpu_get_debugregs = vsm_vcpu_get_debugregs,
    .vcpu_set_debugregs = vsm_vcpu_set_debugregs,
    .vcpu_copy_xstate = vsm_vcpu_copy_xstate,
    .vcpu_get_fpu = vsm_vcpu_get_fpu,
    .vcpu_set_fpu = vsm_vcpu_set_fpu,
    .vcpu_set_msr = vsm_vcpu_set_msr,
    .vcpu_translate = vsm_vcpu_translate,
    .assert_interrupt = vsm_assert_interrupt,
    .vp_from_apic_id = vsm_vp_from_apic_id,
    .vp_is_bsp = vsm_vp_is_bsp,
    .overlay_ptr = vsm_overlay_ptr,
    .vcpu_queue_exception = vsm_vcpu_queue_exception,
    .vcpu_get_msr = vsm_vcpu_get_msr,
    .vcpu_set_run_state = vsm_vcpu_set_run_state,
    .vcpu_set_mp_runnable = vsm_vcpu_set_mp_runnable,
    .guest_read = vsm_guest_read,
    .guest_write = vsm_guest_write,
    .hcall_page_gpa = vsm_hcall_page_gpa,
    .set_memory_attributes = vsm_set_memory_attributes,
    .vcpu_arm_reg_intercepts = vsm_vcpu_arm_reg_intercepts,
    .set_partition_clock = vsm_set_partition_clock,
    .log = vsm_log_op,
};

/*
 * On guest reset, VSM partition state evaporates like the rest of the
 * machine: VTL1 is disabled again and the plane-1 twins are stopped so a
 * fresh boot can re-enable them from scratch.
 */
static void vsm_glue_reset(void *opaque)
{
    qemu_mutex_lock(&vsm_glue.lock);
    hv_vsm_reset(vsm_glue.core);
    for (uint32_t vp = 0; vp < vsm_glue.nr_vps; vp++) {
        if (vsm_glue.plane1_vcpu_fd[vp] >= 0) {
            vsm_vcpu_set_run_state(&vsm_glue, 1, vp, false);
        }
    }
    qemu_mutex_unlock(&vsm_glue.lock);
}


/* Debug: periodically log every VP's plane-1 RIP to spot VTL1 spins. */
static void *vsm_spin_debug_thread(void *arg)
{
    for (;;) {
        uint32_t vp;

        sleep(10);
        for (vp = 0; vp < vsm_glue.nr_vps; vp++) {
            struct kvm_regs regs;

            if (vsm_glue.plane1_vcpu_fd[vp] < 0) {
                continue;
            }
            if (!vsm_vcpu_get_regs(&vsm_glue, 1, vp, &regs)) {
                struct kvm_lapic_state lapic;
                uint32_t irr = 0, isr = 0;
                int i;

                if (!vsm_vcpu_ioctl_on(vp, vsm_glue.plane1_vcpu_fd[vp],
                                       KVM_GET_LAPIC, &lapic)) {
                    for (i = 0; i < 8; i++) {
                        irr |= *(uint32_t *)(lapic.regs + 0x200 + i * 0x10) ?
                               (1u << i) : 0;
                        isr |= *(uint32_t *)(lapic.regs + 0x100 + i * 0x10) ?
                               (1u << i) : 0;
                    }
                }
                if (vsm_dbg()) {
                    fprintf(stderr, "hv-vsm dbg: spin vp%u p1 rip=%llx rsp=%llx rfl=%llx irr=%x isr=%x tpr=%x ppr=%x\n",
                            vp, (unsigned long long)regs.rip,
                            (unsigned long long)regs.rsp,
                            (unsigned long long)regs.rflags, irr, isr,
                            *(uint32_t *)(lapic.regs + 0x80),
                            *(uint32_t *)(lapic.regs + 0xa0));
                }
            }
        }
    }
    return NULL;
}

static void vsm_glue_init_once(void)
{
    static bool inited;
    CPUState *cs;
    uint32_t nr = 0;

    if (inited) {
        return;
    }
    nr = MACHINE(qdev_get_machine())->smp.max_cpus;
    CPU_FOREACH(cs) {
        nr = MAX(nr, hyperv_vp_index(cs) + 1);
    }
    qemu_mutex_init(&vsm_glue.lock);
    vsm_glue.nr_vps = nr;
    vsm_glue.plane1_vcpu_fd = g_new(int, vsm_glue.nr_vps);
    for (uint32_t i = 0; i < vsm_glue.nr_vps; i++) {
        vsm_glue.plane1_vcpu_fd[i] = -1;
    }
    vsm_glue.core = hv_vsm_new(&vsm_qemu_ops, &vsm_glue, vsm_glue.nr_vps);
    qemu_register_reset(vsm_glue_reset, NULL);
    if (getenv("VSM_SPIN_DEBUG")) {
        QemuThread t;

        qemu_thread_create(&t, "vsm-spin-dbg", vsm_spin_debug_thread, NULL,
                           QEMU_THREAD_DETACHED);
    }
    inited = true;
}

int kvm_hv_vsm_vm_init(KVMState *s)
{
    int ret;

    if (!kvm_irqchip_is_split()) {
        error_report("hv-vsm requires kernel-irqchip=split");
        return -EINVAL;
    }

    if (s->vm_planes_max < 2) {
        ret = kvm_vm_enable_cap(s, KVM_CAP_PLANES, 0, 2);
        if (ret < 0) {
            error_report("hv-vsm: KVM_CAP_PLANES unavailable: %d", ret);
            return ret;
        }
        s->vm_planes_max = 2;
    }
    ret = kvm_vm_enable_cap(s, KVM_CAP_HYPERV_FORWARD_HCALL, 0, 1);
    if (ret < 0) {
        error_report("hv-vsm: KVM_CAP_HYPERV_FORWARD_HCALL unavailable: %d",
                     ret);
        return ret;
    }
    if (getenv("VSM_INKERNEL_SWITCH")) {
        ret = kvm_vm_enable_cap(s, KVM_CAP_HYPERV_VTL_SWITCH, 0, 1);
        if (ret < 0) {
            warn_report("hv-vsm: no in-kernel VTL switch, using the "
                        "userspace path");
        } else {
            vsm_inkernel_switch = true;
        }
    }
    return 0;
}

/*
 * Create the plane-1 twin of a vCPU at init time, before any vCPU runs:
 * creating a plane vCPU later would block on the vCPU mutex, which a vCPU
 * parked inside KVM_RUN (e.g. an AP in HLT) holds indefinitely.
 */
void kvm_hv_vsm_vcpu_init(X86CPU *cpu)
{
    uint32_t vp = hyperv_vp_index(CPU(cpu));
    int ret;

    vsm_glue_init_once();


    qemu_mutex_lock(&vsm_glue.lock);
    ret = vsm_plane_vcpu_create(&vsm_glue, 1, vp);
    qemu_mutex_unlock(&vsm_glue.lock);
    if (ret && ret != -EEXIST) {
        warn_report("hv-vsm: plane-1 vCPU creation for VP %u failed: %d",
                    vp, ret);
    }
}

/*
 * Plane vCPUs share the plane-0 CPUID (kvm_set_cpuid applies it across
 * all planes), but per-vCPU capabilities do not propagate: enable SynIC
 * on the plane-1 twin when plane 0 has the feature.
 */
int kvm_hv_vsm_vcpu_set_cpuid(X86CPU *cpu, struct kvm_cpuid2 *cpuid)
{
    uint32_t vp = hyperv_vp_index(CPU(cpu));
    int fd, ret;

    vsm_glue_init_once();

    fd = vsm_glue.plane1_vcpu_fd[vp];
    if (fd < 0) {
        return -ENODEV;
    }

    if (hyperv_feat_enabled(cpu, HYPERV_FEAT_SYNIC)) {
        /*
         * SYNIC (not SYNIC2): the TLFS overlay a VTL sees on enabling
         * SIMP/SIEFP is a fresh zeroed page.  Writing messages into
         * unzeroed guest RAM leaves stale bytes that read as an
         * unconsumed message, wedging delivery with -EAGAIN forever.
         * The twins are not migrated, so SYNIC2's keep-contents
         * behaviour buys nothing here.
         */
        struct kvm_enable_cap cap = {
            .cap = KVM_CAP_HYPERV_SYNIC2,
        };

        ret = ioctl(fd, KVM_ENABLE_CAP, &cap);
        if (ret < 0) {
            return -errno;
        }
    }
    return 0;
}

/*
 * Debug harness: when VSM_TRACE_AFTER_0XC is set in the environment,
 * enable single-stepping on the plane-1 twin after the Nth
 * ModifyVtlProtectionMask and append each stepped PC to
 * /tmp/vsm-trace.log until the trace limit is hit.
 */
static FILE *vsm_trace_file;
static long vsm_trace_remaining = -1;
static uint64_t vsm_bp_addr;
static uint64_t vsm_sk_base;

/* Minimal 4-level page walk through plane-1 guest page tables. */
static int vsm_vtl1_read(uint32_t vp, uint64_t va, void *buf, size_t len)
{
    struct kvm_sregs sregs;
    uint64_t table, pte = 0;
    int level;

    if (vsm_vcpu_get_sregs(&vsm_glue, 1, vp, &sregs)) {
        return -1;
    }
    table = sregs.cr3 & 0x000ffffffffff000ULL;
    for (level = 3; level >= 0; level--) {
        uint64_t idx = (va >> (12 + 9 * level)) & 0x1ff;

        physical_memory_read(table + idx * 8, &pte, 8);
        if (!(pte & 1)) {
            return -1;
        }
        if (level && (pte & 0x80)) { /* large page */
            uint64_t sz = 1ULL << (12 + 9 * level);

            physical_memory_read((pte & 0x000fffffffffe000ULL & ~(sz - 1)) +
                                 (va & (sz - 1)), buf, len);
            return 0;
        }
        table = pte & 0x000ffffffffff000ULL;
    }
    physical_memory_read(table + (va & 0xfff), buf, len);
    return 0;
}

static bool vsm_sc_fail_seen;

static void vsm_bp_hit(uint32_t vp)
{
    struct kvm_regs regs;
    struct kvm_guest_debug dbg = { 0 };
    uint64_t q;
    int i;

    if (vsm_vcpu_get_regs(&vsm_glue, 1, vp, &regs)) {
        return;
    }
    warn_report("hv-vsm bp: rip=%llx rsp=%llx rax=%llx rbx=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx r8=%llx r9=%llx",
                (unsigned long long)regs.rip, (unsigned long long)regs.rsp,
                (unsigned long long)regs.rax, (unsigned long long)regs.rbx,
                (unsigned long long)regs.rcx, (unsigned long long)regs.rdx,
                (unsigned long long)regs.rsi, (unsigned long long)regs.rdi,
                (unsigned long long)regs.r8, (unsigned long long)regs.r9);
    for (i = 0; i < 96; i++) {
        if (vsm_vtl1_read(vp, regs.rsp + i * 8, &q, 8)) {
            break;
        }
        if ((q >> 40) == 0xfffff8 && q - vsm_sk_base < 0x140000) {
            warn_report("hv-vsm bp stack[%03x]: rva %llx", i * 8,
                        (unsigned long long)(q - vsm_sk_base));
        }
    }

    /* Walk the bugcheck's referenced VA (rdx) level by level. */
    {
        struct kvm_sregs sregs;
        uint64_t table, pte = 0, va = regs.rdx;
        int level;

        if (!vsm_vcpu_get_sregs(&vsm_glue, 1, vp, &sregs)) {
            table = sregs.cr3 & 0x000ffffffffff000ULL;
            for (level = 3; level >= 0; level--) {
                uint64_t idx = (va >> (12 + 9 * level)) & 0x1ff;

                physical_memory_read(table + idx * 8, &pte, 8);
                warn_report("hv-vsm bp walk L%d[%03llx] = %llx", level + 1,
                            (unsigned long long)idx,
                            (unsigned long long)pte);
                if (!(pte & 1) || (level && (pte & 0x80))) {
                    break;
                }
                table = pte & 0x000ffffffffff000ULL;
            }
        }
    }
    ioctl(vsm_glue.plane1_vcpu_fd[vp], KVM_SET_GUEST_DEBUG, &dbg);
    vsm_bp_addr = 0;
}

bool kvm_hv_vsm_trace_step(X86CPU *cpu, uint64_t pc)
{
    if (vsm_bp_addr && pc == vsm_bp_addr) {
        vsm_bp_hit(hyperv_vp_index(CPU(cpu)));
        return true;
    }
    if (!vsm_trace_file) {
        return false;
    }
    fprintf(vsm_trace_file, "%u %" PRIx64 "\n",
            hyperv_vp_index(CPU(cpu)), pc);
    if (getenv("VSM_TRACE_SYNC") || (vsm_trace_remaining & 0x3ff) == 0) {
        fflush(vsm_trace_file);
    }
    if (--vsm_trace_remaining <= 0) {
        struct kvm_guest_debug dbg = { 0 };
        uint32_t vp = hyperv_vp_index(CPU(cpu));

        ioctl(vsm_glue.plane1_vcpu_fd[vp], KVM_SET_GUEST_DEBUG, &dbg);
        fflush(vsm_trace_file);
        fclose(vsm_trace_file);
        vsm_trace_file = NULL;
        warn_report("hv-vsm trace: limit reached, disabled");
    }
    return true;
}

static void vsm_trace_rearm(uint32_t vp)
{
    struct kvm_guest_debug dbg = {
        .control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
    };

    if (getenv("VSM_TRACE_AP") && vp != vsm_trace_vp) {
        return;         /* only the explicitly armed AP is stepped */
    }
    if (vsm_trace_file) {
        ioctl(vsm_glue.plane1_vcpu_fd[vp], KVM_SET_GUEST_DEBUG, &dbg);
    }
}

static void vsm_trace_maybe_start(X86CPU *cpu, uint16_t code)
{
    static int count_0xf;

    /* Trace ntos (plane0) from the VTL return after the EnableVpVtl burst. */
    if (vsm_trace_file || !getenv("VSM_TRACE_NT_AFTER_0XF")) {
        return;
    }
    if (code == 0xf) {
        count_0xf++;
        return;
    }
    if (code != 0x12 || count_0xf < 4) {
        return;
    }
    vsm_trace_file = fopen("/tmp/vsm-trace.log", "w");
    vsm_trace_remaining = 500000;
    if (vsm_trace_file) {
        struct kvm_guest_debug dbg = {
            .control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
        };

        if (kvm_vcpu_ioctl(CPU(cpu), KVM_SET_GUEST_DEBUG, &dbg)) {
            warn_report("hv-vsm trace: plane0 SET_GUEST_DEBUG failed");
        } else {
            warn_report("hv-vsm trace: plane0 stepping after EnableVpVtl burst");
        }
    }
}

/*
 * Handle a forwarded Hyper-V hypercall.  Returns true if consumed; the
 * result field is set either to the final status or, after a VTL switch,
 * to the shared RAX that the entered plane's pending in-kernel completion
 * must observe when it resumes.
 */
bool kvm_hv_vsm_handle_hcall(X86CPU *cpu, struct kvm_hyperv_exit *exit)
{
    uint32_t vp = hyperv_vp_index(CPU(cpu));
    struct hv_vsm_hcall_result res;
    enum hv_vsm_action action;

    vsm_glue_init_once();

    {
        uint16_t dbgcode = exit->u.hcall.input & 0xffff;

        if (dbgcode == 0x11 || dbgcode == 0x12) {
            static uint64_t last_sc_gpa;
            uint64_t va = exit->u.hcall.params[0];
            uint64_t gpa = 0;
            bool valid = false;

            if (dbgcode == 0x11 && va &&
                !vsm_vcpu_translate(&vsm_glue, 0, vp, va, &gpa, &valid,
                                    NULL) &&
                valid) {
                last_sc_gpa = gpa;
            }
            if (last_sc_gpa) {
                uint64_t q[8];
                physical_memory_read(last_sc_gpa, q, sizeof(q));
                if (dbgcode == 0x11 && q[0] == 0x20002 &&
                    getenv("VSM_TRACE_SVC2") && vsm_sc_fail_seen &&
                    !vsm_trace_file) {
                    struct kvm_guest_debug sdbg = {
                        .control = KVM_GUESTDBG_ENABLE |
                                   KVM_GUESTDBG_SINGLESTEP,
                    };

                    vsm_trace_file = fopen("/tmp/vsm-trace.log", "w");
                    vsm_trace_remaining = 400000;
                    if (vsm_trace_file &&
                        !ioctl(vsm_glue.plane1_vcpu_fd[vp],
                               KVM_SET_GUEST_DEBUG, &sdbg)) {
                        warn_report("hv-vsm trace: armed on AP-start svc 2");
                    }
                }
                if (dbgcode == 0x11 && q[0] == 0x1010002 && q[2] == 1 &&
                    q[3] == 2 && !vsm_sc_fail_seen && vsm_bp_addr) {
                    struct kvm_guest_debug dbg = {
                        .control = KVM_GUESTDBG_ENABLE |
                                   KVM_GUESTDBG_USE_HW_BP,
                    };

                    vsm_sc_fail_seen = true;
                    dbg.arch.debugreg[0] = vsm_bp_addr;
                    dbg.arch.debugreg[7] = 0x401;
                    if (ioctl(vsm_glue.plane1_vcpu_fd[vp],
                              KVM_SET_GUEST_DEBUG, &dbg)) {
                        warn_report("hv-vsm bp: late arm failed: %s",
                                    strerror(errno));
                    } else {
                        warn_report("hv-vsm bp: armed on failing svc");
                    }
                }
                if (vsm_dbg())
                fprintf(stderr,
                        "hv-vsm dbg: %s scpage@%llx %llx %llx %llx %llx | %llx %llx %llx %llx\n",
                        dbgcode == 0x11 ? "CALL" : "RET ",
                        (unsigned long long)last_sc_gpa,
                        (unsigned long long)q[0], (unsigned long long)q[1],
                        (unsigned long long)q[2], (unsigned long long)q[3],
                        (unsigned long long)q[4], (unsigned long long)q[5],
                        (unsigned long long)q[6], (unsigned long long)q[7]);
            }
        }
    }
    if (vsm_dbg()) {
        fprintf(stderr, "hv-vsm dbg: vp%u HC %04llx in=%llx out=%llx\n",
                vp,
                (unsigned long long)(exit->u.hcall.input & 0xffff),
                (unsigned long long)exit->u.hcall.params[0],
                (unsigned long long)exit->u.hcall.params[1]);
    }
    if ((exit->u.hcall.input & 0xffff) == 0x9a) {
        vsm_sc_fail_seen = true;   /* next svc-2 is the AP start */
    }
    if ((exit->u.hcall.input & 0xffff) == 0x99) {
        struct kvm_regs r;
        struct kvm_sregs sr;

        if (!vsm_vcpu_get_regs(&vsm_glue, 1, vp, &r) &&
            !vsm_vcpu_get_sregs(&vsm_glue, 1, vp, &sr)) {
            uint64_t ab0 = 0, ab1 = 0;
            struct kvm_lapic_state lap;

            vsm_vcpu_get_msr(&vsm_glue, 1, 0, 0x1b, &ab0);
            vsm_vcpu_get_msr(&vsm_glue, 1, 1, 0x1b, &ab1);
            if (!vsm_vcpu_ioctl_on(1, vsm_glue.plane1_vcpu_fd[1],
                                   KVM_GET_LAPIC, &lap)) {
                if (vsm_dbg())
                fprintf(stderr,
                        "hv-vsm dbg: P1V1 LAPIC id=%x spiv=%x\n",
                        *(uint32_t *)(lap.regs + 0x20),
                        *(uint32_t *)(lap.regs + 0xf0));
            }
            if (vsm_dbg())
            fprintf(stderr,
                    "hv-vsm dbg: SK99 vp%u cr3=%llx rip=%llx apicbase p1v0=%llx p1v1=%llx\n",
                    vp, (unsigned long long)sr.cr3,
                    (unsigned long long)r.rip,
                    (unsigned long long)ab0, (unsigned long long)ab1);
        }
    }
    if ((exit->u.hcall.input & 0xffff) == 0x8001 &&
        getenv("VSM_TRACE_AFTER_8001") && !vsm_trace_file) {
        struct kvm_guest_debug sdbg = {
            .control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
        };

        vsm_trace_file = fopen("/tmp/vsm-trace.log", "w");
        vsm_trace_remaining = 400000;
        if (vsm_trace_file &&
            !ioctl(vsm_glue.plane1_vcpu_fd[vp], KVM_SET_GUEST_DEBUG, &sdbg)) {
            warn_report("hv-vsm trace: plane1 stepping after 0x8001");
        }
    }
    if ((exit->u.hcall.input & 0xffff) == 0x99 && getenv("VSM_TRACE_AP") &&
        !vsm_trace_file) {
        struct {
            uint64_t partition_id;
            uint32_t vp_index;
        } QEMU_PACKED hdr;

        physical_memory_read(exit->u.hcall.params[0], &hdr, sizeof(hdr));
        if (getenv("VSM_TRACE_AP_VP")) {
            hdr.vp_index = atoi(getenv("VSM_TRACE_AP_VP"));
        }
        warn_report("hv-vsm trace: AP arm request vp%u", hdr.vp_index);
        if (hdr.vp_index < vsm_glue.nr_vps &&
            vsm_glue.plane1_vcpu_fd[hdr.vp_index] >= 0) {
            struct kvm_guest_debug sdbg = {
                .control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
            };

            vsm_trace_file = fopen("/tmp/vsm-trace.log", "w");
            vsm_trace_remaining = 400000;
            if (vsm_trace_file) {
                int rc = vsm_vcpu_ioctl_on(hdr.vp_index,
                                           vsm_glue.plane1_vcpu_fd[hdr.vp_index],
                                           KVM_SET_GUEST_DEBUG, &sdbg);

                warn_report("hv-vsm trace: arm AP vp%u plane1 rc=%d",
                            hdr.vp_index, rc);
                vsm_trace_vp = hdr.vp_index;
            }
        }
    }
    vsm_glue_lock_from_vcpu(CPU(cpu));
    if (vsm_inkernel_switch) {
        hv_vsm_set_active_vtl(vsm_glue.core, vp, exit->plane);
    }
    action = hv_vsm_handle_hcall(vsm_glue.core, vp, exit->u.hcall.input,
                                 exit->u.hcall.params[0],
                                 exit->u.hcall.params[1], &res);
    qemu_mutex_unlock(&vsm_glue.lock);
    if (action == HV_VSM_COMPLETE) {
        if (vsm_dbg())
            fprintf(stderr, "hv-vsm dbg: vp%u HC %04llx res=%llx\n", vp,
                (unsigned long long)(exit->u.hcall.input & 0xffff),
                (unsigned long long)res.result);
    }
    vsm_trace_maybe_start(cpu, exit->u.hcall.input & 0xffff);
    vsm_trace_rearm(vp);

    if ((exit->u.hcall.input & 0xffff) == 0x12 && action == HV_VSM_SWITCHED) {
        struct kvm_regs r0;

        if (!vsm_vcpu_get_regs(&vsm_glue, 0, vp, &r0)) {
            if (vsm_dbg())
            fprintf(stderr,
                    "hv-vsm dbg: RETREGS rax=%llx rbx=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx r8=%llx\n",
                    (unsigned long long)res.resume_rax,
                    (unsigned long long)r0.rbx, (unsigned long long)r0.rcx,
                    (unsigned long long)r0.rdx, (unsigned long long)r0.rsi,
                    (unsigned long long)r0.rdi, (unsigned long long)r0.r8);
        }
    }

    if ((exit->u.hcall.input & 0xffff) == 0xf && getenv("VSM_BP_RVA") &&
        !vsm_bp_addr) {
        struct kvm_regs regs;
        struct kvm_guest_debug dbg = {
            .control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP,
        };

        /* VTL1 initial RIP = ShvlpVtl1Entry (RVA 0xdc530 in this build). */
        (void)dbg;
        if (!vsm_vcpu_get_regs(&vsm_glue, 1, vp, &regs)) {
            vsm_sk_base = regs.rip - 0xdc530;
            vsm_bp_addr = vsm_sk_base +
                          strtoull(getenv("VSM_BP_RVA"), NULL, 0);
            warn_report("hv-vsm bp: target %llx (base %llx), arming deferred",
                        (unsigned long long)vsm_bp_addr,
                        (unsigned long long)vsm_sk_base);
        }
    }

    switch (action) {
    case HV_VSM_COMPLETE:
        exit->u.hcall.result = res.result;
        return true;
    case HV_VSM_SWITCHED:
        vsm_refresh_env_xcr0(CPU(cpu));
        exit->u.hcall.result = res.resume_rax;
        return true;
    case HV_VSM_RAISE_UD:
        exit->u.hcall.result = KVM_HV_HCALL_RESULT_RAISE_UD;
        /*
         * VtlCall/VtlReturn are retired eagerly in the kernel with no
         * pending completion to raise the fault, so inject #UD directly.
         */
        if ((exit->u.hcall.input & 0xffff) == 0x11 ||
            (exit->u.hcall.input & 0xffff) == 0x12) {
            vsm_vcpu_queue_exception(&vsm_glue, exit->plane, vp,
                                     6 /* #UD */, false, 0, false, 0);
        }
        return true;
    default:
        return false;
    }
}

/*
 * Protection-violation exits (KVM_EXIT_MEMORY_FAULT with R/W/X flags) on
 * a VTL with a higher one enabled enter the higher VTL.  Returns 0 if the
 * fault was converted into a VTL entry.
 */
/*
 * The kernel reports a pending interrupt for a higher, suspended VTL;
 * enter that VTL.  Returns 0 when the planes were switched.
 */
int kvm_hv_vsm_handle_vtl_interrupt(X86CPU *cpu, uint8_t target_vtl)
{
    uint32_t vp = hyperv_vp_index(CPU(cpu));
    struct hv_vsm_hcall_result res;
    enum hv_vsm_action action;

    if (!hyperv_feat_enabled(cpu, HYPERV_FEAT_VSM)) {
        return -1;
    }

    vsm_glue_init_once();

    vsm_glue_lock_from_vcpu(CPU(cpu));
    action = hv_vsm_vtl_interrupt_entry(vsm_glue.core, vp, target_vtl, &res);
    qemu_mutex_unlock(&vsm_glue.lock);

    if (vsm_dbg()) {
        fprintf(stderr, "hv-vsm dbg: VTLINTR vp%u -> vtl%u action=%d\n",
                vp, target_vtl, (int)action);
    }
    if (action != HV_VSM_SWITCHED) {
        /*
         * Refused entry (e.g. the target VTL has not enabled its VP
         * assist page yet): resume the current VTL, the event waits in
         * the target's IRR.  The kernel's pended marker is single-shot,
         * so this does not loop.
         */
        return 0;
    }
    vsm_refresh_env_xcr0(CPU(cpu));
    return 0;
}

/*
 * A lower-VTL descriptor-table write hit an armed register intercept:
 * reflect it into the higher VTL.
 */
int kvm_hv_vsm_handle_reg_intercept(X86CPU *cpu, struct kvm_hyperv_exit *exit)
{
    uint32_t vp = hyperv_vp_index(CPU(cpu));
    struct hv_vsm_hcall_result res;
    enum hv_vsm_action action;

    if (!hyperv_feat_enabled(cpu, HYPERV_FEAT_VSM)) {
        return -1;
    }

    vsm_glue_init_once();

    vsm_glue_lock_from_vcpu(CPU(cpu));
    action = hv_vsm_deliver_reg_intercept(vsm_glue.core, vp,
                                          exit->u.reg_intercept.reg,
                                          exit->u.reg_intercept.base,
                                          exit->u.reg_intercept.limit,
                                          exit->u.reg_intercept.rip,
                                          exit->u.reg_intercept.insn_len,
                                          &res);
    qemu_mutex_unlock(&vsm_glue.lock);

    if (action == HV_VSM_RAISE_UD) {
        /*
         * Undeliverable (target SIMP disabled): the core queued #UD into
         * the faulting plane; resume it without switching. The kernel
         * rewound RIP, so the fault hits the intercepted instruction.
         */
        return 0;
    }
    if (action != HV_VSM_SWITCHED) {
        error_report("hv-vsm: register intercept for VP %u reg %x failed",
                     vp, exit->u.reg_intercept.reg);
        return -1;
    }
    return 0;
}

int kvm_hv_vsm_handle_memory_fault(X86CPU *cpu, struct kvm_run *run)
{
    uint32_t vp = hyperv_vp_index(CPU(cpu));
    struct hv_vsm_hcall_result res;
    enum hv_vsm_action action;
    int access;

    if (!hyperv_feat_enabled(cpu, HYPERV_FEAT_VSM)) {
        return -1;
    }

    vsm_glue_init_once();

    if (run->memory_fault.flags & KVM_MEMORY_EXIT_FLAG_EXEC) {
        access = HV_VSM_INTERCEPT_ACCESS_EXECUTE;
    } else if (run->memory_fault.flags & KVM_MEMORY_EXIT_FLAG_WRITE) {
        access = HV_VSM_INTERCEPT_ACCESS_WRITE;
    } else {
        access = HV_VSM_INTERCEPT_ACCESS_READ;
    }

    struct hv_vsm_fault_info fi = {
        .gva = run->memory_fault.gva,
        .gva_valid = !!(run->memory_fault.flags &
                        KVM_MEMORY_EXIT_FLAG_GVA_VALID),
        .insn_len = MIN(run->memory_fault.insn_len, 16u),
    };
    memcpy(fi.insn_bytes, run->memory_fault.insn_bytes, fi.insn_len);

    vsm_glue_lock_from_vcpu(CPU(cpu));
    if (vsm_inkernel_switch) {
        /* Only VTL0 pages carry protections, so the fault is VTL0's. */
        hv_vsm_set_active_vtl(vsm_glue.core, vp, 0);
    }
    action = hv_vsm_handle_protection_fault(vsm_glue.core,
                                            run->memory_fault.gpa, access,
                                            vp, &fi, &res);
    qemu_mutex_unlock(&vsm_glue.lock);

    if (action == HV_VSM_RAISE_UD) {
        /*
         * Undeliverable (target SIMP disabled): the core queued #UD into
         * the faulting plane; resume it without switching. The faulting
         * instruction never retired, so the fault hits it in place.
         */
        return 0;
    }
    if (action != HV_VSM_SWITCHED) {
        error_report("hv-vsm: unhandled protection fault at gpa %" PRIx64
                     " flags %" PRIx64, (uint64_t)run->memory_fault.gpa,
                     (uint64_t)run->memory_fault.flags);
        return -1;
    }

    vsm_refresh_env_xcr0(CPU(cpu));
    run->hyperv.u.hcall.result = res.resume_rax;
    return 0;
}
