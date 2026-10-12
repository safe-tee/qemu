/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Hyper-V VSM (Virtual Secure Mode) userspace emulation core.
 *
 * VMM-agnostic: see hv-vsm.h for the embedding contract.  One VTL is one
 * KVM plane; VTL transitions are plane run-state flips plus a copy of the
 * VTL-shared register state between the plane vCPUs.  The shared/private
 * split follows the TLFS: general purpose registers (except RSP), CR2 and
 * the FPU/XMM state are shared across VTLs; RIP, RSP, RFLAGS, control
 * registers, segmentation, descriptor tables and the syscall/sysenter MSRs
 * are private per VTL.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "hv-vsm.h"

static bool vsm_dbg(void)
{
    static int on = -1;

    if (on < 0) {
        on = getenv("VSM_DEBUG") ? 1 : 0;
    }
    return on;
}


#define HV_VSM_ACCESS_VSM               (1u << 16)
#define HV_VSM_ACCESS_VP_REGISTERS      (1u << 17)

/* CR4.PCIDE: set on VTL1 entry contexts, matching observed Hyper-V. */
#define HV_VSM_X86_CR4_PCIDE            (1ULL << 17)
#define HV_VSM_X86_EFLAGS_FIXED         (1ULL << 1)
#define HV_VSM_X86_CR0_PG               (1ULL << 31)
#define HV_VSM_X86_EFER_LME             (1ULL << 8)
#define HV_VSM_X86_EFER_LMA             (1ULL << 10)

#define HV_VSM_MSR_PAT                  0x277

struct hv_vsm *hv_vsm_new(const struct hv_vsm_host_ops *ops, void *vm,
                          uint32_t nr_vps)
{
    struct hv_vsm *vsm = calloc(1, sizeof(*vsm));

    if (!vsm) {
        return NULL;
    }
    vsm->vp = calloc(nr_vps, sizeof(*vsm->vp));
    if (!vsm->vp) {
        free(vsm);
        return NULL;
    }
    vsm->ops = ops;
    vsm->vm = vm;
    vsm->nr_vps = nr_vps;
    for (uint32_t i = 0; i < nr_vps; i++) {
        vsm->vp[i].enabled_vtl_set = 1; /* VTL0 */
    }
    return vsm;
}

void hv_vsm_free(struct hv_vsm *vsm)
{
    if (vsm) {
        free(vsm->pending_prot);
        free(vsm->applied_prot);
        free(vsm->vp);
        free(vsm);
    }
}

uint32_t hv_vsm_cpuid_privileges(void)
{
    return HV_VSM_ACCESS_VSM | HV_VSM_ACCESS_VP_REGISTERS;
}

static uint64_t mkstatus(uint16_t status, uint16_t reps)
{
    return (uint64_t)status |
           ((uint64_t)reps << HV_VSM_HYPERCALL_REP_COMP_SHIFT);
}

static uint16_t partition_max_enabled_vtl(struct hv_vsm *vsm)
{
    uint16_t set = 0;

    for (uint32_t i = 0; i < vsm->nr_vps; i++) {
        set |= vsm->vp[i].enabled_vtl_set;
    }
    return set & 2 ? 1 : 0;
}

static int resolve_vp(struct hv_vsm *vsm, uint32_t caller, uint32_t vp_index,
                      uint32_t *vp)
{
    if (vp_index == HV_VSM_VP_INDEX_SELF) {
        *vp = caller;
        return 0;
    }
    if (vp_index >= vsm->nr_vps) {
        return -1;
    }
    *vp = vp_index;
    return 0;
}

void hv_vsm_reset(struct hv_vsm *vsm)
{
    uint32_t i;

    vsm->vtl1_partition_enabled = false;
    vsm->mbec_requested = false;
    memset(vsm->partition_config, 0, sizeof(vsm->partition_config));
    free(vsm->pending_prot);
    vsm->pending_prot = NULL;
    vsm->nr_pending_prot = 0;
    vsm->pending_prot_cap = 0;
    for (i = 0; i < vsm->nr_applied_prot; i++) {
        vsm->ops->set_memory_attributes(vsm->vm, 0,
                                        (vsm->applied_prot[i] >> 8) << 12,
                                        1ULL << 12, 0);
    }
    free(vsm->applied_prot);
    vsm->applied_prot = NULL;
    vsm->nr_applied_prot = 0;
    vsm->applied_prot_cap = 0;
    memset(vsm->thunked_pages, 0, sizeof(vsm->thunked_pages));
    vsm->nr_thunked = 0;
    for (i = 0; i < vsm->nr_vps; i++) {
        memset(&vsm->vp[i], 0, sizeof(vsm->vp[i]));
        vsm->vp[i].enabled_vtl_set = 1; /* VTL0 */
    }
}

static void vsm_log(struct hv_vsm *vsm, const char *what, uint64_t val)
{
    char buf[96];

    if (!vsm->ops->log) {
        return;
    }
    snprintf(buf, sizeof(buf), "hv-vsm: unimplemented %s %#llx", what,
             (unsigned long long)val);
    vsm->ops->log(vsm->vm, buf);
}

static void store_segment(const struct kvm_segment *seg,
                          struct hv_vsm_x64_segment_register *hv)
{
    memset(hv, 0, sizeof(*hv));
    hv->base = seg->base;
    hv->limit = seg->limit;
    hv->selector = seg->selector;
    hv->segment_type = seg->type;
    hv->non_system_segment = seg->s;
    hv->descriptor_privilege_level = seg->dpl;
    hv->present = seg->present;
    hv->available = seg->avl;
    hv->_long = seg->l;
    hv->_default = seg->db;
    hv->granularity = seg->g;
}

/*
 * TLFS hv_x64_vp_execution_state for an intercept message header, matching
 * the reference host's deliver_reg_intercept()/deliver_gpa_intercept(): CPL
 * follows the hardware CPL derivation its get_cpl() uses (real mode 0,
 * virtual-8086 mode 3, otherwise SS.DPL), CR0.PE/CR0.AM/EFER.LMA come from
 * the faulting plane, and debug_active/interruption_pending are always 0.
 */
static uint16_t intercept_exec_state(const struct kvm_regs *regs,
                                     const struct kvm_sregs *sregs)
{
    uint16_t cpl;

    if (!(sregs->cr0 & 1)) {                /* !CR0.PE: real mode */
        cpl = 0;
    } else if (regs->rflags & (1 << 17)) {  /* EFLAGS.VM: virtual-8086 */
        cpl = 3;
    } else {
        cpl = sregs->ss.dpl & 3;
    }
    return cpl |
           ((sregs->cr0 & 1) ? 1 << 2 : 0) |        /* PE */
           ((sregs->cr0 >> 18 & 1) ? 1 << 3 : 0) |  /* AM */
           ((sregs->efer >> 10 & 1) ? 1 << 4 : 0);  /* LMA */
}

static struct kvm_segment *seg_of(struct kvm_sregs *s, uint32_t name)
{
    switch (name) {
    case HV_VSM_X64_REG_ES: return &s->es;
    case HV_VSM_X64_REG_CS: return &s->cs;
    case HV_VSM_X64_REG_SS: return &s->ss;
    case HV_VSM_X64_REG_DS: return &s->ds;
    case HV_VSM_X64_REG_FS: return &s->fs;
    case HV_VSM_X64_REG_GS: return &s->gs;
    case HV_VSM_X64_REG_LDTR: return &s->ldt;
    case HV_VSM_X64_REG_TR: return &s->tr;
    default: return NULL;
    }
}

/* MSR index backing an 0x8xxxx/0x9xxxx register, 0 if none. */
static uint32_t reg_msr(uint32_t name)
{
    switch (name) {
    case HV_VSM_X64_REG_KERNEL_GS_BASE: return 0xc0000102;
    case HV_VSM_X64_REG_APIC_BASE: return 0x1b;
    case HV_VSM_X64_REG_PAT: return 0x277;
    case HV_VSM_X64_REG_SYSENTER_CS: return 0x174;
    case HV_VSM_X64_REG_SYSENTER_ESP: return 0x175;
    case HV_VSM_X64_REG_SYSENTER_EIP: return 0x176;
    case HV_VSM_X64_REG_STAR: return 0xc0000081;
    case HV_VSM_X64_REG_LSTAR: return 0xc0000082;
    case HV_VSM_X64_REG_CSTAR: return 0xc0000083;
    case HV_VSM_X64_REG_SFMASK: return 0xc0000084;
    case HV_VSM_X64_REG_TSC_AUX: return 0xc0000103;
    case HV_VSM_REG_HYPERCALL: return 0x40000001;
    case HV_VSM_REG_GUEST_OS_ID: return HV_VSM_MSR_GUEST_OS_ID;
    case HV_VSM_REG_REFERENCE_TSC: return 0x40000021;
    case HV_VSM_REG_VP_ASSIST_PAGE: return HV_VSM_MSR_VP_ASSIST_PAGE;
    default: return 0;
    }
}

static __u64 *gpr_slot(struct kvm_regs *r, unsigned idx)
{
    switch (idx) {
    case 0: return &r->rax;
    case 1: return &r->rcx;
    case 2: return &r->rdx;
    case 3: return &r->rbx;
    case 4: return &r->rsp;
    case 5: return &r->rbp;
    case 6: return &r->rsi;
    case 7: return &r->rdi;
    case 8: return &r->r8;
    case 9: return &r->r9;
    case 10: return &r->r10;
    case 11: return &r->r11;
    case 12: return &r->r12;
    case 13: return &r->r13;
    case 14: return &r->r14;
    case 15: return &r->r15;
    default: return NULL;
    }
}

static void load_segment(const struct hv_vsm_x64_segment_register *hv,
                         struct kvm_segment *seg)
{
    seg->base = hv->base;
    seg->limit = hv->limit;
    seg->selector = hv->selector;
    seg->type = hv->segment_type;
    seg->s = hv->non_system_segment;
    seg->dpl = hv->descriptor_privilege_level;
    seg->present = hv->present;
    seg->avl = hv->available;
    seg->l = hv->_long;
    seg->db = hv->_default;
    seg->g = hv->granularity;
    seg->unusable = !hv->present;
}

/*
 * Apply an EnableVpVtl initial context to a freshly created plane vCPU.
 * CR4.PCIDE is forced on: traces of real Hyper-V show the VTL1 context
 * starts with PCIDE set regardless of the caller-provided value, and
 * Windows (WS2025 resume) depends on it.
 */
static int apply_vp_context(struct hv_vsm *vsm, int plane, uint32_t vp,
                            const struct hv_vsm_init_vp_context *ctx)
{
    const struct hv_vsm_host_ops *ops = vsm->ops;
    struct kvm_sregs sregs;
    struct kvm_regs regs;
    int ret;

    ret = ops->vcpu_get_sregs(vsm->vm, plane, vp, &sregs);
    if (ret) {
        fprintf(stderr, "hv-vsm dbg: APPLYCTX get_sregs plane=%d vp=%u ret=%d\n", plane, vp, ret);
        return ret;
    }

    load_segment(&ctx->cs, &sregs.cs);
    load_segment(&ctx->ds, &sregs.ds);
    load_segment(&ctx->es, &sregs.es);
    load_segment(&ctx->fs, &sregs.fs);
    load_segment(&ctx->gs, &sregs.gs);
    load_segment(&ctx->ss, &sregs.ss);
    load_segment(&ctx->tr, &sregs.tr);
    load_segment(&ctx->ldtr, &sregs.ldt);
    sregs.gdt.base = ctx->gdtr.base;
    sregs.gdt.limit = ctx->gdtr.limit;
    sregs.idt.base = ctx->idtr.base;
    sregs.idt.limit = ctx->idtr.limit;
    sregs.cr0 = ctx->cr0;
    sregs.cr3 = ctx->cr3;
    sregs.cr4 = ctx->cr4 | HV_VSM_X86_CR4_PCIDE;
    sregs.efer = ctx->efer;
    /*
     * EFER.LMA is hardware-derived, and the initial VP context carries
     * only what software wrote: ntoskrnl's AP start context has LME set
     * with LMA clear. KVM_SET_SREGS validates LMA against LME and
     * CR0.PG, so derive it the way hardware would.
     */
    if ((sregs.efer & HV_VSM_X86_EFER_LME) &&
        (sregs.cr0 & HV_VSM_X86_CR0_PG)) {
        sregs.efer |= HV_VSM_X86_EFER_LMA;
    }

    ret = ops->vcpu_set_sregs(vsm->vm, plane, vp, &sregs);
    if (ret) {
        fprintf(stderr, "hv-vsm dbg: APPLYCTX set_sregs plane=%d vp=%u ret=%d cr0=%llx cr3=%llx cr4=%llx efer=%llx cs=%x/%llx l=%d\n",
                plane, vp, ret, (unsigned long long)sregs.cr0,
                (unsigned long long)sregs.cr3, (unsigned long long)sregs.cr4,
                (unsigned long long)sregs.efer, sregs.cs.selector,
                (unsigned long long)sregs.cs.base, sregs.cs.l);
        return ret;
    }

    ret = ops->vcpu_get_regs(vsm->vm, plane, vp, &regs);
    if (ret) {
        fprintf(stderr, "hv-vsm dbg: APPLYCTX get_regs plane=%d vp=%u ret=%d\n", plane, vp, ret);
        return ret;
    }
    regs.rip = ctx->rip;
    regs.rsp = ctx->rsp;
    regs.rflags = ctx->rflags | HV_VSM_X86_EFLAGS_FIXED;
    ret = ops->vcpu_set_regs(vsm->vm, plane, vp, &regs);
    if (ret) {
        fprintf(stderr, "hv-vsm dbg: APPLYCTX set_regs plane=%d vp=%u ret=%d\n", plane, vp, ret);
        return ret;
    }

    ret = ops->vcpu_set_msr(vsm->vm, plane, vp, HV_VSM_MSR_PAT,
                            ctx->msr_cr_pat);
    if (ret) {
        fprintf(stderr, "hv-vsm dbg: APPLYCTX set_msr PAT plane=%d vp=%u ret=%d\n", plane, vp, ret);
    }
    return ret;
}

/*
 * Thunks written into the hypercall page.  Each loads the call code into
 * ECX and jumps to the hypervisor's own stub at offset 0, so the actual
 * VMCALL/VMMCALL instruction (and its RET) stays hypervisor-provided.
 */
static void write_thunk(uint8_t *buf, size_t off, uint16_t code)
{
    buf[0] = 0x48;                      /* mov %rcx, %rax */
    buf[1] = 0x89;
    buf[2] = 0xc8;
    buf[3] = 0xb9;                      /* mov $code, %ecx */
    buf[4] = code & 0xff;
    buf[5] = code >> 8;
    buf[6] = 0;
    buf[7] = 0;
    buf[8] = 0xeb;                      /* jmp rel8 to offset 0 */
    buf[9] = (uint8_t)(0x100 - (off + 10));
}

static void ensure_thunks(struct hv_vsm *vsm, uint8_t vtl, uint32_t vp)
{
    uint64_t gpa;
    uint8_t thunk[10];
    unsigned i;

    gpa = vsm->ops->hcall_page_gpa(vsm->vm, vtl, vp);
    if (!gpa) {
        return;
    }
    for (i = 0; i < vsm->nr_thunked; i++) {
        if (vsm->thunked_pages[i] == gpa) {
            return;
        }
    }
    if (vsm->nr_thunked == sizeof(vsm->thunked_pages) /
                           sizeof(vsm->thunked_pages[0])) {
        return;
    }

    write_thunk(thunk, HV_VSM_VTL_CALL_OFFSET, HV_VSM_CALL_VTL_CALL);
    vsm->ops->guest_write(vsm->vm, gpa + HV_VSM_VTL_CALL_OFFSET,
                          thunk, sizeof(thunk));
    write_thunk(thunk, HV_VSM_VTL_RETURN_OFFSET, HV_VSM_CALL_VTL_RETURN);
    vsm->ops->guest_write(vsm->vm, gpa + HV_VSM_VTL_RETURN_OFFSET,
                          thunk, sizeof(thunk));
    vsm->thunked_pages[vsm->nr_thunked++] = gpa;
}

/* VP assist page GPA for (plane, vp), 0 unless enabled. */
static uint64_t assist_page_gpa(struct hv_vsm *vsm, int plane, uint32_t vp)
{
    uint64_t val;

    if (!vsm->ops->vcpu_get_msr ||
        vsm->ops->vcpu_get_msr(vsm->vm, plane, vp,
                               HV_VSM_MSR_VP_ASSIST_PAGE, &val)) {
        return 0;
    }
    if (!(val & HV_VSM_MSR_VP_ASSIST_ENABLE)) {
        return 0;
    }
    return val & ~(uint64_t)0xfff;
}

/* VTL-shared state copy: GPRs except RSP (RIP/RFLAGS private), CR2, FPU. */
static int copy_shared_state(struct hv_vsm *vsm, uint32_t vp, int from, int to)
{
    const struct hv_vsm_host_ops *ops = vsm->ops;
    struct kvm_regs src, dst;
    struct kvm_sregs ssrc, sdst;
    struct kvm_fpu fpu;
    int ret;

    ret = ops->vcpu_get_regs(vsm->vm, from, vp, &src);
    ret = ret ?: ops->vcpu_get_regs(vsm->vm, to, vp, &dst);
    if (ret) {
        return ret;
    }
    dst.rax = src.rax;
    dst.rbx = src.rbx;
    dst.rcx = src.rcx;
    dst.rdx = src.rdx;
    dst.rsi = src.rsi;
    dst.rdi = src.rdi;
    dst.rbp = src.rbp;
    dst.r8 = src.r8;
    dst.r9 = src.r9;
    dst.r10 = src.r10;
    dst.r11 = src.r11;
    dst.r12 = src.r12;
    dst.r13 = src.r13;
    dst.r14 = src.r14;
    dst.r15 = src.r15;
    ret = ops->vcpu_set_regs(vsm->vm, to, vp, &dst);
    if (ret) {
        return ret;
    }

    ret = ops->vcpu_get_sregs(vsm->vm, from, vp, &ssrc);
    ret = ret ?: ops->vcpu_get_sregs(vsm->vm, to, vp, &sdst);
    if (ret) {
        return ret;
    }
    if (sdst.cr2 != ssrc.cr2) {
        sdst.cr2 = ssrc.cr2;
        ret = ops->vcpu_set_sregs(vsm->vm, to, vp, &sdst);
        if (ret) {
            return ret;
        }
    }

    if (ops->vcpu_copy_xstate) {
        return ops->vcpu_copy_xstate(vsm->vm, from, to, vp);
    }
    ret = ops->vcpu_get_fpu(vsm->vm, from, vp, &fpu);
    ret = ret ?: ops->vcpu_set_fpu(vsm->vm, to, vp, &fpu);
    return ret;
}

static int switch_vtl(struct hv_vsm *vsm, uint32_t vp, int from, int to)
{
    const struct hv_vsm_host_ops *ops = vsm->ops;
    int ret;

    if (getenv("VSM_SW_LOG")) {
        fprintf(stderr, "hv-vsm dbg: SW vp%u %d->%d\n", vp, from, to);
    }

    /*
     * Validate the target's pending event (HvRegisterPendingEvent0)
     * before touching any state: the set path accepted the raw value,
     * and the reference host rejects an unknown event type here, at
     * delivery. The failed attempt consumes the event, and the aborted
     * switch becomes #UD in the still-active VTL (the VtlCall/VtlReturn
     * paths map a switch_vtl() failure to HV_VSM_RAISE_UD).
     */
    if (vsm->vp[vp].pending_event[to].event_pending &&
        vsm->vp[vp].pending_event[to].event_type != 0) {
        if (vsm_dbg()) {
            fprintf(stderr, "vsm-ev0dlv: vp%u to_vtl%d bad type=%d, "
                    "failing the switch\n", vp, to,
                    vsm->vp[vp].pending_event[to].event_type);
        }
        vsm->vp[vp].pending_event[to].event_pending = 0;
        return -1;
    }

    ret = copy_shared_state(vsm, vp, from, to);
    if (ret) {
        return ret;
    }
    ret = ops->vcpu_set_run_state(vsm->vm, to, vp, true);
    ret = ret ?: ops->vcpu_set_run_state(vsm->vm, from, vp, false);
    if (ret) {
        return ret;
    }
    vsm->vp[vp].active_vtl = to;

    /* Deliver a pending event (HvRegisterPendingEvent0) at this VTL. */
    if (vsm->vp[vp].pending_event[to].event_pending &&
        ops->vcpu_queue_exception) {
        union hv_vsm_pending_event *ev = &vsm->vp[vp].pending_event[to];

        /*
         * The reference host drops exception_parameter (no CR2/DR6
         * payload; verified by unit test against it) even though the
         * TLFS describes it as the #PF address.  Match the reference:
         * a divergence here is guest-visible in CR2.
         */
        if (vsm_dbg()) fprintf(stderr, "vsm-ev0dlv: vp%u to_vtl%d vector=0x%x err=%x/%d\n",
                vp, to, ev->vector, ev->error_code, ev->deliver_error_code);
        ops->vcpu_queue_exception(vsm->vm, to, vp, ev->vector,
                                  ev->deliver_error_code, ev->error_code,
                                  false, 0);
        ev->event_pending = 0;
    }
    return 0;
}

/*
 * TLFS overlay pages (hypercall page, VP assist pages) are not subject to
 * the GPA access rights of the underlying page while the overlay is active,
 * so VTL protections must not revoke access to them: KVM materializes
 * overlays by writing into guest RAM rather than remapping, and protecting
 * e.g. the hypercall page would make the lower VTL fault on its very next
 * hypercall.
 */
/*
 * Intercept messages are consumed through SINT0: raise the vector the
 * target VTL programmed there so its entry dispatches to the handler.
 */
static void assert_sint0(struct hv_vsm *vsm, uint8_t vtl, uint32_t vp)
{
    uint64_t sint0 = 0;

    if (!vsm->ops->assert_interrupt ||
        vsm->ops->vcpu_get_msr(vsm->vm, vtl, vp, HV_VSM_MSR_SINT0, &sint0) ||
        (sint0 & HV_VSM_SINT_MASKED)) {
        return;
    }
    /* vp index == APIC ID in the configurations we run */
    vsm->ops->assert_interrupt(vsm->vm, vtl, vp, sint0 & 0xff, 0, false);
}

/* Write into a plane's SIMP: the overlay buffer when installed, else RAM. */
static void simp_write(struct hv_vsm *vsm, uint8_t vtl, uint64_t simp,
                       const void *data, size_t len)
{
    uint64_t gpa = simp & ~(uint64_t)0xfff;
    void *buf;

    if (vsm->ops->overlay_ptr &&
        (buf = vsm->ops->overlay_ptr(vsm->vm, vtl, gpa >> 12))) {
        memcpy(buf, data, len);
        return;
    }
    vsm->ops->guest_write(vsm->vm, gpa, data, len);
}

static bool gpa_is_overlay_page(struct hv_vsm *vsm, uint8_t vtl, uint64_t gpa)
{
    uint64_t page = gpa & ~(uint64_t)0xfff;
    uint32_t vp;

    if (vsm->ops->hcall_page_gpa &&
        (vsm->ops->hcall_page_gpa(vsm->vm, vtl, 0) & ~(uint64_t)0xfff) ==
        page) {
        return true;
    }
    for (vp = 0; vp < vsm->nr_vps; vp++) {
        if ((assist_page_gpa(vsm, vtl, vp) & ~(uint64_t)0xfff) == page) {
            return true;
        }
    }
    return false;
}

static bool vtl_protection_enabled(struct hv_vsm *vsm, uint8_t vtl)
{
    return vsm->partition_config[vtl] &
           HV_VSM_PARTITION_CONFIG_ENABLE_VTL_PROTECTION;
}

/*
 * Record or apply one page protection.  Until the configuring VTL sets
 * VsmPartitionConfig.EnableVtlProtection, protections are latent: TLFS
 * enforcement starts only when the bit is set, and the Windows secure
 * kernel configures thousands of pages (including code it still runs
 * under VTL0 during bootstrap) before enabling enforcement.
 */
static int record_applied_prot(struct hv_vsm *vsm, uint64_t gfn,
                               uint64_t attrs)
{
    if (vsm->nr_applied_prot == vsm->applied_prot_cap) {
        unsigned cap = vsm->applied_prot_cap ? vsm->applied_prot_cap * 2 :
                       1024;
        uint64_t *p = realloc(vsm->applied_prot, cap * sizeof(*p));

        if (!p) {
            return -1;
        }
        vsm->applied_prot = p;
        vsm->applied_prot_cap = cap;
    }
    vsm->applied_prot[vsm->nr_applied_prot++] = gfn << 8 | (attrs & 0xff);
    return 0;
}

static int apply_protection(struct hv_vsm *vsm, uint8_t owner_vtl,
                            uint8_t target_vtl, uint64_t gfn, uint64_t attrs)
{
    if (gpa_is_overlay_page(vsm, target_vtl, gfn << 12)) {
        return 0;
    }
    if (!vtl_protection_enabled(vsm, owner_vtl)) {
        if (vsm->nr_pending_prot == vsm->pending_prot_cap) {
            unsigned cap = vsm->pending_prot_cap ?
                           vsm->pending_prot_cap * 2 : 1024;
            uint64_t *p = realloc(vsm->pending_prot, cap * sizeof(*p));

            if (!p) {
                return -1;
            }
            vsm->pending_prot = p;
            vsm->pending_prot_cap = cap;
        }
        vsm->pending_prot[vsm->nr_pending_prot++] = gfn << 8 | (attrs & 0xff);
        return 0;
    }
    if (record_applied_prot(vsm, gfn, attrs)) {
        return -1;
    }
    return vsm->ops->set_memory_attributes(vsm->vm, target_vtl, gfn << 12,
                                           1ULL << 12, attrs);
}

/*
 * Apply one contiguous gfn run with a single ranged memory-attributes
 * call.  Per-gfn bookkeeping (overlay skip, pre-enable deferral, applied
 * record) still walks each page; overlay pages split the ranged call.
 */
static int apply_protection_run(struct hv_vsm *vsm, uint8_t owner_vtl,
                                uint8_t target_vtl, uint64_t gfn,
                                uint64_t npages, uint64_t attrs)
{
    uint64_t i, seg_start = 0, seg_len = 0;

    for (i = 0; i < npages; i++) {
        uint64_t g = gfn + i;

        if (gpa_is_overlay_page(vsm, target_vtl, g << 12) ||
            !vtl_protection_enabled(vsm, owner_vtl)) {
            if (seg_len) {
                if (vsm->ops->set_memory_attributes(vsm->vm, target_vtl,
                                                    seg_start << 12,
                                                    seg_len << 12, attrs)) {
                    return -1;
                }
                seg_len = 0;
            }
            if (!gpa_is_overlay_page(vsm, target_vtl, g << 12) &&
                apply_protection(vsm, owner_vtl, target_vtl, g, attrs)) {
                return -1;      /* pre-enable deferral path */
            }
            continue;
        }
        if (record_applied_prot(vsm, g, attrs)) {
            return -1;
        }
        if (!seg_len) {
            seg_start = g;
        }
        seg_len++;
    }
    if (seg_len &&
        vsm->ops->set_memory_attributes(vsm->vm, target_vtl, seg_start << 12,
                                        seg_len << 12, attrs)) {
        return -1;
    }
    return 0;
}

static void flush_pending_protections(struct hv_vsm *vsm, uint8_t owner_vtl)
{
    unsigned i;

    for (i = 0; i < vsm->nr_pending_prot; i++) {
        uint64_t gfn = vsm->pending_prot[i] >> 8;
        uint64_t attrs = vsm->pending_prot[i] & 0xff;

        /* Target VTL recorded implicitly: bootstrap only protects VTL0. */
        record_applied_prot(vsm, gfn, attrs);
        vsm->ops->set_memory_attributes(vsm->vm, 0, gfn << 12, 1ULL << 12,
                                        attrs);
    }
    free(vsm->pending_prot);
    vsm->pending_prot = NULL;
    vsm->nr_pending_prot = 0;
    vsm->pending_prot_cap = 0;
}

/* TranslateVirtualAddress control flags (TLFS; low bits of control_flags). */
#define HV_VSM_XLATE_GVA_VAL_READ       1
#define HV_VSM_XLATE_GVA_VAL_WRITE      2
#define HV_VSM_XLATE_GVA_VAL_EXECUTE    4
#define HV_VSM_XLATE_GVA_FLAGS_MASK     0x3f

/* TranslateVirtualAddress result codes / fields. */
#define HV_VSM_XLATE_GVA_UNMAPPED       1
#define HV_VSM_XLATE_CACHE_WB           (6ULL << 32)
#define HV_VSM_XLATE_OVERLAY_PAGE       (1ULL << 40)

/*
 * HvCallTranslateVirtualAddress: translate a GVA in the target VTL's
 * address-space context.  The translation comes from the host's walker
 * for the target plane; HV_VSM_XLATE_GVA_VAL_WRITE is answered from the
 * walker's supervisor write-access report.  VAL_EXECUTE is not modelled
 * (KVM_TRANSLATE has no fetch walk); the reference host walks with
 * PFERR_FETCH there, so NX validation diverges until that is plumbed.
 */
static uint64_t do_translate_virtual_address(struct hv_vsm *vsm,
                                             uint32_t caller,
                                             uint64_t control,
                                             uint64_t in_gpa, uint64_t r8,
                                             bool fast,
                                             const struct kvm_fpu *xmm_in,
                                             struct kvm_fpu *xmm_io,
                                             int *xmm_out_count)
{
    struct {
        uint64_t partition_id;
        uint32_t vp_index;
        uint32_t reserved;
        uint64_t control_flags;
        uint64_t gva_page;
    } __hv_vsm_packed in;
    union hv_vsm_input_vtl input_vtl;
    struct {
        uint64_t result;
        uint64_t gpa_page;
    } __hv_vsm_packed out;
    uint8_t target_vtl, flags;
    uint64_t gpa = 0;
    bool valid = false, writeable = false;
    uint32_t vp;

    if (control & (HV_VSM_HYPERCALL_REP_COMP_MASK |
                   HV_VSM_HYPERCALL_REP_START_MASK)) {
        return mkstatus(HV_VSM_STATUS_INVALID_HYPERCALL_INPUT, 0);
    }
    if (fast) {
        /* 16-byte header in the fast GPR pair, the rest in XMM0. */
        memcpy(&in, &in_gpa, 8);
        memcpy((char *)&in + 8, &r8, 8);
        if (!xmm_in) {
            return mkstatus(HV_VSM_STATUS_INVALID_HYPERCALL_INPUT, 0);
        }
        memcpy((char *)&in + 16, xmm_in->xmm, 16);
    } else if (vsm->ops->guest_read(vsm->vm, in_gpa, &in, sizeof(in))) {
        return mkstatus(HV_VSM_STATUS_INVALID_ALIGNMENT, 0);
    }

    /*
     * Reference input validation (BrimstoneLinux
     * kvm_hv_xlate_va_validate_input, hyperv.c:4112-4139): every
     * rejection, including a non-self partition id, a vp other than the
     * caller, and a target VTL that is above the caller, disabled, or
     * out of range, is INVALID_HYPERCALL_INPUT.  Only self-translation
     * is supported, a deliberate reference restriction (the TLFS allows
     * other VPs).
     */
    if (in.partition_id != HV_VSM_PARTITION_ID_SELF) {
        return mkstatus(HV_VSM_STATUS_INVALID_HYPERCALL_INPUT, 0);
    }
    if (in.vp_index != HV_VSM_VP_INDEX_SELF && in.vp_index != caller) {
        return mkstatus(HV_VSM_STATUS_INVALID_HYPERCALL_INPUT, 0);
    }
    vp = caller;
    flags = in.control_flags & HV_VSM_XLATE_GVA_FLAGS_MASK;
    input_vtl.as_uint8 = in.control_flags >> 56;
    target_vtl = input_vtl.use_target_vtl ? input_vtl.target_vtl :
                 vsm->vp[caller].active_vtl;
    if (target_vtl > HV_VSM_MAX_VTL ||
        target_vtl > vsm->vp[caller].active_vtl ||
        !(vsm->vp[caller].enabled_vtl_set & (1 << target_vtl))) {
        return mkstatus(HV_VSM_STATUS_INVALID_HYPERCALL_INPUT, 0);
    }
    if (!vsm->ops->vcpu_translate ||
        vsm->ops->vcpu_translate(vsm->vm, target_vtl, vp,
                                 in.gva_page << 12, &gpa, &valid,
                                 &writeable)) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
    }

    /*
     * The reference walks with the requested access rights folded into
     * the page-table walk (hyperv.c:4141-4151), so a mapping that fails
     * write validation reports GVA_UNMAPPED exactly like a non-present
     * one.  GPA access rights (VTL protections) are not consulted,
     * matching the reference hypervisor: the secure kernel translates
     * pages it has itself write-protected in VTL0 (SkpgVerifyPage
     * during AP start) and treats anything but success as a
     * verification failure, aborting the AP start.
     */
    if (valid && (flags & HV_VSM_XLATE_GVA_VAL_WRITE) && !writeable) {
        valid = false;
    }

    /*
     * Success reports cache type X64_WB (6) in bits 39:32 of the result
     * qword, and the overlay_page bit (40) when the translated GPA is
     * the target VTL's hypercall page (hyperv.c:4198-4209).
     */
    out.result = valid ? HV_VSM_XLATE_CACHE_WB : HV_VSM_XLATE_GVA_UNMAPPED;
    out.gpa_page = valid ? gpa >> 12 : 0;
    if (valid && vsm->ops->hcall_page_gpa) {
        uint64_t hcall_page = vsm->ops->hcall_page_gpa(vsm->vm, target_vtl, 0);

        if (hcall_page && hcall_page >> 12 == gpa >> 12) {
            out.result |= HV_VSM_XLATE_OVERLAY_PAGE;
        }
    }
    if (vsm_dbg())
        fprintf(stderr,
            "hv-vsm dbg: XLATE vp=%u vtl=%u flags=%llx gva=%llx -> valid=%d gpa=%llx\n",
            vp, target_vtl, (unsigned long long)in.control_flags,
            (unsigned long long)in.gva_page << 12, valid,
            (unsigned long long)gpa);

    if (fast) {
        /* Output follows the one consumed XMM input register. */
        memcpy((char *)xmm_io->xmm + 16, &out, 16);
        *xmm_out_count = 2;
    } else if (vsm->ops->guest_write(vsm->vm, r8, &out, sizeof(out))) {
        return mkstatus(HV_VSM_STATUS_INVALID_ALIGNMENT, 0);
    }
    return mkstatus(HV_VSM_STATUS_SUCCESS, 0);
}

/* HvCallGetVpIndexFromApicId: single-rep APIC ID to VP index lookup. */
static uint64_t do_get_vp_index_from_apic_id(struct hv_vsm *vsm,
                                             uint64_t control,
                                             uint64_t in_gpa, uint64_t out_gpa,
                                             bool fast,
                                             struct kvm_fpu *xmm_io,
                                             int *xmm_out_count)
{
    struct {
        uint64_t partition_id;
        uint8_t target_vtl;
        uint8_t pad[7];
    } __hv_vsm_packed in;
    uint16_t rep_cnt = (control & HV_VSM_HYPERCALL_REP_COMP_MASK) >>
                       HV_VSM_HYPERCALL_REP_COMP_SHIFT;
    uint16_t rep_idx = (control & HV_VSM_HYPERCALL_REP_START_MASK) >>
                       HV_VSM_HYPERCALL_REP_START_SHIFT;
    uint64_t apic_id, vp_index;
    uint16_t count;
    int64_t vp;

    if ((rep_cnt || rep_idx) && rep_idx >= rep_cnt) {
        return mkstatus(HV_VSM_STATUS_INVALID_HYPERCALL_INPUT, 0);
    }
    /*
     * The rep count collapses: at most one lookup completes per call,
     * and a non-rep call still returns the mapping with zero reps
     * complete (Brimstone hyperv.c:4254-4255, 4290).
     */
    count = (rep_cnt - rep_idx) ? 1 : 0;
    if (fast) {
        in.partition_id = in_gpa;
        in.target_vtl = out_gpa & 0xff;
        if (!xmm_io) {
            return mkstatus(HV_VSM_STATUS_INVALID_HYPERCALL_INPUT, 0);
        }
        memcpy(&apic_id, xmm_io->xmm, 8);
    } else {
        if (vsm->ops->guest_read(vsm->vm, in_gpa, &in, sizeof(in)) ||
            vsm->ops->guest_read(vsm->vm, in_gpa + sizeof(in), &apic_id, 8)) {
            return mkstatus(HV_VSM_STATUS_INVALID_ALIGNMENT, 0);
        }
    }
    /*
     * Validation-order quirk kept from the reference: the APIC ID
     * lookup runs BEFORE the partition id check (Brimstone
     * hyperv.c:4270 vs 4279), so an unknown APIC id with a bad
     * partition reports INVALID_PARAMETER, not INVALID_PARTITION_ID.
     */
    if (!vsm->ops->vp_from_apic_id) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
    }
    vp = vsm->ops->vp_from_apic_id(vsm->vm, apic_id & 0xffffffff);
    if (vp < 0) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
    }
    vp_index = vp;

    if (in.partition_id != HV_VSM_PARTITION_ID_SELF) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARTITION_ID, 0);
    }

    if (fast) {
        memcpy((char *)xmm_io->xmm + 16, &vp_index, 8);
        memset((char *)xmm_io->xmm + 24, 0, 8);
        *xmm_out_count = 2;
    } else if (vsm->ops->guest_write(vsm->vm, out_gpa, &vp_index, 8)) {
        return mkstatus(HV_VSM_STATUS_INVALID_ALIGNMENT, 0);
    }
    return mkstatus(HV_VSM_STATUS_SUCCESS, count);
}

/*
 * Rep GFN lists are consumed at most this many entries per pass, the
 * size of the reference host's per-call list buffer (Brimstone
 * KVM_HV_VP_REGISTER_LIST_SIZE).
 */
#define HV_VSM_GFN_BATCH 16

static uint64_t do_modify_vtl_protection_mask(struct hv_vsm *vsm,
                                              uint32_t caller,
                                              uint64_t control,
                                              uint64_t in_gpa, uint64_t r8,
                                              bool fast,
                                              const struct kvm_fpu *xmm_in)
{
    struct hv_vsm_modify_vtl_protection_mask in;
    uint16_t rep_cnt = (control & HV_VSM_HYPERCALL_REP_COMP_MASK) >>
                       HV_VSM_HYPERCALL_REP_COMP_SHIFT;
    uint16_t rep_idx = (control & HV_VSM_HYPERCALL_REP_START_MASK) >>
                       HV_VSM_HYPERCALL_REP_START_SHIFT;
    uint8_t target_vtl;
    uint64_t attrs = 0;
    uint16_t done;

    if (!rep_cnt || rep_idx >= rep_cnt) {
        return mkstatus(HV_VSM_STATUS_INVALID_HYPERCALL_INPUT, 0);
    }
    if (fast) {
        /*
         * A fast call's GPA list lives in XMM0-5 (12 GFNs) and is
         * consumed whole, so the fast form can never continue: a
         * nonzero rep start or more than 12 GFNs is rejected up front
         * (Brimstone hyperv.c:4054-4056).
         */
        if (rep_idx != 0 || rep_cnt > 6 * 16 / 8) {
            return mkstatus(HV_VSM_STATUS_INVALID_HYPERCALL_INPUT, 0);
        }
        /* 16-byte header in the fast GPR pair, GPA list packed in XMM0-5. */
        memcpy(&in, &in_gpa, 8);
        memcpy((char *)&in + 8, &r8, 8);
    } else if (vsm->ops->guest_read(vsm->vm, in_gpa, &in, sizeof(in))) {
        return mkstatus(HV_VSM_STATUS_INVALID_ALIGNMENT, 0);
    }
    if (in.target_partition_id != HV_VSM_PARTITION_ID_SELF) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARTITION_ID, 0);
    }

    /*
     * The protections apply to the target VTL's view, which must be below
     * the caller's; without an explicit target it is the next enabled VTL
     * below the caller, so VTL0 callers have nothing to target.
     */
    if (in.input_vtl.use_target_vtl) {
        target_vtl = in.input_vtl.target_vtl;
        if (target_vtl >= vsm->vp[caller].active_vtl) {
            return mkstatus(HV_VSM_STATUS_ACCESS_DENIED, 0);
        }
    } else if (vsm->vp[caller].active_vtl == 0) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
    } else {
        target_vtl = vsm->vp[caller].active_vtl - 1;
    }
    if (target_vtl > HV_VSM_MAX_VTL) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
    }

    if (!(in.map_flags & HV_VSM_MAP_GPA_READABLE)) {
        attrs |= 1ULL << 0;     /* KVM_MEMORY_ATTRIBUTE_NR */
    }
    if (!(in.map_flags & HV_VSM_MAP_GPA_WRITABLE)) {
        attrs |= 1ULL << 1;     /* KVM_MEMORY_ATTRIBUTE_NW */
    }
    if (!(in.map_flags & (HV_VSM_MAP_GPA_KERNEL_EXECUTABLE |
                          HV_VSM_MAP_GPA_USER_EXECUTABLE))) {
        attrs |= 1ULL << 2;     /* KVM_MEMORY_ATTRIBUTE_NX */
    }

    {
        uint64_t run_start = 0;
        uint64_t run_len = 0;
        uint16_t run_first = rep_idx;
        /*
         * At most HV_VSM_GFN_BATCH reps complete per pass, matching
         * the reference host's per-call list buffer (Brimstone
         * KVM_HV_VP_REGISTER_LIST_SIZE, hyperv.c:4040-4043): the call
         * returns SUCCESS with the partial rep count and the guest
         * stub re-issues with the advanced rep start index.
         */
        uint16_t end = rep_cnt;
        bool noop = getenv("VSM_MVPM_NOOP"); /* VSM-DEBUG-EXPERIMENT knob */

        if (end - rep_idx > HV_VSM_GFN_BATCH) {
            end = rep_idx + HV_VSM_GFN_BATCH;
        }

        for (done = rep_idx; done < end; done++) {
            uint64_t gpa_page;

            if (fast) {
                memcpy(&gpa_page, (const char *)xmm_in->xmm + done * 8, 8);
            } else if (vsm->ops->guest_read(vsm->vm,
                                            in_gpa + sizeof(in) + done * 8,
                                            &gpa_page, 8)) {
                return mkstatus(HV_VSM_STATUS_INVALID_ALIGNMENT,
                                done - rep_idx);
            }
            if (run_len && gpa_page == run_start + run_len) {
                run_len++;
                continue;
            }
            if (run_len && !noop &&
                apply_protection_run(vsm, vsm->vp[caller].active_vtl,
                                     target_vtl, run_start, run_len, attrs)) {
                return mkstatus(HV_VSM_STATUS_INVALID_PARAMETER,
                                run_first - rep_idx);
            }
            run_start = gpa_page;
            run_len = 1;
            run_first = done;
        }
        if (run_len && !noop &&
            apply_protection_run(vsm, vsm->vp[caller].active_vtl, target_vtl,
                                 run_start, run_len, attrs)) {
            return mkstatus(HV_VSM_STATUS_INVALID_PARAMETER,
                            run_first - rep_idx);
        }
        if (vsm->ops->log && getenv("VSM_MVPM_LOG")) {
            fprintf(stderr,
                    "hv-vsm dbg: MVPM flags=%x vtl=%u reps=%u last_run=%llu@%llx\n",
                    (unsigned)in.map_flags, target_vtl,
                    (unsigned)(end - rep_idx),
                    (unsigned long long)run_len,
                    (unsigned long long)run_start);
        }

        return mkstatus(HV_VSM_STATUS_SUCCESS, end - rep_idx);
    }
}

static uint64_t do_enable_partition_vtl(struct hv_vsm *vsm, uint32_t vp,
                                        uint64_t control, uint64_t in_gpa,
                                        bool fast, uint64_t r8)
{
    struct hv_vsm_enable_partition_vtl in;

    if (control & (HV_VSM_HYPERCALL_REP_COMP_MASK |
                   HV_VSM_HYPERCALL_REP_START_MASK)) {
        return mkstatus(HV_VSM_STATUS_INVALID_HYPERCALL_INPUT, 0);
    }
    if (fast) {
        /* 16-byte input: fits the two fast-call GPRs */
        memcpy(&in, &in_gpa, 8);
        memcpy((char *)&in + 8, &r8, 8);
    } else if (vsm->ops->guest_read(vsm->vm, in_gpa, &in, sizeof(in))) {
        return mkstatus(HV_VSM_STATUS_INVALID_ALIGNMENT, 0);
    }

    if (in.target_partition_id != HV_VSM_PARTITION_ID_SELF) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARTITION_ID, 0);
    }
    if (in.target_vtl != 1) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
    }
    if (in.flags & ~1) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
    }
    if (vsm->vtl1_partition_enabled) {
        return mkstatus(HV_VSM_STATUS_VTL_ALREADY_ENABLED, 0);
    }

    vsm->vtl1_partition_enabled = true;
    vsm->mbec_requested = in.flags & 1;
    return mkstatus(HV_VSM_STATUS_SUCCESS, 0);
}

static uint64_t do_enable_vp_vtl(struct hv_vsm *vsm, uint32_t caller,
                                 uint64_t control, uint64_t in_gpa, bool fast)
{
    struct hv_vsm_enable_vp_vtl in;
    uint32_t vp;
    int ret;

    if (fast || (control & (HV_VSM_HYPERCALL_REP_COMP_MASK |
                            HV_VSM_HYPERCALL_REP_START_MASK))) {
        return mkstatus(HV_VSM_STATUS_INVALID_HYPERCALL_INPUT, 0);
    }
    if (vsm->ops->guest_read(vsm->vm, in_gpa, &in, sizeof(in))) {
        return mkstatus(HV_VSM_STATUS_INVALID_ALIGNMENT, 0);
    }

    if (in.partition_id != HV_VSM_PARTITION_ID_SELF) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARTITION_ID, 0);
    }
    if (resolve_vp(vsm, caller, in.vp_index, &vp)) {
        return mkstatus(HV_VSM_STATUS_INVALID_VP_INDEX, 0);
    }
    if (!vsm->vtl1_partition_enabled) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
    }
    if (in.target_vtl.target_vtl != 1) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
    }
    if (vsm->vp[vp].enabled_vtl_set & 2) {
        return mkstatus(HV_VSM_STATUS_VTL_ALREADY_ENABLED, 0);
    }
    /*
     * Requestor rule (matching the reference host): the caller must be
     * running at or above the target VTL, or be running at the highest
     * VTL any VP has enabled so far.  The first enablement is thus
     * allowed from the lower VTL; afterwards only the higher VTL may
     * enable further VPs, including a VP's own.
     */
    if (vsm->vp[caller].active_vtl < in.target_vtl.target_vtl &&
        vsm->vp[caller].active_vtl != partition_max_enabled_vtl(vsm)) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
    }

    ret = vsm->ops->plane_vcpu_create(vsm->vm, 1, vp);
    if (ret && ret != -EEXIST) {
        return mkstatus(HV_VSM_STATUS_INVALID_VP_STATE, 0);
    }
    if (apply_vp_context(vsm, 1, vp, &in.vp_context)) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
    }

    /*
     * The new VTL instance's local APIC starts in the mode the enabling
     * VTL's APIC is in: the secure kernel records x2APIC-ness once, on
     * the boot processor, and reads the x2APIC ID MSR on every further
     * processor without re-enabling the mode.
     */
    if (caller != vp && vsm->ops->vcpu_get_msr && vsm->ops->vcpu_set_msr) {
        uint64_t apic_base, tgt_base;

        if (!vsm->ops->vcpu_get_msr(vsm->vm, 1, caller,
                                    HV_VSM_MSR_APIC_BASE, &apic_base) &&
            !vsm->ops->vcpu_get_msr(vsm->vm, 1, vp,
                                    HV_VSM_MSR_APIC_BASE, &tgt_base)) {
            /* Mode bits come from the caller; BSP-ness stays the VP's own. */
            apic_base = (apic_base & ~HV_VSM_APIC_BASE_BSP) |
                        (tgt_base & HV_VSM_APIC_BASE_BSP);
            vsm->ops->vcpu_set_msr(vsm->vm, 1, vp,
                                   HV_VSM_MSR_APIC_BASE, apic_base);
        }
    }
    /* APs start wait-for-INIT; the VTL context replaces that entirely. */
    if (vsm->ops->vcpu_set_mp_runnable(vsm->vm, 1, vp)) {
        return mkstatus(HV_VSM_STATUS_INVALID_VP_STATE, 0);
    }

    vsm->vp[vp].enabled_vtl_set |= 2;
    return mkstatus(HV_VSM_STATUS_SUCCESS, 0);
}

static uint64_t do_start_vp(struct hv_vsm *vsm, uint32_t caller,
                            uint64_t control, uint64_t in_gpa, bool fast)
{
    struct hv_vsm_enable_vp_vtl in; /* StartVirtualProcessor: same layout */
    uint32_t vp;
    uint8_t vtl;
    int ret;

    if (fast || (control & (HV_VSM_HYPERCALL_REP_COMP_MASK |
                            HV_VSM_HYPERCALL_REP_START_MASK))) {
        return mkstatus(HV_VSM_STATUS_INVALID_HYPERCALL_INPUT, 0);
    }
    if (vsm->ops->guest_read(vsm->vm, in_gpa, &in, sizeof(in))) {
        return mkstatus(HV_VSM_STATUS_INVALID_ALIGNMENT, 0);
    }
    if (in.partition_id != HV_VSM_PARTITION_ID_SELF) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARTITION_ID, 0);
    }
    if (resolve_vp(vsm, caller, in.vp_index, &vp)) {
        return mkstatus(HV_VSM_STATUS_INVALID_VP_INDEX, 0);
    }
    /*
     * The reset BSP may never be a StartVp target, whatever its state
     * (Brimstone hyperv.c:4330-4338, kvm_vcpu_is_reset_bsp).  A
     * non-BSP self-start is also refused with the same status: this
     * VMM cannot INIT-reset the very vCPU whose thread is executing
     * the hypercall.
     */
    if ((vsm->ops->vp_is_bsp && vsm->ops->vp_is_bsp(vsm->vm, vp)) ||
        vp == caller) {
        return mkstatus(HV_VSM_STATUS_INVALID_VP_STATE, 0);
    }
    vtl = in.target_vtl.target_vtl;
    /*
     * A target VTL above the partition maximum or above the caller's
     * active VTL is INVALID_PARAMETER, not ACCESS_DENIED (Brimstone
     * hyperv.c:4340-4347).
     */
    if (vtl > HV_VSM_MAX_VTL || vtl > vsm->vp[caller].active_vtl) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
    }
    if (vtl && (vsm->vp[vp].enabled_vtl_set & (1 << vtl))) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
    }

    if (vtl) {
        ret = vsm->ops->plane_vcpu_create(vsm->vm, vtl, vp);
        if (ret && ret != -EEXIST) {
            return mkstatus(HV_VSM_STATUS_INVALID_VP_STATE, 0);
        }
    }
    if (apply_vp_context(vsm, vtl, vp, &in.vp_context)) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
    }
    vsm->vp[vp].enabled_vtl_set |= 1 << vtl;

    /*
     * Carry the boot processor's VTL1 APIC mode to the starting
     * processor's VTL1 instance now, not at EnableVpVtl time: the boot
     * VTL1 switches itself to x2APIC after it has enabled the other
     * VPs' VTL1, and the secure kernel's per-processor init reads the
     * x2APIC ID MSR unconditionally once its boot processor recorded
     * x2APIC mode, without re-enabling it per processor.
     */
    if ((vsm->vp[vp].enabled_vtl_set & 2) && vp != caller &&
        vsm->ops->vcpu_get_msr && vsm->ops->vcpu_set_msr) {
        uint64_t apic_base, tgt_base;

        if (!vsm->ops->vcpu_get_msr(vsm->vm, 1, caller,
                                    HV_VSM_MSR_APIC_BASE, &apic_base) &&
            !vsm->ops->vcpu_get_msr(vsm->vm, 1, vp,
                                    HV_VSM_MSR_APIC_BASE, &tgt_base)) {
            /* Mode bits come from the caller; BSP-ness stays the VP's own. */
            apic_base = (apic_base & ~HV_VSM_APIC_BASE_BSP) |
                        (tgt_base & HV_VSM_APIC_BASE_BSP);
            vsm->ops->vcpu_set_msr(vsm->vm, 1, vp,
                                   HV_VSM_MSR_APIC_BASE, apic_base);
        }
    }

    /*
     * The context supplied describes the target VTL, but the AP starts
     * executing in the highest VTL enabled on it (matching the
     * reference host): a higher VTL enabled earlier via EnableVpVtl
     * runs its per-processor init first and only then returns into the
     * lower VTL's startup context.
     */
    {
        uint16_t set = vsm->vp[vp].enabled_vtl_set;
        uint8_t start_vtl = 0;
        int i;

        for (i = HV_VSM_MAX_VTL; i >= 0; i--) {
            if (set & (1 << i)) {
                start_vtl = i;
                break;
            }
        }
        /*
         * Make the starting VTL's plane runnable before stopping the
         * others, and only then update the MP states. Each ioctl kicks
         * the parked vCPU thread, so it can re-enter KVM_RUN between any
         * two of these calls; the ordering keeps an invariant that at
         * least one plane is runnable at every instant.  A window with
         * no runnable plane trips the kernel's select-plane fallback,
         * which forces plane 0 runnable; plane 0 then wins selection
         * over the starting VTL for good.
         */
        for (i = HV_VSM_MAX_VTL; i >= 0; i--) {
            if (set & (1 << i)) {
                vsm->ops->vcpu_set_run_state(vsm->vm, i, vp,
                                             i == start_vtl);
            }
        }
        for (i = 0; i <= HV_VSM_MAX_VTL; i++) {
            if (set & (1 << i)) {
                if (vsm->ops->vcpu_set_mp_runnable(vsm->vm, i, vp)) {
                    return mkstatus(HV_VSM_STATUS_INVALID_VP_STATE, 0);
                }
            }
        }
        vsm->vp[vp].active_vtl = start_vtl;
    }

    return mkstatus(HV_VSM_STATUS_SUCCESS, 0);
}

static int get_one_register(struct hv_vsm *vsm, uint32_t vp, uint8_t vtl,
                            uint32_t name, uint64_t val[2])
{
    const struct hv_vsm_host_ops *ops = vsm->ops;
    struct kvm_sregs sregs;
    struct kvm_regs regs;
    uint32_t msr = reg_msr(name);

    val[0] = val[1] = 0;

    if (msr) {
        return ops->vcpu_get_msr(vsm->vm, vtl, vp, msr, &val[0]) ?
               HV_VSM_STATUS_INVALID_PARAMETER : 0;
    }

    if (name >= HV_VSM_X64_REG_RAX && name <= HV_VSM_X64_REG_RFLAGS) {
        if (ops->vcpu_get_regs(vsm->vm, vtl, vp, &regs)) {
            return HV_VSM_STATUS_INVALID_PARAMETER;
        }
        if (name == HV_VSM_X64_REG_RIP) {
            val[0] = regs.rip;
        } else if (name == HV_VSM_X64_REG_RFLAGS) {
            val[0] = regs.rflags;
        } else {
            val[0] = *gpr_slot(&regs, name - HV_VSM_X64_REG_RAX);
        }
        return 0;
    }

    switch (name) {
    case HV_VSM_REG_CAPABILITIES:
        /*
         * Windows ABI layout: dr6_shared is bit 63 (bits 47-62 are the
         * MBEC VTL mask, bit 46 deny-lower-VTL-startup).  DR6 is shared,
         * matching the reference host implementation.
         */
        val[0] = 1ULL << 63;
        return 0;
    case HV_VSM_REG_PARTITION_STATUS:
        val[0] = (uint64_t)(1 | (vsm->vtl1_partition_enabled ? 2 : 0)) |
                 ((uint64_t)HV_VSM_MAX_VTL << 16);
        return 0;
    case HV_VSM_REG_VP_STATUS:
        val[0] = vsm->vp[vp].active_vtl |
                 ((uint64_t)vsm->vp[vp].enabled_vtl_set << 16);
        return 0;
    case HV_VSM_REG_CODE_PAGE_OFFSETS:
        ensure_thunks(vsm, vtl, vp);
        val[0] = (uint64_t)HV_VSM_VTL_CALL_OFFSET |
                 ((uint64_t)HV_VSM_VTL_RETURN_OFFSET << 12);
        return 0;
    case HV_VSM_REG_PARTITION_CONFIG:
        val[0] = vsm->partition_config[vtl];
        return 0;
    case HV_VSM_REG_VP_SECURE_CONFIG_VTL0:
        val[0] = vsm->vp[vp].secure_config_vtl0;
        return 0;
    case HV_VSM_X64_REG_PENDING_EVENT0:
        val[0] = vsm->vp[vp].pending_event[vtl].as_u64[0];
        val[1] = vsm->vp[vp].pending_event[vtl].as_u64[1];
        return 0;
    case HV_VSM_REG_DT_TRAPS:
        val[0] = vsm->vp[vp].dt_traps;
        return 0;
    case HV_VSM_REG_VP_CONFIG:
        val[0] = vsm->vp[vp].vp_config;
        return 0;
    case HV_VSM_REG_VINA:
        val[0] = vsm->vp[vp].vina;
        return 0;
    case HV_VSM_X64_REG_ES ... HV_VSM_X64_REG_TR: {
        struct hv_vsm_x64_segment_register seg;

        if (ops->vcpu_get_sregs(vsm->vm, vtl, vp, &sregs)) {
            return HV_VSM_STATUS_INVALID_PARAMETER;
        }
        store_segment(seg_of(&sregs, name), &seg);
        memcpy(val, &seg, sizeof(seg));
        return 0;
    }
    case HV_VSM_X64_REG_DR0 ... HV_VSM_X64_REG_DR7: {
        struct kvm_debugregs dbg;

        if (!ops->vcpu_get_debugregs ||
            ops->vcpu_get_debugregs(vsm->vm, vtl, vp, &dbg)) {
            return HV_VSM_STATUS_INVALID_PARAMETER;
        }
        if (name == HV_VSM_X64_REG_DR6) {
            val[0] = dbg.dr6;
        } else if (name == HV_VSM_X64_REG_DR7) {
            val[0] = dbg.dr7;
        } else {
            val[0] = dbg.db[name - HV_VSM_X64_REG_DR0];
        }
        return 0;
    }
    case HV_VSM_X64_REG_IDTR:
    case HV_VSM_X64_REG_GDTR: {
        struct hv_vsm_x64_table_register tab = {};

        if (ops->vcpu_get_sregs(vsm->vm, vtl, vp, &sregs)) {
            return HV_VSM_STATUS_INVALID_PARAMETER;
        }
        if (name == HV_VSM_X64_REG_IDTR) {
            tab.limit = sregs.idt.limit;
            tab.base = sregs.idt.base;
        } else {
            tab.limit = sregs.gdt.limit;
            tab.base = sregs.gdt.base;
        }
        memcpy(val, &tab, sizeof(tab));
        return 0;
    }
    case HV_VSM_X64_REG_EFER:
    case HV_VSM_X64_REG_CR0:
    case HV_VSM_X64_REG_CR2:
    case HV_VSM_X64_REG_CR3:
    case HV_VSM_X64_REG_CR4:
    case HV_VSM_X64_REG_CR8:
        if (ops->vcpu_get_sregs(vsm->vm, vtl, vp, &sregs)) {
            return HV_VSM_STATUS_INVALID_PARAMETER;
        }
        switch (name) {
        case HV_VSM_X64_REG_EFER:
            val[0] = sregs.efer;
            break;
        case HV_VSM_X64_REG_CR0:
            val[0] = sregs.cr0;
            break;
        case HV_VSM_X64_REG_CR2:
            val[0] = sregs.cr2;
            break;
        case HV_VSM_X64_REG_CR3:
            val[0] = sregs.cr3;
            break;
        case HV_VSM_X64_REG_CR4:
            val[0] = sregs.cr4;
            break;
        case HV_VSM_X64_REG_CR8:
            val[0] = sregs.cr8;
            break;
        }
        return 0;
    default:
        vsm_log(vsm, "GetVpRegisters name", name);
        return HV_VSM_STATUS_INVALID_PARAMETER;
    }
}

/*
 * SetVpRegisters writes that target a register living inside kvm_sregs /
 * kvm_debugregs are applied as an atomic read-modify-write on the target
 * vCPU's thread (ops->vcpu_patch_*): a split get/set pair from the caller's
 * thread races with the target changing other fields of the same struct
 * (CR3 on a context switch, segment reloads) between the two ioctls.
 */
struct vsm_sregs_patch_ctx {
    uint32_t name;
    uint64_t value;
    struct hv_vsm_x64_segment_register seg;
    struct hv_vsm_x64_table_register tab;
};

static void patch_sregs_segment(struct kvm_sregs *sregs, void *opaque)
{
    struct vsm_sregs_patch_ctx *ctx = opaque;

    load_segment(&ctx->seg, seg_of(sregs, ctx->name));
}

static void patch_sregs_table(struct kvm_sregs *sregs, void *opaque)
{
    struct vsm_sregs_patch_ctx *ctx = opaque;

    if (ctx->name == HV_VSM_X64_REG_IDTR) {
        sregs->idt.limit = ctx->tab.limit;
        sregs->idt.base = ctx->tab.base;
    } else {
        sregs->gdt.limit = ctx->tab.limit;
        sregs->gdt.base = ctx->tab.base;
    }
}

static void patch_sregs_control(struct kvm_sregs *sregs, void *opaque)
{
    struct vsm_sregs_patch_ctx *ctx = opaque;

    switch (ctx->name) {
    case HV_VSM_X64_REG_EFER:
        sregs->efer = ctx->value;
        break;
    case HV_VSM_X64_REG_CR0:
        sregs->cr0 = ctx->value;
        break;
    case HV_VSM_X64_REG_CR2:
        sregs->cr2 = ctx->value;
        break;
    case HV_VSM_X64_REG_CR3:
        sregs->cr3 = ctx->value;
        break;
    case HV_VSM_X64_REG_CR4:
        sregs->cr4 = ctx->value;
        break;
    case HV_VSM_X64_REG_CR8:
        sregs->cr8 = ctx->value;
        break;
    }
}

static void patch_debugregs(struct kvm_debugregs *dbg, void *opaque)
{
    struct vsm_sregs_patch_ctx *ctx = opaque;

    if (ctx->name == HV_VSM_X64_REG_DR6) {
        dbg->dr6 = ctx->value;
    } else if (ctx->name == HV_VSM_X64_REG_DR7) {
        dbg->dr7 = ctx->value;
    } else {
        dbg->db[ctx->name - HV_VSM_X64_REG_DR0] = ctx->value;
    }
}

static int set_one_register(struct hv_vsm *vsm, uint32_t vp, uint8_t vtl,
                            uint32_t name, const uint64_t val[2])
{
    const struct hv_vsm_host_ops *ops = vsm->ops;
    struct kvm_regs regs;
    uint32_t msr = reg_msr(name);

    if (msr) {
        return ops->vcpu_set_msr(vsm->vm, vtl, vp, msr, val[0]) ?
               HV_VSM_STATUS_INVALID_PARAMETER : 0;
    }

    if (name >= HV_VSM_X64_REG_RAX && name <= HV_VSM_X64_REG_RFLAGS) {
        if (ops->vcpu_get_regs(vsm->vm, vtl, vp, &regs)) {
            return HV_VSM_STATUS_INVALID_PARAMETER;
        }
        if (name == HV_VSM_X64_REG_RIP) {
            regs.rip = val[0];
        } else if (name == HV_VSM_X64_REG_RFLAGS) {
            regs.rflags = val[0] | HV_VSM_X86_EFLAGS_FIXED;
        } else {
            *gpr_slot(&regs, name - HV_VSM_X64_REG_RAX) = val[0];
        }
        return ops->vcpu_set_regs(vsm->vm, vtl, vp, &regs) ?
               HV_VSM_STATUS_INVALID_PARAMETER : 0;
    }

    switch (name) {
    case HV_VSM_REG_PARTITION_CONFIG: {
        bool was_enabled = vtl_protection_enabled(vsm, vtl);
        uint64_t cfg = val[0];

        /*
         * TLFS: DefaultVtlProtectionMask is fixed when the VTL is
         * enabled and cannot be changed afterwards; later writes keep
         * the original mask.
         */
        if (vsm->partition_config[vtl]) {
            cfg = (cfg & ~(uint64_t)HV_VSM_PARTITION_CONFIG_DEFAULT_PROT_MASK) |
                  (vsm->partition_config[vtl] &
                   HV_VSM_PARTITION_CONFIG_DEFAULT_PROT_MASK);
        }
        vsm->partition_config[vtl] = cfg;
        if (!was_enabled && vtl_protection_enabled(vsm, vtl)) {
            flush_pending_protections(vsm, vtl);
        }
        return 0;
    }
    case HV_VSM_REG_VP_SECURE_CONFIG_VTL0:
        vsm->vp[vp].secure_config_vtl0 = val[0];
        return 0;
    case HV_VSM_X64_REG_PENDING_EVENT0: {
        union hv_vsm_pending_event ev;

        ev.as_u64[0] = val[0];
        ev.as_u64[1] = val[1];
        /*
         * The set path validates only the vector; the reference host
         * accepts a non-exception event TYPE here and rejects it at
         * delivery, where it fails the next switch into the target VTL
         * (see switch_vtl()).
         */
        if (ev.event_pending && (ev.vector >= 32 || ev.vector == 2)) {
            return HV_VSM_STATUS_INVALID_PARAMETER;
        }
        if (vsm_dbg()) fprintf(stderr, "vsm-ev0set: vp%u vtl%d pending=%d vector=0x%x type=%d err=%x/%d param=0x%llx\n",
                vp, vtl, ev.event_pending, ev.vector, ev.event_type,
                ev.error_code, ev.deliver_error_code,
                (unsigned long long)ev.exception_parameter);
        vsm->vp[vp].pending_event[vtl] = ev;
        return 0;
    }
    case HV_VSM_REG_DT_TRAPS:
        vsm->vp[vp].dt_traps = val[0];
        return 0;
    case HV_VSM_REG_VP_CONFIG:
        vsm->vp[vp].vp_config = val[0];
        return 0;
    case HV_VSM_REG_VINA:
        /* Accept the VINA configuration; assertion is not implemented. */
        vsm->vp[vp].vina = val[0];
        return 0;
    case HV_VSM_REG_CR_INTERCEPT_CONTROL:
        /*
         * Arm the descriptor-table write intercepts (the reference host
         * filters LIDT/LGDT and reflects them to the higher VTL as
         * register intercept messages; the secure kernel relies on the
         * IDTR intercept functionally for its patch-protection flow).
         * The CR/MSR intercept bits beyond the descriptor tables are
         * not implemented yet.
         */
        vsm->vp[vp].cr_intercept_control = val[0];
        if (ops->vcpu_arm_reg_intercepts &&
            ops->vcpu_arm_reg_intercepts(vsm->vm, vp, val[0])) {
            return HV_VSM_STATUS_INVALID_PARAMETER;
        }
        return 0;
    case HV_VSM_REG_CR_INTERCEPT_CR0_MASK:
    case HV_VSM_REG_CR_INTERCEPT_CR4_MASK:
    case HV_VSM_REG_CR_INTERCEPT_IA32_MISC_ENABLE_MASK:
        /*
         * Accepted and ignored: failing the write fails VSM bring-up,
         * while not intercepting merely loses the hardening.
         */
        return 0;
    case HV_VSM_X64_REG_ES ... HV_VSM_X64_REG_TR: {
        struct vsm_sregs_patch_ctx ctx = { .name = name };

        memcpy(&ctx.seg, val, sizeof(ctx.seg));
        return ops->vcpu_patch_sregs(vsm->vm, vtl, vp,
                                     patch_sregs_segment, &ctx) ?
               HV_VSM_STATUS_INVALID_PARAMETER : 0;
    }
    case HV_VSM_X64_REG_DR0 ... HV_VSM_X64_REG_DR7: {
        struct vsm_sregs_patch_ctx ctx = { .name = name, .value = val[0] };

        if (!ops->vcpu_patch_debugregs) {
            return HV_VSM_STATUS_INVALID_PARAMETER;
        }
        return ops->vcpu_patch_debugregs(vsm->vm, vtl, vp,
                                         patch_debugregs, &ctx) ?
               HV_VSM_STATUS_INVALID_PARAMETER : 0;
    }
    case HV_VSM_X64_REG_IDTR:
    case HV_VSM_X64_REG_GDTR: {
        struct vsm_sregs_patch_ctx ctx = { .name = name };

        memcpy(&ctx.tab, val, sizeof(ctx.tab));
        return ops->vcpu_patch_sregs(vsm->vm, vtl, vp,
                                     patch_sregs_table, &ctx) ?
               HV_VSM_STATUS_INVALID_PARAMETER : 0;
    }
    case HV_VSM_X64_REG_EFER:
    case HV_VSM_X64_REG_CR0:
    case HV_VSM_X64_REG_CR2:
    case HV_VSM_X64_REG_CR3:
    case HV_VSM_X64_REG_CR4:
    case HV_VSM_X64_REG_CR8: {
        struct vsm_sregs_patch_ctx ctx = { .name = name, .value = val[0] };

        return ops->vcpu_patch_sregs(vsm->vm, vtl, vp,
                                     patch_sregs_control, &ctx) ?
               HV_VSM_STATUS_INVALID_PARAMETER : 0;
    }
    default:
        vsm_log(vsm, "SetVpRegisters name", name);
        return HV_VSM_STATUS_INVALID_PARAMETER;
    }
}

static uint64_t do_get_vp_registers(struct hv_vsm *vsm, uint32_t caller,
                                    uint64_t control, uint64_t in_gpa,
                                    uint64_t out_gpa, bool fast,
                                    struct kvm_fpu *xmm_io, int *xmm_out_count)
{
    struct hv_vsm_get_vp_registers_input hdr;
    uint16_t rep_cnt = (control & HV_VSM_HYPERCALL_REP_COMP_MASK) >>
                       HV_VSM_HYPERCALL_REP_COMP_SHIFT;
    uint16_t rep_idx = (control & HV_VSM_HYPERCALL_REP_START_MASK) >>
                       HV_VSM_HYPERCALL_REP_START_SHIFT;
    uint32_t vp;
    uint8_t target_vtl;
    uint16_t done;

    if (!rep_cnt || rep_idx >= rep_cnt) {
        return mkstatus(HV_VSM_STATUS_INVALID_HYPERCALL_INPUT, 0);
    }

    if (fast) {
        /* Header in the two fast GPRs, names packed into XMM0-5. */
        memcpy(&hdr, &in_gpa, 8);
        memcpy((char *)&hdr + 8, &out_gpa, 8);
    } else if (vsm->ops->guest_read(vsm->vm, in_gpa, &hdr, sizeof(hdr))) {
        return mkstatus(HV_VSM_STATUS_INVALID_ALIGNMENT, 0);
    }

    if (hdr.partition_id != HV_VSM_PARTITION_ID_SELF) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARTITION_ID, 0);
    }
    if (resolve_vp(vsm, caller, hdr.vp_index, &vp)) {
        return mkstatus(HV_VSM_STATUS_INVALID_VP_INDEX, 0);
    }
    target_vtl = hdr.input_vtl.use_target_vtl ? hdr.input_vtl.target_vtl :
                 vsm->vp[caller].active_vtl;
    if (target_vtl > HV_VSM_MAX_VTL) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
    }
    if (target_vtl > vsm->vp[caller].active_vtl) {
        return mkstatus(HV_VSM_STATUS_ACCESS_DENIED, 0);
    }

    for (done = rep_idx; done < rep_cnt; done++) {
        uint64_t val[2];
        uint32_t name;
        int status;

        if (fast) {
            if ((done + 1) * 4 > 6 * 16) {
                return mkstatus(HV_VSM_STATUS_INVALID_HYPERCALL_INPUT, done);
            }
            memcpy(&name, (char *)xmm_io->xmm + done * 4, 4);
        } else if (vsm->ops->guest_read(vsm->vm,
                                        in_gpa + sizeof(hdr) + done * 4,
                                        &name, 4)) {
            return mkstatus(HV_VSM_STATUS_INVALID_ALIGNMENT, done);
        }

        status = get_one_register(vsm, vp, target_vtl, name, val);
        if (status) {
            return mkstatus(status, done);
        }

        if (fast) {
            /* Output starts at the XMM register after the consumed input. */
            int in_regs = ((rep_cnt * 4) + 15) / 16;

            if ((in_regs + done - rep_idx + 1) > 6) {
                return mkstatus(HV_VSM_STATUS_INVALID_HYPERCALL_INPUT, done);
            }
            memcpy((char *)xmm_io->xmm + (in_regs + done - rep_idx) * 16,
                   val, 16);
            *xmm_out_count = in_regs + done - rep_idx + 1;
        } else if (vsm->ops->guest_write(vsm->vm, out_gpa + done * 16,
                                         val, 16)) {
            return mkstatus(HV_VSM_STATUS_INVALID_ALIGNMENT, done);
        }
    }

    return mkstatus(HV_VSM_STATUS_SUCCESS, rep_cnt);
}

static uint64_t do_set_vp_registers(struct hv_vsm *vsm, uint32_t caller,
                                    uint64_t control, uint64_t in_gpa,
                                    uint64_t out_gpa, bool fast,
                                    const struct kvm_fpu *xmm_in)
{
    struct hv_vsm_get_vp_registers_input hdr; /* same 16-byte header */
    uint16_t rep_cnt = (control & HV_VSM_HYPERCALL_REP_COMP_MASK) >>
                       HV_VSM_HYPERCALL_REP_COMP_SHIFT;
    uint16_t rep_idx = (control & HV_VSM_HYPERCALL_REP_START_MASK) >>
                       HV_VSM_HYPERCALL_REP_START_SHIFT;
    uint32_t vp;
    uint8_t target_vtl;
    uint16_t done;

    if (!rep_cnt || rep_idx >= rep_cnt) {
        return mkstatus(HV_VSM_STATUS_INVALID_HYPERCALL_INPUT, 0);
    }
    if (fast) {
        /* Header in the fast GPR pair, rep elements packed into XMM0-5. */
        memcpy(&hdr, &in_gpa, 8);
        memcpy((char *)&hdr + 8, &out_gpa, 8);
    } else if (vsm->ops->guest_read(vsm->vm, in_gpa, &hdr, sizeof(hdr))) {
        return mkstatus(HV_VSM_STATUS_INVALID_ALIGNMENT, 0);
    }
    if (hdr.partition_id != HV_VSM_PARTITION_ID_SELF) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARTITION_ID, 0);
    }
    if (resolve_vp(vsm, caller, hdr.vp_index, &vp)) {
        return mkstatus(HV_VSM_STATUS_INVALID_VP_INDEX, 0);
    }
    target_vtl = hdr.input_vtl.use_target_vtl ? hdr.input_vtl.target_vtl :
                 vsm->vp[caller].active_vtl;
    if (target_vtl > HV_VSM_MAX_VTL) {
        return mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
    }
    if (target_vtl > vsm->vp[caller].active_vtl) {
        return mkstatus(HV_VSM_STATUS_ACCESS_DENIED, 0);
    }

    for (done = rep_idx; done < rep_cnt; done++) {
        struct hv_vsm_register_assoc assoc;
        uint64_t val[2];
        int status;

        if (fast) {
            if ((done + 1) * sizeof(assoc) > 6 * 16) {
                return mkstatus(HV_VSM_STATUS_INVALID_HYPERCALL_INPUT, done);
            }
            memcpy(&assoc, (const char *)xmm_in->xmm + done * sizeof(assoc),
                   sizeof(assoc));
        } else if (vsm->ops->guest_read(vsm->vm, in_gpa + sizeof(hdr) +
                                        done * sizeof(assoc), &assoc,
                                        sizeof(assoc))) {
            return mkstatus(HV_VSM_STATUS_INVALID_ALIGNMENT, done);
        }

        val[0] = assoc.value_low;
        val[1] = assoc.value_high;
        status = set_one_register(vsm, vp, target_vtl, assoc.name, val);
        if (status) {
            return mkstatus(status, done);
        }
    }

    return mkstatus(HV_VSM_STATUS_SUCCESS, rep_cnt);
}

/*
 * Deliver a TLFS GPA-intercept message into the entered VTL's SIM slot 0,
 * capturing the faulting VTL's execution context.  Delivered as part of VTL
 * entry: no SINT interrupt is raised; the secure kernel reads slot 0 when the
 * entry reason is HV_VSM_VTL_ENTRY_INTERCEPT.
 */
static void deliver_gpa_intercept(struct hv_vsm *vsm, uint32_t vp,
                                  uint8_t from_vtl, uint8_t to_vtl,
                                  uint64_t gpa, int access,
                                  const struct hv_vsm_fault_info *fi,
                                  const struct kvm_regs *regs)
{
    if (vsm_dbg()) fprintf(stderr, "vsm-gpaint: vp%u vtl%d->%d gpa=0x%llx access=%d\n",
            vp, from_vtl, to_vtl, (unsigned long long)gpa, access);
    const struct hv_vsm_host_ops *ops = vsm->ops;
    struct {
        struct hv_vsm_message_header hdr;
        struct hv_vsm_memory_intercept_message m;
    } __hv_vsm_packed msg;
    struct kvm_sregs sregs;
    uint64_t simp = 0;

    if (ops->vcpu_get_msr(vsm->vm, to_vtl, vp, HV_VSM_MSR_SIMP, &simp) ||
        !(simp & 1)) {
        vsm_log(vsm, "intercept dropped (no SIMP), gpa", gpa);
        return;
    }
    if (ops->vcpu_get_sregs(vsm->vm, from_vtl, vp, &sregs)) {
        return;
    }

    memset(&msg, 0, sizeof(msg));
    msg.hdr.message_type = HV_VSM_MSG_GPA_INTERCEPT;
    msg.hdr.payload_size = sizeof(msg.m);

    msg.m.header.vp_index = vp;
    msg.m.header.instruction_length = 0;
    msg.m.header.access_type = access;
    msg.m.header.exec_state = intercept_exec_state(regs, &sregs);
    store_segment(&sregs.cs, &msg.m.header.cs);
    msg.m.header.rip = regs->rip;
    msg.m.header.rflags = regs->rflags;

    msg.m.cache_type = 6;       /* 6 = writeback */
    msg.m.memory_access_info = 0;   /* reference host never sets gva here */
    msg.m.gva = 0;
    msg.m.instruction_byte_count = 0;
    if (fi) {
        msg.m.header.instruction_length = fi->insn_len & 0xf;
        /*
         * No instruction bytes for execute intercepts: RIP points into
         * the faulted page, there is nothing to decode (and the
         * reference host leaves the field empty too).
         */
        if (access != HV_VSM_INTERCEPT_ACCESS_EXECUTE) {
            size_t blen = fi->insn_len;

            if (blen > sizeof(msg.m.instruction_bytes)) {
                blen = sizeof(msg.m.instruction_bytes);
            }
            msg.m.instruction_byte_count = blen;
            memcpy(msg.m.instruction_bytes, fi->insn_bytes, blen);
        }
    }
    msg.m.gpa = gpa;
    store_segment(&sregs.ds, &msg.m.ds);
    store_segment(&sregs.ss, &msg.m.ss);
    msg.m.rax = regs->rax;
    msg.m.rcx = regs->rcx;
    msg.m.rdx = regs->rdx;
    msg.m.rbx = regs->rbx;
    msg.m.rsp = regs->rsp;
    msg.m.rbp = regs->rbp;
    msg.m.rsi = regs->rsi;
    msg.m.rdi = regs->rdi;
    msg.m.r8 = regs->r8;
    msg.m.r9 = regs->r9;
    msg.m.r10 = regs->r10;
    msg.m.r11 = regs->r11;
    msg.m.r12 = regs->r12;
    msg.m.r13 = regs->r13;
    msg.m.r14 = regs->r14;
    msg.m.r15 = regs->r15;

    /* SIM slot 0 is reserved for hypervisor intercept messages. */
    simp_write(vsm, to_vtl, simp, &msg, sizeof(msg));
    assert_sint0(vsm, to_vtl, vp);
}

enum hv_vsm_action hv_vsm_handle_protection_fault(struct hv_vsm *vsm,
                                                  uint64_t gpa, int access,
                                                  uint32_t vp,
                                                  const struct hv_vsm_fault_info *fi,
                                                  struct hv_vsm_hcall_result *res)
{
    struct hv_vsm_vp *v = &vsm->vp[vp];
    struct kvm_regs regs;
    uint8_t from_vtl = v->active_vtl;
    uint64_t assist;
    uint64_t simp = 0;

    res->resume_rax = 0;
    if (v->active_vtl >= HV_VSM_MAX_VTL || !(v->enabled_vtl_set & 2)) {
        return HV_VSM_UNHANDLED;
    }
    /*
     * Check deliverability before switch_vtl(): the target VTL must never
     * be entered without the intercept message in its SIM. With its SIMP
     * disabled the reference host fails message delivery and injects #UD
     * into the faulting VTL at the unretired instruction instead.
     */
    if (vsm->ops->vcpu_get_msr(vsm->vm, from_vtl + 1, vp, HV_VSM_MSR_SIMP,
                               &simp) || !(simp & 1)) {
        if (vsm->ops->vcpu_queue_exception) {
            vsm_log(vsm, "gpa intercept undeliverable (no SIMP), gpa", gpa);
            vsm->ops->vcpu_queue_exception(vsm->vm, from_vtl, vp, 6 /* #UD */,
                                           false, 0, false, 0);
            return HV_VSM_RAISE_UD;
        }
        return HV_VSM_UNHANDLED;
    }
    if (vsm->ops->vcpu_get_regs(vsm->vm, v->active_vtl, vp, &regs)) {
        return HV_VSM_UNHANDLED;
    }
    if (switch_vtl(vsm, vp, v->active_vtl, v->active_vtl + 1)) {
        return HV_VSM_UNHANDLED;
    }

    v->entry_rax = regs.rax;
    v->entry_rcx = regs.rcx;
    deliver_gpa_intercept(vsm, vp, from_vtl, v->active_vtl, gpa, access,
                          fi, &regs);

    /*
     * The faulting VTL is suspended mid-instruction, not in a hypercall;
     * record the intercept entry reason so the entered VTL can tell this
     * apart from an explicit VTL call.
     */
    assist = assist_page_gpa(vsm, v->active_vtl, vp);
    if (assist) {
        struct hv_vsm_vtl_control ctl = {
            .vtl_entry_reason = HV_VSM_VTL_ENTRY_INTERRUPT,
            .vtl_ret_x64rax = regs.rax,
            .vtl_ret_x64rcx = regs.rcx,
        };

        vsm->ops->guest_write(vsm->vm, assist + HV_VSM_VTL_CONTROL_OFFSET,
                              &ctl, sizeof(ctl));
    }
    res->resume_rax = regs.rax;
    return HV_VSM_SWITCHED;
}

/*
 * A lower-VTL descriptor-table write hit a register intercept the higher
 * VTL armed via HvRegisterCrInterceptControl: deliver the TLFS register
 * intercept message into the higher VTL's SIM slot 0 and enter it with
 * the INTERCEPT reason.  The write itself is not applied; the higher VTL
 * emulates or rejects it and adjusts the lower VTL's state before the
 * VTL return.
 */
enum hv_vsm_action hv_vsm_deliver_reg_intercept(struct hv_vsm *vsm,
                                                uint32_t vp, uint32_t reg,
                                                uint64_t base, uint32_t limit,
                                                uint64_t rip, uint8_t insn_len,
                                                struct hv_vsm_hcall_result *res)
{
    const struct hv_vsm_host_ops *ops = vsm->ops;
    struct hv_vsm_vp *v = &vsm->vp[vp];
    struct {
        struct hv_vsm_message_header hdr;
        struct hv_vsm_register_intercept_message m;
    } __hv_vsm_packed msg;
    struct kvm_sregs sregs;
    struct kvm_regs regs;
    uint8_t from_vtl = v->active_vtl;
    uint64_t simp = 0;
    uint64_t assist;

    res->resume_rax = 0;
    if (v->active_vtl >= HV_VSM_MAX_VTL || !(v->enabled_vtl_set & 2)) {
        return HV_VSM_UNHANDLED;
    }
    if (ops->vcpu_get_msr(vsm->vm, from_vtl + 1, vp, HV_VSM_MSR_SIMP, &simp) ||
        !(simp & 1)) {
        /*
         * Undeliverable intercept: the target VTL has no enabled SIMP to
         * receive the message. The reference host injects #UD into the
         * faulting VTL and never enters the target; the kernel rewound
         * RIP when it emitted the exit, so the #UD lands on the
         * intercepted instruction itself.
         */
        if (ops->vcpu_queue_exception) {
            vsm_log(vsm, "reg intercept undeliverable (no SIMP), reg", reg);
            ops->vcpu_queue_exception(vsm->vm, from_vtl, vp, 6 /* #UD */,
                                      false, 0, false, 0);
            return HV_VSM_RAISE_UD;
        }
        vsm_log(vsm, "reg intercept dropped (no SIMP), reg", reg);
        return HV_VSM_UNHANDLED;
    }
    if (ops->vcpu_get_regs(vsm->vm, from_vtl, vp, &regs) ||
        ops->vcpu_get_sregs(vsm->vm, from_vtl, vp, &sregs)) {
        return HV_VSM_UNHANDLED;
    }

    memset(&msg, 0, sizeof(msg));
    msg.hdr.message_type = HV_VSM_MSG_REGISTER_INTERCEPT;
    msg.hdr.payload_size = sizeof(msg.m);

    msg.m.header.vp_index = vp;
    msg.m.header.instruction_length = insn_len;
    msg.m.header.access_type = HV_VSM_INTERCEPT_ACCESS_WRITE;
    msg.m.header.exec_state = intercept_exec_state(&regs, &sregs);
    store_segment(&sregs.cs, &msg.m.header.cs);
    msg.m.header.rip = rip;
    msg.m.header.rflags = regs.rflags;

    /* Windows reads source_value regardless; see the reference host. */
    msg.m.is_memory_op = 1;
    msg.m.reg_name = reg;
    if (reg == HV_VSM_X64_REGISTER_LDTR_ID ||
        reg == HV_VSM_X64_REGISTER_TR_ID) {
        /* A selector write: the raw 16-bit value, not a table register. */
        msg.m.source_value.reg128.low = base & 0xffff;
    } else {
        msg.m.source_value.table.limit = limit;
        msg.m.source_value.table.base = base;
    }

    if (switch_vtl(vsm, vp, from_vtl, from_vtl + 1)) {
        return HV_VSM_UNHANDLED;
    }
    v->entry_rax = regs.rax;
    v->entry_rcx = regs.rcx;

    simp_write(vsm, from_vtl + 1, simp, &msg, sizeof(msg));
    assert_sint0(vsm, from_vtl + 1, vp);

    assist = assist_page_gpa(vsm, v->active_vtl, vp);
    if (assist) {
        struct hv_vsm_vtl_control ctl = {
            .vtl_entry_reason = HV_VSM_VTL_ENTRY_INTERRUPT,
            .vtl_ret_x64rax = regs.rax,
            .vtl_ret_x64rcx = regs.rcx,
        };

        vsm->ops->guest_write(vsm->vm, assist + HV_VSM_VTL_CONTROL_OFFSET,
                              &ctl, sizeof(ctl));
    }
    res->resume_rax = regs.rax;
    return HV_VSM_SWITCHED;
}

/*
 * Enter a higher VTL because it has a pending interrupt (TLFS: a higher
 * VTL's interrupts preempt lower-VTL execution).  The lower VTL is
 * suspended mid-instruction; the entered VTL's control area carries the
 * INTERRUPT entry reason with the preempted RAX/RCX, which the VTL
 * return path restores.
 */
enum hv_vsm_action hv_vsm_vtl_interrupt_entry(struct hv_vsm *vsm,
                                              uint32_t vp, uint8_t target_vtl,
                                              struct hv_vsm_hcall_result *res)
{
    struct hv_vsm_vp *v = &vsm->vp[vp];
    struct kvm_regs regs;
    uint64_t assist;

    res->resume_rax = 0;
    if (vp >= vsm->nr_vps || target_vtl > HV_VSM_MAX_VTL ||
        target_vtl <= v->active_vtl ||
        !(v->enabled_vtl_set & (1 << target_vtl))) {
        return HV_VSM_UNHANDLED;
    }
    /*
     * The target VTL only enables its VP assist page once it has fully
     * brought this VP up; forcing entry before that triple-faults the
     * guest (reference host rule).  The event stays in the target's IRR
     * and is delivered on the next cooperative entry.
     */
    if (!assist_page_gpa(vsm, target_vtl, vp)) {
        return HV_VSM_UNHANDLED;
    }
    if (vsm->ops->vcpu_get_regs(vsm->vm, v->active_vtl, vp, &regs)) {
        return HV_VSM_UNHANDLED;
    }
    if (switch_vtl(vsm, vp, v->active_vtl, target_vtl)) {
        return HV_VSM_UNHANDLED;
    }

    v->entry_rax = regs.rax;
    v->entry_rcx = regs.rcx;

    if (getenv("VSM_DEBUG")) {
        v->dbg_forced_regs = regs;
        v->dbg_forced_pending = true;
    }

    assist = assist_page_gpa(vsm, v->active_vtl, vp);
    if (assist) {
        struct hv_vsm_vtl_control ctl = {
            .vtl_entry_reason = HV_VSM_VTL_ENTRY_INTERRUPT,
            .vtl_ret_x64rax = regs.rax,
            .vtl_ret_x64rcx = regs.rcx,
        };

        vsm->ops->guest_write(vsm->vm, assist + HV_VSM_VTL_CONTROL_OFFSET,
                              &ctl, sizeof(ctl));
    }
    res->resume_rax = regs.rax;
    return HV_VSM_SWITCHED;
}

/*
 * With in-kernel VTL switching the host no longer sees every transition;
 * each forwarded exit reports the plane it came from, and the glue syncs
 * it here before handling.
 */
void hv_vsm_set_active_vtl(struct hv_vsm *vsm, uint32_t vp, uint8_t vtl)
{
    if (vp < vsm->nr_vps && vtl <= HV_VSM_MAX_VTL) {
        vsm->vp[vp].active_vtl = vtl;
    }
}

enum hv_vsm_action hv_vsm_handle_hcall(struct hv_vsm *vsm, uint32_t vp,
                                       uint64_t control, uint64_t in_gpa,
                                       uint64_t out_gpa,
                                       struct hv_vsm_hcall_result *res)
{
    uint16_t code = control & HV_VSM_HYPERCALL_CODE_MASK;
    bool fast = control & HV_VSM_HYPERCALL_FAST;
    struct hv_vsm_vp *v = &vsm->vp[vp];
    struct kvm_regs regs;

    res->resume_rax = 0;

    switch (code) {
    case HV_VSM_CALL_ENABLE_PARTITION_VTL:
        res->result = do_enable_partition_vtl(vsm, vp, control, in_gpa, fast,
                                              out_gpa);
        return HV_VSM_COMPLETE;

    case HV_VSM_CALL_ENABLE_VP_VTL:
        res->result = do_enable_vp_vtl(vsm, vp, control, in_gpa, fast);
        return HV_VSM_COMPLETE;

    case HV_VSM_CALL_GET_VP_REGISTERS: {
        struct kvm_fpu fpu;
        int xmm_out = 0;
        uint64_t result;

        if (fast && vsm->ops->vcpu_get_fpu(vsm->vm, v->active_vtl, vp, &fpu)) {
            res->result = mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
            return HV_VSM_COMPLETE;
        }
        result = do_get_vp_registers(vsm, vp, control, in_gpa, out_gpa, fast,
                                     fast ? &fpu : NULL, &xmm_out);
        if (fast && xmm_out &&
            (result & 0xffff) == HV_VSM_STATUS_SUCCESS) {
            vsm->ops->vcpu_set_fpu(vsm->vm, v->active_vtl, vp, &fpu);
        }
        res->result = result;
        return HV_VSM_COMPLETE;
    }

    case HV_VSM_CALL_SET_VP_REGISTERS: {
        struct kvm_fpu fpu;

        if (fast && vsm->ops->vcpu_get_fpu(vsm->vm, v->active_vtl, vp, &fpu)) {
            res->result = mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
            return HV_VSM_COMPLETE;
        }
        res->result = do_set_vp_registers(vsm, vp, control, in_gpa, out_gpa,
                                          fast, fast ? &fpu : NULL);
        return HV_VSM_COMPLETE;
    }

    case HV_VSM_CALL_VTL_CALL: {
        uint64_t assist;

        /* An invalid VTL call faults rather than completing. */
        if (v->active_vtl >= HV_VSM_MAX_VTL || !(v->enabled_vtl_set & 2)) {
            return HV_VSM_RAISE_UD;
        }
        if (vsm->ops->vcpu_get_regs(vsm->vm, v->active_vtl, vp, &regs)) {
            return HV_VSM_RAISE_UD;
        }
        if (switch_vtl(vsm, vp, v->active_vtl, v->active_vtl + 1)) {
            return HV_VSM_RAISE_UD;
        }
        v->suspended_in_hcall[v->active_vtl - 1] = true;
        v->entry_rax = regs.rax;
        v->entry_rcx = regs.rcx;
        if (vsm_dbg()) {
            fprintf(stderr, "hv-vsm dbg: CALLER0 vp%u rsp=%llx rip=%llx\n", vp,
                    (unsigned long long)regs.rsp, (unsigned long long)regs.rip);
        }
        {
            struct kvm_regs t;

            if (!vsm->ops->vcpu_get_regs(vsm->vm, v->active_vtl, vp, &t)) {
                if (vsm_dbg()) {
                    fprintf(stderr, "hv-vsm dbg: CALLREGS vp%u tgt rax=%llx rbx=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx r8=%llx rsp=%llx rip=%llx rfl=%llx\n",
                            vp,
                            (unsigned long long)t.rax, (unsigned long long)t.rbx,
                            (unsigned long long)t.rcx, (unsigned long long)t.rdx,
                            (unsigned long long)t.rsi, (unsigned long long)t.rdi,
                            (unsigned long long)t.r8, (unsigned long long)t.rsp,
                            (unsigned long long)t.rip,
                            (unsigned long long)t.rflags);
                }
            }
        }

        /*
         * Stash the entering VTL's RAX/RCX and the entry reason in the
         * entered VTL's assist page, when it has one; a non-fast VTL
         * return restores from there.
         */
        assist = assist_page_gpa(vsm, v->active_vtl, vp);
        if (assist) {
            struct hv_vsm_vtl_control ctl = {
                .vtl_entry_reason = HV_VSM_VTL_ENTRY_VTL_CALL,
                .vtl_ret_x64rax = regs.rax,
                .vtl_ret_x64rcx = regs.rcx,
            };

            vsm->ops->guest_write(vsm->vm,
                                  assist + HV_VSM_VTL_CONTROL_OFFSET,
                                  &ctl, sizeof(ctl));
        }
        res->resume_rax = regs.rax;
        return HV_VSM_SWITCHED;
    }

    case HV_VSM_CALL_VTL_RETURN: {
        struct hv_vsm_vtl_control ctl = {0};
        uint64_t assist = 0;
        bool fast_ret;

        if (v->active_vtl == 0) {
            return HV_VSM_RAISE_UD;
        }
        if (vsm->ops->vcpu_get_regs(vsm->vm, v->active_vtl, vp, &regs)) {
            return HV_VSM_RAISE_UD;
        }
        /* The thunk parks the caller's VTL-return control value in RAX. */
        fast_ret = regs.rax & HV_VSM_VTL_RETURN_FAST;
        if (!fast_ret) {
            /*
             * Restore the lower VTL's RAX/RCX from the returning VTL's
             * assist-page VTL control area when one is registered (the
             * higher VTL may have modified them there), else from the
             * values stashed at VTL entry.
             */
            assist = assist_page_gpa(vsm, v->active_vtl, vp);
            if (assist) {
                if (vsm->ops->guest_read(vsm->vm,
                                         assist + HV_VSM_VTL_CONTROL_OFFSET,
                                         &ctl, sizeof(ctl))) {
                    return HV_VSM_RAISE_UD;
                }
            } else {
                ctl.vtl_ret_x64rax = v->entry_rax;
                ctl.vtl_ret_x64rcx = v->entry_rcx;
            }
        }
        if (switch_vtl(vsm, vp, v->active_vtl, v->active_vtl - 1)) {
            return HV_VSM_RAISE_UD;
        }
        v->suspended_in_hcall[v->active_vtl + 1] = true;

        if (!fast_ret) {
            struct kvm_regs lower;

            /*
             * The lower VTL resumes with the stashed RAX and RCX. Set
             * RAX directly as well as via the resume value: a plane
             * suspended by an in-kernel switch has no pending hypercall
             * completion to consume the resume value.
             */
            if (!vsm->ops->vcpu_get_regs(vsm->vm, v->active_vtl, vp,
                                         &lower)) {
                lower.rax = ctl.vtl_ret_x64rax;
                lower.rcx = ctl.vtl_ret_x64rcx;
                vsm->ops->vcpu_set_regs(vsm->vm, v->active_vtl, vp, &lower);
            }
            res->resume_rax = ctl.vtl_ret_x64rax;
        } else {
            res->resume_rax = regs.rax;
        }
        if (v->dbg_forced_pending) {
            struct kvm_regs now;

            v->dbg_forced_pending = false;
            if (!vsm->ops->vcpu_get_regs(vsm->vm, v->active_vtl, vp, &now)) {
                struct kvm_regs *o = &v->dbg_forced_regs;
                #define DCHK(f) if (now.f != o->f)                     fprintf(stderr, "vsm-gprdiff: vp%u fast=%d " #f                             " %llx -> %llx (rip=%llx)\n", vp, (int)fast_ret,                             (unsigned long long)o->f,                             (unsigned long long)now.f,                             (unsigned long long)now.rip);
                if (now.rax != o->rax)
                    fprintf(stderr, "vsm-gprdiff-ctl: vp%u fast=%d reason=%u "
                            "ret_rax=%llx ret_rcx=%llx stash_rax=%llx\n",
                            vp, (int)fast_ret, ctl.vtl_entry_reason,
                            (unsigned long long)ctl.vtl_ret_x64rax,
                            (unsigned long long)ctl.vtl_ret_x64rcx,
                            (unsigned long long)v->entry_rax);
                DCHK(rax) DCHK(rbx) DCHK(rcx) DCHK(rdx) DCHK(rsi) DCHK(rdi)
                DCHK(rbp) DCHK(r8) DCHK(r9) DCHK(r10) DCHK(r11) DCHK(r12)
                DCHK(r13) DCHK(r14) DCHK(r15) DCHK(rsp) DCHK(rip)
                #undef DCHK
            }
        }
        return HV_VSM_SWITCHED;
    }

    case HV_VSM_CALL_TRANSLATE_VIRTUAL_ADDRESS: {
        struct kvm_fpu fpu;
        int xmm_out = 0;

        if (fast && vsm->ops->vcpu_get_fpu(vsm->vm, v->active_vtl, vp, &fpu)) {
            res->result = mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
            return HV_VSM_COMPLETE;
        }
        res->result = do_translate_virtual_address(vsm, vp, control, in_gpa,
                                                   out_gpa, fast,
                                                   fast ? &fpu : NULL,
                                                   fast ? &fpu : NULL,
                                                   &xmm_out);
        if (fast && xmm_out &&
            (res->result & 0xffff) == HV_VSM_STATUS_SUCCESS) {
            vsm->ops->vcpu_set_fpu(vsm->vm, v->active_vtl, vp, &fpu);
        }
        return HV_VSM_COMPLETE;
    }

    case HV_VSM_CALL_GET_VP_INDEX_FROM_APIC_ID: {
        struct kvm_fpu fpu;
        int xmm_out = 0;

        if (fast && vsm->ops->vcpu_get_fpu(vsm->vm, v->active_vtl, vp, &fpu)) {
            res->result = mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
            return HV_VSM_COMPLETE;
        }
        res->result = do_get_vp_index_from_apic_id(vsm, control, in_gpa,
                                                   out_gpa, fast,
                                                   fast ? &fpu : NULL,
                                                   &xmm_out);
        if (fast && xmm_out &&
            (res->result & 0xffff) == HV_VSM_STATUS_SUCCESS) {
            vsm->ops->vcpu_set_fpu(vsm->vm, v->active_vtl, vp, &fpu);
        }
        return HV_VSM_COMPLETE;
    }

    case HV_VSM_CALL_MODIFY_VTL_PROTECTION_MASK: {
        struct kvm_fpu fpu;

        if (fast && vsm->ops->vcpu_get_fpu(vsm->vm, v->active_vtl, vp, &fpu)) {
            res->result = mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
            return HV_VSM_COMPLETE;
        }
        res->result = do_modify_vtl_protection_mask(vsm, vp, control, in_gpa,
                                                    out_gpa, fast,
                                                    fast ? &fpu : NULL);
        return HV_VSM_COMPLETE;
    }

    case HV_VSM_CALL_NOTIFY_PARTITION_EVENT:
        /*
         * Accepted; event delivery is not implemented.  The secure kernel
         * reports crash progress through this call, so failing it would
         * mask guest diagnostics.
         */
        res->result = mkstatus(HV_VSM_STATUS_SUCCESS, 0);
        return HV_VSM_COMPLETE;

    case HV_VSM_CALL_ASSERT_VIRTUAL_INTERRUPT: {
        struct {
            uint64_t partition_id;
            uint64_t interrupt_control;
            uint64_t destination_address;
            uint32_t requested_vector;
            uint8_t target_vtl;
            uint8_t rsvd[3];
        } __hv_vsm_packed in;

        if (control & (HV_VSM_HYPERCALL_REP_COMP_MASK |
                       HV_VSM_HYPERCALL_REP_START_MASK)) {
            res->result = mkstatus(HV_VSM_STATUS_INVALID_HYPERCALL_INPUT, 0);
            return HV_VSM_COMPLETE;
        }
        if (fast) {
            struct kvm_fpu fpu;

            if (vsm->ops->vcpu_get_fpu(vsm->vm, v->active_vtl, vp, &fpu)) {
                res->result = mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
                return HV_VSM_COMPLETE;
            }
            memcpy(&in, &in_gpa, 8);
            memcpy((char *)&in + 8, &out_gpa, 8);
            memcpy((char *)&in + 16, fpu.xmm[0], 16);
        } else if (vsm->ops->guest_read(vsm->vm, in_gpa, &in, sizeof(in))) {
            res->result = mkstatus(HV_VSM_STATUS_INVALID_ALIGNMENT, 0);
            return HV_VSM_COMPLETE;
        }
        if (in.partition_id != HV_VSM_PARTITION_ID_SELF ||
            in.target_vtl > HV_VSM_MAX_VTL) {
            res->result = mkstatus(HV_VSM_STATUS_INVALID_PARTITION_ID, 0);
            return HV_VSM_COMPLETE;
        }
        if (!vsm->ops->assert_interrupt ||
            vsm->ops->assert_interrupt(vsm->vm, in.target_vtl,
                                       in.destination_address,
                                       in.requested_vector,
                                       (uint32_t)in.interrupt_control,
                                       !!(in.interrupt_control &
                                          (1ULL << 33)))) {
            res->result = mkstatus(HV_VSM_STATUS_INVALID_PARAMETER, 0);
            return HV_VSM_COMPLETE;
        }
        res->result = mkstatus(HV_VSM_STATUS_SUCCESS, 0);
        return HV_VSM_COMPLETE;
    }

    case HV_VSM_EXT_CALL_QUERY_CAPABILITIES: {
        /* No extended hypercalls beyond the query itself. */
        uint64_t caps = 0;

        if (control & (HV_VSM_HYPERCALL_REP_COMP_MASK |
                       HV_VSM_HYPERCALL_REP_START_MASK)) {
            res->result = mkstatus(HV_VSM_STATUS_INVALID_HYPERCALL_INPUT, 0);
        } else if (vsm->ops->guest_write(vsm->vm, out_gpa, &caps,
                                         sizeof(caps))) {
            res->result = mkstatus(HV_VSM_STATUS_INVALID_ALIGNMENT, 0);
        } else {
            res->result = mkstatus(HV_VSM_STATUS_SUCCESS, 0);
        }
        return HV_VSM_COMPLETE;
    }

    case HV_VSM_CALL_START_VP:
        res->result = do_start_vp(vsm, vp, control, in_gpa, fast);
        return HV_VSM_COMPLETE;

    default:
        vsm_log(vsm, "hypercall code", code);
        return HV_VSM_UNHANDLED;
    }
}
