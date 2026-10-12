/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Hyper-V VSM (Virtual Secure Mode) userspace emulation core.
 *
 * This file and hv-vsm.c are deliberately free of QEMU types so the same
 * code can be compiled into any Linux VMM that exposes the small host-ops
 * table below (QEMU today; KVM selftests harnesses and other VMMs later).
 * The kernel contract is the KVM planes model plus two capabilities:
 * KVM_CAP_HYPERV_FORWARD_HCALL routes the hypercalls below to the VMM, and
 * KVM_GET/SET_PLANE_RUN_STATE selects which plane a vCPU runs.  One VTL maps
 * to one KVM plane, same index.
 *
 * Numeric ABI values follow the Microsoft TLFS as shipped in the mainline
 * Linux headers include/hyperv/hvgdk_mini.h; values absent there carry a
 * comment naming their source.  The layouts mirror the VSM conformance
 * suite's x86/hyperv_vsm.h, which is verified against both the headers and
 * the Brimstone implementation.
 */
#ifndef HV_VSM_CORE_H
#define HV_VSM_CORE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <linux/kvm.h>

#define HV_VSM_MAX_VTL          1   /* VTL0 and VTL1 for now */

/* Hypercall status codes (RAX bits 15:0) */
#define HV_VSM_STATUS_SUCCESS                   0x0
#define HV_VSM_STATUS_INVALID_HYPERCALL_CODE    0x2
#define HV_VSM_STATUS_INVALID_HYPERCALL_INPUT   0x3
#define HV_VSM_STATUS_INVALID_ALIGNMENT         0x4
#define HV_VSM_STATUS_INVALID_PARAMETER         0x5
#define HV_VSM_STATUS_ACCESS_DENIED             0x6
#define HV_VSM_STATUS_INVALID_PARTITION_ID      0xD
#define HV_VSM_STATUS_INVALID_VP_INDEX          0xE
#define HV_VSM_STATUS_INVALID_VP_STATE          0x15
#define HV_VSM_STATUS_VTL_ALREADY_ENABLED       0x86

/* Hypercall input value layout (RCX) */
#define HV_VSM_HYPERCALL_CODE_MASK      0xffffULL
#define HV_VSM_HYPERCALL_FAST           (1ULL << 16)
#define HV_VSM_HYPERCALL_VARHEAD_SHIFT  17
#define HV_VSM_HYPERCALL_VARHEAD_MASK   (0x3ffULL << 17)
#define HV_VSM_HYPERCALL_RSVD1_MASK     (0x1fULL << 27)
#define HV_VSM_HYPERCALL_REP_COMP_SHIFT 32
#define HV_VSM_HYPERCALL_REP_COMP_MASK  (0xfffULL << 32)
#define HV_VSM_HYPERCALL_RSVD2_MASK     (0xfULL << 44)
#define HV_VSM_HYPERCALL_REP_START_SHIFT 48
#define HV_VSM_HYPERCALL_REP_START_MASK (0xfffULL << 48)
#define HV_VSM_HYPERCALL_RSVD3_MASK     (0xfULL << 60)

/* Hypercall codes handled here (0x0d/0x11/0x12 absent from mainline: TLFS) */
#define HV_VSM_CALL_MODIFY_VTL_PROTECTION_MASK  0x000c
#define HV_VSM_CALL_ENABLE_PARTITION_VTL        0x000d
#define HV_VSM_CALL_ENABLE_VP_VTL               0x000f
#define HV_VSM_CALL_VTL_CALL                    0x0011
#define HV_VSM_CALL_VTL_RETURN                  0x0012
#define HV_VSM_CALL_NOTIFY_PARTITION_EVENT      0x0087
#define HV_VSM_CALL_ASSERT_VIRTUAL_INTERRUPT    0x0094
#define HV_VSM_CALL_START_VP                    0x0099
#define HV_VSM_EXT_CALL_QUERY_CAPABILITIES      0x8001
#define HV_VSM_CALL_GET_VP_REGISTERS            0x0050
#define HV_VSM_CALL_SET_VP_REGISTERS            0x0051
#define HV_VSM_CALL_TRANSLATE_VIRTUAL_ADDRESS   0x0052
#define HV_VSM_CALL_GET_VP_INDEX_FROM_APIC_ID   0x009a
/* 0x103 is reserved in the TLFS; defined in Microsoft's hvdef and in
 * mainline hvgdk_mini.h via the posted nested-Hyper-V hibernation series. */
#define HV_VSM_CALL_RESTORE_PARTITION_TIME      0x0103

#define HV_VSM_PARTITION_ID_SELF        ((uint64_t)-1)

/* HvCallModifyVtlProtectionMask map flags (hvhdk_mini.h) */
#define HV_VSM_MAP_GPA_READABLE         0x1
#define HV_VSM_MAP_GPA_WRITABLE         0x2
#define HV_VSM_MAP_GPA_KERNEL_EXECUTABLE 0x4
#define HV_VSM_MAP_GPA_USER_EXECUTABLE  0x8
#define HV_VSM_VP_INDEX_SELF            ((uint32_t)-2)

/* Synthetic VSM register ids (0xD0004/0xD0005 absent from mainline: TLFS) */
#define HV_VSM_REG_CODE_PAGE_OFFSETS    0x000D0002
#define HV_VSM_REG_VP_STATUS            0x000D0003
#define HV_VSM_REG_PARTITION_STATUS     0x000D0004
#define HV_VSM_REG_VINA                 0x000D0005
#define HV_VSM_REG_VINA                 0x000D0005
#define HV_VSM_REG_CAPABILITIES         0x000D0006
#define HV_VSM_REG_PARTITION_CONFIG     0x000D0007

/*
 * X64 register ids (TLFS hv_register_name).  GPR block 0x2xxxx, DRs
 * 0x5xxxx, segments 0x6xxxx, table registers 0x7xxxx, MSR-backed block
 * 0x8xxxx, per-VP Hyper-V registers 0x9xxxx.
 */
#define HV_VSM_X64_REG_RAX              0x00020000
#define HV_VSM_X64_REG_RSP              0x00020004
#define HV_VSM_X64_REG_R15              0x0002000F
#define HV_VSM_X64_REG_RIP              0x00020010
#define HV_VSM_X64_REG_RFLAGS           0x00020011
#define HV_VSM_X64_REG_ES               0x00060000
#define HV_VSM_X64_REG_CS               0x00060001
#define HV_VSM_X64_REG_SS               0x00060002
#define HV_VSM_X64_REG_DS               0x00060003
#define HV_VSM_X64_REG_FS               0x00060004
#define HV_VSM_X64_REG_GS               0x00060005
#define HV_VSM_X64_REG_LDTR             0x00060006
#define HV_VSM_X64_REG_TR               0x00060007
#define HV_VSM_X64_REG_IDTR             0x00070000
#define HV_VSM_X64_REG_GDTR             0x00070001
#define HV_VSM_X64_REG_TSC              0x00080000
#define HV_VSM_X64_REG_EFER             0x00080001
#define HV_VSM_X64_REG_KERNEL_GS_BASE   0x00080002
#define HV_VSM_X64_REG_APIC_BASE        0x00080003
#define HV_VSM_X64_REG_PAT              0x00080004
#define HV_VSM_X64_REG_SYSENTER_CS      0x00080005
#define HV_VSM_X64_REG_SYSENTER_EIP     0x00080006
#define HV_VSM_X64_REG_SYSENTER_ESP     0x00080007
#define HV_VSM_X64_REG_STAR             0x00080008
#define HV_VSM_X64_REG_LSTAR            0x00080009
#define HV_VSM_X64_REG_CSTAR            0x0008000A
#define HV_VSM_X64_REG_SFMASK           0x0008000B
#define HV_VSM_X64_REG_TSC_AUX          0x0008007B

#define HV_VSM_X64_REG_DR0              0x00050000
#define HV_VSM_X64_REG_DR1              0x00050001
#define HV_VSM_X64_REG_DR2              0x00050002
#define HV_VSM_X64_REG_DR3              0x00050003
#define HV_VSM_X64_REG_DR6              0x00050004
#define HV_VSM_X64_REG_DR7              0x00050005
#define HV_VSM_REG_HYPERCALL            0x00090001
#define HV_VSM_REG_GUEST_OS_ID          0x00090002
#define HV_VSM_REG_VP_ASSIST_PAGE       0x00090013
#define HV_VSM_REG_VP_SECURE_CONFIG_VTL0 0x000D0010
#define HV_VSM_X64_REG_PENDING_EVENT0   0x00010004
#define HV_VSM_REG_DT_TRAPS             0x00090005
#define HV_VSM_REG_REFERENCE_TSC        0x00090017
#define HV_VSM_REG_VP_CONFIG            0x00090018
#define HV_VSM_REG_CR_INTERCEPT_CONTROL  0x000E0000
#define HV_VSM_REG_CR_INTERCEPT_CR0_MASK 0x000E0001
#define HV_VSM_REG_CR_INTERCEPT_CR4_MASK 0x000E0002
#define HV_VSM_REG_CR_INTERCEPT_IA32_MISC_ENABLE_MASK 0x000E0003

/* The MSRs backing the 0x9xxxx registers */
#define HV_VSM_MSR_GUEST_OS_ID          0x40000000
#define HV_VSM_MSR_HYPERCALL            0x40000001
#define HV_VSM_MSR_REFERENCE_TSC        0x40000021
#define HV_VSM_MSR_IA32_TSC             0x00000010
#define HV_VSM_MSR_TSC_REFERENCE_ENABLE 0x1

/* X64 control register ids (TLFS HvX64RegisterCr0..Cr8) */
#define HV_VSM_X64_REG_CR0              0x00040000
#define HV_VSM_X64_REG_CR2              0x00040001
#define HV_VSM_X64_REG_CR3              0x00040002
#define HV_VSM_X64_REG_CR4              0x00040003
#define HV_VSM_X64_REG_CR8              0x00040004

/*
 * Offsets of the VTL call/return thunks this core writes into the guest's
 * hypercall page, reported through HV_VSM_REG_CODE_PAGE_OFFSETS.  The
 * hypervisor's own hypercall stub occupies the first bytes of the page;
 * these land clear of it.
 */
#define HV_VSM_MSR_VP_ASSIST_PAGE       0x40000073
#define HV_VSM_MSR_APIC_BASE            0x0000001b
#define HV_VSM_MSR_SINT0                0x40000090
#define HV_VSM_SINT_MASKED              (1u << 16)
#define HV_VSM_APIC_BASE_BSP            (1ULL << 8)
#define HV_VSM_MSR_VP_ASSIST_ENABLE     0x1

/* VP assist page VTL control area (offset 8), TLFS layout */
#define HV_VSM_VTL_CONTROL_OFFSET       8
#define HV_VSM_VTL_ENTRY_VTL_CALL       1
#define HV_VSM_VTL_ENTRY_INTERRUPT      2
#define HV_VSM_VTL_ENTRY_INTERCEPT      3

/* Faulting-access classification for hv_vsm_handle_protection_fault(). */
#define HV_VSM_INTERCEPT_ACCESS_READ    0
#define HV_VSM_INTERCEPT_ACCESS_WRITE   1
#define HV_VSM_INTERCEPT_ACCESS_EXECUTE 2

#define HV_VSM_PARTITION_CONFIG_ENABLE_VTL_PROTECTION 0x1
#define HV_VSM_PARTITION_CONFIG_DEFAULT_PROT_MASK     0x1e /* bits 1:4 */

#define HV_VSM_MSR_SIMP                 0x40000083
#define HV_VSM_MSG_GPA_INTERCEPT        0x80000001u
#define HV_VSM_MSG_REGISTER_INTERCEPT   0x80010006u

#define HV_VSM_X64_REGISTER_IDTR_ID     0x00070000u
#define HV_VSM_X64_REGISTER_GDTR_ID     0x00070001u
#define HV_VSM_X64_REGISTER_LDTR_ID     0x00060006
#define HV_VSM_X64_REGISTER_TR_ID       0x00060007

/* HvRegisterCrInterceptControl bits */
#define HV_VSM_CR_INTERCEPT_GDTR_WRITE  (1ULL << 15)
#define HV_VSM_CR_INTERCEPT_IDTR_WRITE  (1ULL << 16)
#define HV_VSM_CR_INTERCEPT_LDTR_WRITE  (1ULL << 17)
#define HV_VSM_CR_INTERCEPT_TR_WRITE    (1ULL << 18)

#define HV_VSM_VTL_RETURN_FAST          0x1

#define HV_VSM_VTL_CALL_OFFSET          0x20
#define HV_VSM_VTL_RETURN_OFFSET        0x30

#define __hv_vsm_packed __attribute__((__packed__))

struct hv_vsm_x64_segment_register {
    uint64_t base;
    uint32_t limit;
    uint16_t selector;
    union {
        struct {
            uint16_t segment_type : 4;
            uint16_t non_system_segment : 1;
            uint16_t descriptor_privilege_level : 2;
            uint16_t present : 1;
            uint16_t reserved : 4;
            uint16_t available : 1;
            uint16_t _long : 1;
            uint16_t _default : 1;
            uint16_t granularity : 1;
        };
        uint16_t attributes;
    };
} __hv_vsm_packed;

/* TLFS SynIC message and GPA-intercept payload, delivered to SIM slot 0. */
struct hv_vsm_message_header {
    uint32_t message_type;
    uint8_t payload_size;
    uint8_t message_flags;
    uint16_t reserved;
    uint64_t sender;
} __hv_vsm_packed;

struct hv_vsm_intercept_header {
    uint32_t vp_index;
    uint8_t instruction_length;
    uint8_t access_type;        /* HV_VSM_INTERCEPT_ACCESS_* */
    uint16_t exec_state;        /* cpl:2 cr0_pe:1 cr0_am:1 efer_lma:1 ... */
    struct hv_vsm_x64_segment_register cs;
    uint64_t rip;
    uint64_t rflags;
} __hv_vsm_packed;

struct hv_vsm_memory_intercept_message {
    struct hv_vsm_intercept_header header;
    uint32_t cache_type;        /* 6 = writeback */
    uint8_t instruction_byte_count;
    uint8_t memory_access_info; /* bit 0: gva_valid */
    uint16_t reserved;
    uint64_t gva;
    uint64_t gpa;
    uint8_t instruction_bytes[16];
    struct hv_vsm_x64_segment_register ds;
    struct hv_vsm_x64_segment_register ss;
    uint64_t rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
} __hv_vsm_packed;


union hv_vsm_input_vtl {
    uint8_t as_uint8;
    struct {
        uint8_t target_vtl : 4;
        uint8_t use_target_vtl : 1;
        uint8_t reserved_z : 3;
    };
} __hv_vsm_packed;

struct hv_vsm_x64_table_register {
    uint16_t pad[3];
    uint16_t limit;
    uint64_t base;
} __hv_vsm_packed;

struct hv_vsm_register_intercept_message {
    struct hv_vsm_intercept_header header;
    uint8_t is_memory_op;       /* bit 0; Windows expects it set */
    uint8_t reserved_0;
    uint16_t reserved_1;
    uint32_t reg_name;
    union {
        struct {
            uint64_t low;
            uint64_t high;
        } reg128;
        struct hv_vsm_x64_table_register table;
    } source_value;
} __hv_vsm_packed;

struct hv_vsm_init_vp_context {
    uint64_t rip;
    uint64_t rsp;
    uint64_t rflags;
    struct hv_vsm_x64_segment_register cs, ds, es, fs, gs, ss, tr, ldtr;
    struct hv_vsm_x64_table_register idtr, gdtr;
    uint64_t efer;
    uint64_t cr0;
    uint64_t cr3;
    uint64_t cr4;
    uint64_t msr_cr_pat;
} __hv_vsm_packed;

struct hv_vsm_vtl_control {
    uint32_t vtl_entry_reason;
    uint8_t vina_asserted;
    uint8_t reserved0[3];
    uint64_t vtl_ret_x64rax;
    uint64_t vtl_ret_x64rcx;
} __hv_vsm_packed;

struct hv_vsm_modify_vtl_protection_mask {
    uint64_t target_partition_id;
    uint32_t map_flags;
    union hv_vsm_input_vtl input_vtl;
    uint8_t reserved[3];
    /* uint64_t gpa_page_list[] follows as rep elements */
} __hv_vsm_packed;

struct hv_vsm_enable_partition_vtl {
    uint64_t target_partition_id;
    uint8_t target_vtl;
    uint8_t flags;              /* bit 0: enable_mbec */
    uint8_t reserved[6];
} __hv_vsm_packed;

struct hv_vsm_enable_vp_vtl {
    uint64_t partition_id;
    uint32_t vp_index;
    union hv_vsm_input_vtl target_vtl;
    uint8_t mbz0;
    uint16_t mbz1;
    struct hv_vsm_init_vp_context vp_context;
} __hv_vsm_packed;

/* HvCallRestorePartitionTime input; layout from Microsoft's hvdef (in
 * mainline hvgdk_mini.h via the nested-Hyper-V hibernation series). */
struct hv_vsm_restore_partition_time {
    uint64_t partition_id;
    uint32_t tsc_sequence;
    uint32_t reserved;
    uint64_t reference_time_in_100ns;
    uint64_t tsc;
} __hv_vsm_packed;

struct hv_vsm_get_vp_registers_input {
    uint64_t partition_id;
    uint32_t vp_index;
    union hv_vsm_input_vtl input_vtl;
    uint8_t rsvd_z8;
    uint16_t rsvd_z16;
    /* uint32_t names[] follow */
} __hv_vsm_packed;

struct hv_vsm_register_assoc {
    uint32_t name;
    uint32_t reserved1;
    uint64_t reserved2;
    uint64_t value_low;
    uint64_t value_high;
} __hv_vsm_packed;

/*
 * Host operations the embedding VMM provides.  "plane" is the KVM plane
 * index (== VTL), "vp" is the Hyper-V VP index (== KVM vcpu id).  All
 * return 0 or -errno unless stated.  The vCPU state accessors operate on
 * the plane vCPU fds; the embedder owns fd lifetime.
 */
struct hv_vsm_host_ops {
    /* Create the plane (if needed) and the plane vCPU for (plane, vp). */
    int (*plane_vcpu_create)(void *vm, int plane, uint32_t vp);

    int (*vcpu_get_regs)(void *vm, int plane, uint32_t vp,
                         struct kvm_regs *regs);
    int (*vcpu_set_regs)(void *vm, int plane, uint32_t vp,
                         const struct kvm_regs *regs);
    int (*vcpu_get_sregs)(void *vm, int plane, uint32_t vp,
                          struct kvm_sregs *sregs);
    int (*vcpu_set_sregs)(void *vm, int plane, uint32_t vp,
                          const struct kvm_sregs *sregs);
    /*
     * Atomic read-modify-write of sregs/debugregs on the vCPU's owning
     * thread: get, patch(), set with no guest re-entry in between.  A
     * split get/set pair from another thread races with the target
     * changing other fields of the same struct in guest mode.
     */
    int (*vcpu_patch_sregs)(void *vm, int plane, uint32_t vp,
                            void (*patch)(struct kvm_sregs *s, void *opaque),
                            void *opaque);
    int (*vcpu_patch_debugregs)(void *vm, int plane, uint32_t vp,
                                void (*patch)(struct kvm_debugregs *d,
                                              void *opaque),
                                void *opaque);
    int (*vcpu_get_debugregs)(void *vm, int plane, uint32_t vp,
                              struct kvm_debugregs *dbg);
    int (*vcpu_set_debugregs)(void *vm, int plane, uint32_t vp,
                              const struct kvm_debugregs *dbg);
    /*
     * Copy the full FPU/XSAVE state between two planes of a vp.  The
     * TLFS shares the FPU across VTLs; copying only the legacy FXSAVE
     * area silently corrupts live AVX state across a VTL transition.
     */
    int (*vcpu_copy_xstate)(void *vm, int from_plane, int to_plane,
                            uint32_t vp);
    int (*vcpu_get_fpu)(void *vm, int plane, uint32_t vp, struct kvm_fpu *fpu);
    int (*vcpu_set_fpu)(void *vm, int plane, uint32_t vp,
                        const struct kvm_fpu *fpu);
    int (*vcpu_set_msr)(void *vm, int plane, uint32_t vp, uint32_t msr,
                        uint64_t value);
    int (*vcpu_get_msr)(void *vm, int plane, uint32_t vp, uint32_t msr,
                        uint64_t *value);
    /* KVM_SET_PLANE_RUN_STATE on the (plane, vp) vCPU. */
    int (*vcpu_set_run_state)(void *vm, int plane, uint32_t vp, bool runnable);
    /* Queue an exception into the (plane, vp) vCPU for its next entry.
     * payload carries CR2 for #PF / DR6 bits for #DB (TLFS
     * exception_parameter); has_payload distinguishes zero from absent. */
    int (*vcpu_queue_exception)(void *vm, int plane, uint32_t vp,
                                uint8_t vector, bool has_error,
                                uint32_t error_code, bool has_payload,
                                uint64_t payload);
    /*
     * Host buffer backing the plane's overlay of the given gfn, or NULL.
     * Writes meant for a plane's SynIC message page must go here, not to
     * guest RAM: the memslot holds only the underlay other planes see.
     */
    void *(*overlay_ptr)(void *vm, int plane, uint64_t gfn);
    /* Mark the plane vCPU architecturally runnable (KVM_SET_MP_STATE). */
    int (*vcpu_set_mp_runnable)(void *vm, int plane, uint32_t vp);

    int (*guest_read)(void *vm, uint64_t gpa, void *buf, size_t len);
    int (*guest_write)(void *vm, uint64_t gpa, const void *buf, size_t len);

    /* Guest-physical address of vp's hypercall page, 0 if not established. */
    uint64_t (*hcall_page_gpa)(void *vm, int plane, uint32_t vp);

    /*
     * Translate a guest virtual address in the (plane, vp) context.
     * Returns 0 with *gpa, *valid and *writeable set; nonzero on
     * transport failure.  *writeable reports a supervisor-level write
     * walk of the same address; it may be NULL when the caller only
     * needs presence.
     */
    int (*vcpu_translate)(void *vm, int plane, uint32_t vp, uint64_t gva,
                          uint64_t *gpa, bool *valid, bool *writeable);

    /* VP index for an APIC ID; negative if no such processor. */
    int (*assert_interrupt)(void *vm, uint8_t vtl, uint64_t dest_mda,
                            uint32_t vector, uint32_t type, bool logical);
    int64_t (*vp_from_apic_id)(void *vm, uint32_t apic_id);

    /* True if vp is the partition's boot processor. */
    bool (*vp_is_bsp)(void *vm, uint32_t vp);

    /*
     * Apply KVM_MEMORY_ATTRIBUTE_* to [gpa, gpa+size) as seen by the given
     * plane (KVM_SET_MEMORY_ATTRIBUTES on that plane's VM fd).
     */
    int (*set_memory_attributes)(void *vm, int plane, uint64_t gpa,
                                 uint64_t size, uint64_t attrs);
    /* Arm lower-VTL register intercepts (HvRegisterCrInterceptControl). */
    int (*vcpu_arm_reg_intercepts)(void *vm, uint32_t vp, uint64_t control);

    /*
     * Make the partition-wide clock backing the Hyper-V reference time
     * read ref_ns (nanoseconds) at the moment the guest TSC reads
     * guest_tsc; vp is the calling processor, whose TSC has already been
     * stepped to guest_tsc.  An exact implementation anchors the clock to
     * the (guest_tsc, ref_ns) pair; stepping the clock to ref_ns "now" is
     * an acceptable approximation, costing the latency between the TSC
     * writes and the step.
     */
    int (*set_partition_clock)(void *vm, uint32_t vp, uint64_t ref_ns,
                               uint64_t guest_tsc);

    /* Diagnostics for unimplemented guest requests; may be NULL. */
    void (*log)(void *vm, const char *msg);
};

/* HvRegisterPendingEvent0: TLFS pending exception event (type 0 only). */
union hv_vsm_pending_event {
    uint64_t as_u64[2];
    struct {
        uint32_t event_pending:1;
        uint32_t event_type:3;
        uint32_t reserved0:4;
        uint32_t deliver_error_code:1;
        uint32_t reserved1:7;
        uint32_t vector:16;
        uint32_t error_code;
        uint64_t exception_parameter;
    } __hv_vsm_packed;
} __hv_vsm_packed;

struct hv_vsm_vp {
    uint16_t enabled_vtl_set;   /* bit N: VTL N enabled; bit 0 always set */
    uint8_t active_vtl;
    /* Pending event to deliver on the next entry to each VTL. */
    union hv_vsm_pending_event pending_event[HV_VSM_MAX_VTL + 1];
    bool suspended_in_hcall[HV_VSM_MAX_VTL + 1];
    uint64_t secure_config_vtl0;
    uint64_t dt_traps;
    uint64_t vp_config;
    uint64_t vina;              /* HvRegisterVsmVina; delivery TODO */
    /*
     * Lower-VTL RAX/RCX stashed at VTL entry.  A non-fast VTL return
     * restores these; the entered VTL's assist page, when registered,
     * holds a guest-visible copy the higher VTL may override.
     */
    uint64_t entry_rax;
    uint64_t entry_rcx;
    /* HvRegisterCrInterceptControl armed by the higher VTL. */
    uint64_t cr_intercept_control;
    /* VSM_DEBUG: GPR snapshot at forced entry, diffed at VTL return. */
    struct kvm_regs dbg_forced_regs;
    bool dbg_forced_pending;
};

struct hv_vsm {
    const struct hv_vsm_host_ops *ops;
    void *vm;
    uint32_t nr_vps;
    bool vtl1_partition_enabled;
    bool mbec_requested;
    uint64_t partition_config[HV_VSM_MAX_VTL + 1];
    /*
     * VTL protections recorded before VsmPartitionConfig.EnableVtlProtection
     * is set; flushed to the per-plane memory attributes when the owning VTL
     * enables enforcement.  Entry format: gfn << 8 | attrs.
     */
    uint64_t *pending_prot;
    unsigned nr_pending_prot;
    unsigned pending_prot_cap;
    /*
     * VTL0-view memory attributes that have been applied, encoded as
     * gfn << 8 | attrs (newest entry wins): hv_vsm_reset() restores full
     * access on machine reset, and HvCallTranslateVirtualAddress's
     * access-validation flags are answered from this record.
     */
    uint64_t *applied_prot;
    unsigned nr_applied_prot;
    unsigned applied_prot_cap;
    uint64_t thunked_pages[8];
    unsigned nr_thunked;
    struct hv_vsm_vp *vp;
};

/*
 * Result of hv_vsm_handle_hcall().  For SWITCHED, the embedder must, before
 * re-entering KVM_RUN, store resume_rax into the exit's result field: the
 * suspended source plane's pending in-kernel completion consumes it as the
 * (VTL-shared) RAX when that plane next runs.  For COMPLETE, status goes in
 * the result field as usual (reps-completed already encoded).
 */
enum hv_vsm_action {
    HV_VSM_UNHANDLED,       /* not a VSM hypercall: embedder's problem */
    HV_VSM_COMPLETE,        /* result holds the final status */
    HV_VSM_SWITCHED,        /* plane run states changed; see resume_rax */
    HV_VSM_RAISE_UD,        /* fault the call: #UD at the unadvanced RIP */
};

struct hv_vsm_hcall_result {
    uint64_t result;        /* status | reps_completed << 32 */
    uint64_t resume_rax;    /* HV_VSM_SWITCHED only */
};

struct hv_vsm *hv_vsm_new(const struct hv_vsm_host_ops *ops, void *vm,
                          uint32_t nr_vps);
void hv_vsm_free(struct hv_vsm *vsm);
void hv_vsm_reset(struct hv_vsm *vsm);

/* Partition-privilege bits (CPUID 0x40000003 EBX) this core implements. */
uint32_t hv_vsm_cpuid_privileges(void);

void hv_vsm_set_active_vtl(struct hv_vsm *vsm, uint32_t vp,
                           uint8_t vtl);
enum hv_vsm_action hv_vsm_handle_hcall(struct hv_vsm *vsm, uint32_t vp,
                                       uint64_t control, uint64_t in_gpa,
                                       uint64_t out_gpa,
                                       struct hv_vsm_hcall_result *res);

/*
 * Handle a protection violation (KVM_EXIT_MEMORY_FAULT with R/W/X flags)
 * on a lower VTL: delivers the GPA intercept message and enters the next
 * higher enabled VTL.  Returns SWITCHED (res->resume_rax as for
 * hypercalls, except no hypercall completion is pending on the faulting
 * plane), RAISE_UD when the target VTL's SIMP is disabled (#UD was queued
 * into the faulting plane; resume it), or UNHANDLED when no higher VTL is
 * enabled.
 */
enum hv_vsm_action hv_vsm_deliver_reg_intercept(struct hv_vsm *vsm,
                                                uint32_t vp, uint32_t reg,
                                                uint64_t base, uint32_t limit,
                                                uint64_t rip, uint8_t insn_len,
                                                struct hv_vsm_hcall_result *res);
enum hv_vsm_action hv_vsm_vtl_interrupt_entry(struct hv_vsm *vsm,
                                              uint32_t vp, uint8_t target_vtl,
                                              struct hv_vsm_hcall_result *res);
/* Faulting-instruction details for the GPA intercept message. */
struct hv_vsm_fault_info {
    uint64_t gva;
    bool gva_valid;
    uint8_t insn_len;
    uint8_t insn_bytes[16];
};

enum hv_vsm_action hv_vsm_handle_protection_fault(struct hv_vsm *vsm,
                                                  uint64_t gpa, int access,
                                                  uint32_t vp,
                                                  const struct hv_vsm_fault_info *fi,
                                                  struct hv_vsm_hcall_result *res);

#endif /* HV_VSM_CORE_H */
