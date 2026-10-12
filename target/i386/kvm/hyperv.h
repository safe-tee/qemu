/*
 * QEMU KVM Hyper-V support
 *
 * Copyright (C) 2015 Andrey Smetanin <asmetanin@virtuozzo.com>
 *
 * Authors:
 *  Andrey Smetanin <asmetanin@virtuozzo.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef TARGET_I386_HYPERV_H
#define TARGET_I386_HYPERV_H

#include "cpu.h"
#include "system/kvm.h"
#include "hw/hyperv/hyperv.h"

#ifdef CONFIG_KVM
int kvm_hv_handle_exit(X86CPU *cpu, struct kvm_hyperv_exit *exit);

/* hv-vsm-qemu.c */
struct KVMState;
int kvm_hv_vsm_vm_init(struct KVMState *s);
bool kvm_hv_vsm_handle_hcall(X86CPU *cpu, struct kvm_hyperv_exit *exit);
int kvm_hv_vsm_handle_memory_fault(X86CPU *cpu, struct kvm_run *run);
int kvm_hv_vsm_handle_vtl_interrupt(X86CPU *cpu, uint8_t target_vtl);
int kvm_hv_vsm_handle_reg_intercept(X86CPU *cpu, struct kvm_hyperv_exit *exit);
int kvm_hv_vsm_handle_synic_exit(X86CPU *cpu, uint32_t plane,
                                 uint64_t msg_page);
int kvm_hv_vsm_set_synic_overlay(X86CPU *cpu, uint32_t plane, int kind,
                                 uint64_t page_reg, void *ext_buf);
void kvm_hv_vsm_vcpu_init(X86CPU *cpu);
int kvm_hv_vsm_vcpu_set_cpuid(X86CPU *cpu, struct kvm_cpuid2 *cpuid);
bool kvm_hv_vsm_trace_step(X86CPU *cpu, uint64_t pc);
#endif

int hyperv_x86_synic_add(X86CPU *cpu);
int hyperv_enable_synic(X86CPU *cpu);
void hyperv_x86_synic_reset(X86CPU *cpu);
void hyperv_x86_synic_update(X86CPU *cpu);

void hyperv_x86_set_vmbus_recommended_features_enabled(void);

#endif
