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

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "exec/target_page.h"
#include "hyperv.h"
#include "hw/hyperv/hyperv.h"
#include "hyperv-proto.h"

int hyperv_x86_synic_add(X86CPU *cpu)
{
    hyperv_synic_add(CPU(cpu));
    return 0;
}

int hyperv_enable_synic(X86CPU *cpu)
{
    int ret = 0;
    if (!hyperv_is_synic_present(CPU(cpu))) {
        ret = hyperv_x86_synic_add(cpu);
    }
    return ret;
}

/*
 * All devices possibly using SynIC have to be reset before calling this to let
 * them remove their SINT routes first.
 */
void hyperv_x86_synic_reset(X86CPU *cpu)
{
    hyperv_synic_reset(CPU(cpu));
}

void hyperv_x86_synic_update(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    bool enable = env->msr_hv_synic_control & HV_SYNIC_ENABLE;
    hwaddr msg_page_addr = (env->msr_hv_synic_msg_page & HV_SIMP_ENABLE) ?
        (env->msr_hv_synic_msg_page & TARGET_PAGE_MASK) : 0;
    hwaddr event_page_addr = (env->msr_hv_synic_evt_page & HV_SIEFP_ENABLE) ?
        (env->msr_hv_synic_evt_page & TARGET_PAGE_MASK) : 0;
    hyperv_synic_update(CPU(cpu), enable, msg_page_addr, event_page_addr);
}

static void async_synic_update(CPUState *cs, run_on_cpu_data data)
{
    bql_lock();
    hyperv_x86_synic_update(X86_CPU(cs));
    bql_unlock();
}

int kvm_hv_handle_exit(X86CPU *cpu, struct kvm_hyperv_exit *exit)
{
    CPUX86State *env = &cpu->env;

    switch (exit->type) {
    case KVM_EXIT_HYPERV_SYNIC:
        if (!hyperv_feat_enabled(cpu, HYPERV_FEAT_SYNIC)) {
            return -1;
        }

        /*
         * With VSM, each plane's SIMP is a per-plane overlay; the SynIC
         * device's global MemoryRegion overlay would leak one plane's
         * message page into every other plane's view of that GPA.
         */
        if (hyperv_feat_enabled(cpu, HYPERV_FEAT_VSM)) {
            if (exit->plane != 0) {
                if (exit->u.synic.msr == HV_X64_MSR_SIMP &&
                    kvm_hv_vsm_handle_synic_exit(cpu, exit->plane,
                                                 exit->u.synic.msg_page) < 0) {
                    return -1;
                }
                return EXCP_INTERRUPT;
            }

            switch (exit->u.synic.msr) {
            case HV_X64_MSR_SCONTROL:
                env->msr_hv_synic_control = exit->u.synic.control;
                break;
            case HV_X64_MSR_SIMP:
                env->msr_hv_synic_msg_page = exit->u.synic.msg_page;
                break;
            case HV_X64_MSR_SIEFP:
                env->msr_hv_synic_evt_page = exit->u.synic.evt_page;
                break;
            default:
                return -1;
            }

            /*
             * Keep the SynIC device's state (so in-QEMU message and
             * event delivery works) but do not map its pages globally:
             * back this plane's view with the device buffers instead.
             */
            {
                void *msg_ptr = NULL, *evt_ptr = NULL;
                uint64_t simp = env->msr_hv_synic_msg_page;
                uint64_t siefp = env->msr_hv_synic_evt_page;

                hyperv_synic_update_nomap(CPU(cpu),
                        env->msr_hv_synic_control & HV_SYNIC_ENABLE,
                        (simp & HV_SIMP_ENABLE) ?
                            (simp & TARGET_PAGE_MASK) : 0,
                        (siefp & HV_SIEFP_ENABLE) ?
                            (siefp & TARGET_PAGE_MASK) : 0,
                        &msg_ptr, &evt_ptr);
                if (kvm_hv_vsm_set_synic_overlay(cpu, 0, 0, simp,
                                                 msg_ptr) < 0 ||
                    kvm_hv_vsm_set_synic_overlay(cpu, 0, 1, siefp,
                                                 evt_ptr) < 0) {
                    return -1;
                }
            }
            return EXCP_INTERRUPT;
        }

        switch (exit->u.synic.msr) {
        case HV_X64_MSR_SCONTROL:
            env->msr_hv_synic_control = exit->u.synic.control;
            break;
        case HV_X64_MSR_SIMP:
            env->msr_hv_synic_msg_page = exit->u.synic.msg_page;
            break;
        case HV_X64_MSR_SIEFP:
            env->msr_hv_synic_evt_page = exit->u.synic.evt_page;
            break;
        default:
            return -1;
        }

        /*
         * this will run in this cpu thread before it returns to KVM, but in a
         * safe environment (i.e. when all cpus are quiescent) -- this is
         * necessary because memory hierarchy is being changed
         */
        async_safe_run_on_cpu(CPU(cpu), async_synic_update, RUN_ON_CPU_NULL);

        return EXCP_INTERRUPT;
    case KVM_EXIT_HYPERV_HCALL: {
        uint16_t code = exit->u.hcall.input & 0xffff;
        bool fast = exit->u.hcall.input & HV_HYPERCALL_FAST;
        uint64_t in_param = exit->u.hcall.params[0];
        uint64_t out_param = exit->u.hcall.params[1];

        switch (code) {
        case HV_POST_MESSAGE:
            exit->u.hcall.result = hyperv_hcall_post_message(in_param, fast);
            break;
        case HV_SIGNAL_EVENT:
            exit->u.hcall.result = hyperv_hcall_signal_event(in_param, fast);
            break;
        case HV_POST_DEBUG_DATA:
            exit->u.hcall.result =
                hyperv_hcall_post_dbg_data(in_param, out_param, fast);
            break;
        case HV_RETRIEVE_DEBUG_DATA:
            exit->u.hcall.result =
                hyperv_hcall_retreive_dbg_data(in_param, out_param, fast);
            break;
        case HV_RESET_DEBUG_SESSION:
            exit->u.hcall.result =
                hyperv_hcall_reset_dbg_session(out_param);
            break;
        default:
            if (hyperv_feat_enabled(cpu, HYPERV_FEAT_VSM) &&
                kvm_hv_vsm_handle_hcall(cpu, exit)) {
                break;
            }
            exit->u.hcall.result = HV_STATUS_INVALID_HYPERCALL_CODE;
        }
        return 0;
    }

    case KVM_EXIT_HYPERV_VTL_INTERRUPT:
        if (!hyperv_feat_enabled(cpu, HYPERV_FEAT_VSM)) {
            return -1;
        }
        return kvm_hv_vsm_handle_vtl_interrupt(cpu, exit->plane);

    case KVM_EXIT_HYPERV_REG_INTERCEPT:
        if (!hyperv_feat_enabled(cpu, HYPERV_FEAT_VSM)) {
            return -1;
        }
        return kvm_hv_vsm_handle_reg_intercept(cpu, exit);

    case KVM_EXIT_HYPERV_SYNDBG:
        if (!hyperv_feat_enabled(cpu, HYPERV_FEAT_SYNDBG)) {
            return -1;
        }

        switch (exit->u.syndbg.msr) {
        case HV_X64_MSR_SYNDBG_CONTROL: {
            uint64_t control = exit->u.syndbg.control;
            env->msr_hv_syndbg_control = control;
            env->msr_hv_syndbg_send_page = exit->u.syndbg.send_page;
            env->msr_hv_syndbg_recv_page = exit->u.syndbg.recv_page;
            exit->u.syndbg.status = HV_STATUS_SUCCESS;
            if (control & HV_SYNDBG_CONTROL_SEND) {
                exit->u.syndbg.status =
                    hyperv_syndbg_send(env->msr_hv_syndbg_send_page,
                            HV_SYNDBG_CONTROL_SEND_SIZE(control));
            } else if (control & HV_SYNDBG_CONTROL_RECV) {
                exit->u.syndbg.status =
                    hyperv_syndbg_recv(env->msr_hv_syndbg_recv_page,
                            TARGET_PAGE_SIZE);
            }
            break;
        }
        case HV_X64_MSR_SYNDBG_PENDING_BUFFER:
            env->msr_hv_syndbg_pending_page = exit->u.syndbg.pending_page;
            hyperv_syndbg_set_pending_page(env->msr_hv_syndbg_pending_page);
            break;
        default:
            return -1;
        }

        return 0;
    default:
        return -1;
    }
}

void hyperv_x86_set_vmbus_recommended_features_enabled(void)
{
    hyperv_set_vmbus_recommended_features_enabled();
}
