/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *  Tom Boning             tboning@mit.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
#define __STDC_FORMAT_MACROS

#include <sstream>

extern "C" {

#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>    
    
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "rr_log.h"
#include "panda_plugin.h"
#include "pandalog.h"        
    //#include "pandalog_print.h"
#include "panda_common.h"
#include "../syscalls2/gen_syscalls_ext_typedefs.h"
#include "../syscalls2/syscalls_common.h"
#include "panda_plugin_plugin.h"

#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);
              
}

// name of the process we want effects for
const char *effects_proc_name = NULL;

// current process
OsiProc *current_proc = NULL;

bool bbbexec_check_proc = false;

// asid changed -- start looking for valid proc info  
int asid_changed(CPUState *env, target_ulong old_asid, target_ulong new_asid) {
    bbbexec_check_proc = true;
    if (current_proc) {
        free_osiproc(current_proc);
        current_proc = NULL;
    }
    return 0;
}


bool proc_diff(OsiProc *p_curr, OsiProc *p_new) {
    if (p_curr == NULL) {
        return (p_new != NULL);
    }
    if (p_curr->offset != p_new->offset
        || p_curr->asid != p_new->asid
        || p_curr->pid != p_new->pid
        || p_curr->ppid != p_new->ppid)
        return true;
    return false;
}

int osi_foo(CPUState *env, TranslationBlock *tb) {
    // NB: we only really know the current process when we are in kernel                                                                                                                                                                                                                                                   
    bool proc_changed = false;
    if (bbbexec_check_proc && panda_in_kernel(env)) {
        OsiProc *p = get_current_process(env);
        //some sanity checks on what we think the current process is
        // this means we didnt find current task 
        if (p->offset == 0) return 0;
        // or the name 
        if (p->name == 0) return 0;
        // weird -- this is just not ok 
        if (((int) p->pid) == -1) return 0;
        uint32_t n = strnlen(p->name, 32);
        // yuck -- name is one char 
        if (n<2) return 0;
        uint32_t np = 0;
        for (uint32_t i=0; i<n; i++) {
            np += (isprint(p->name[i]) != 0);
        }
        // yuck -- name doesnt consist of solely printable characters
        if (np != n) return 0;
        // we have a valid process
        proc_changed = proc_diff(current_proc, p);
        if (proc_changed) {
            if (current_proc != NULL) {
                free_osiproc(current_proc);
                current_proc = NULL;
            }
            current_proc = copy_osiproc_g(p, current_proc);
        }
        free_osiproc(p);
        // turn this off until next asid change
        bbbexec_check_proc = false;
    }
    if (current_proc != NULL && proc_changed) {
        // if we get here, we have a valid proc in current_proc 
        // that is new.  That is, we believe process has changed 
        OsiModules *libs = get_libraries(env, current_proc);
        if (libs) {
            free_osimodules(libs);
        }
    }

    return 0;
}





void all_sys_enter(CPUState* env, target_ulong pc, target_ulong syscall_number) {
    // we need to know what process we are 'in'...
    printf ("all_sys_enter: ");
    if (current_proc) {
        printf ("proc_known ");
        if (0 != strstr(current_proc->name, effects_proc_name)) {
            // current proc is the one we care about
            printf ("effects_proc [%s]: ord=%d ", effects_proc_name, syscall_number);
        }
        else {
            printf ("not_effects_proc ");
        }
    }
    else {
        printf ("proc_not_known ");
    }
    printf ("\n");

    /*
    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
    ple.has_nt_any_syscall = 1;
    ple.nt_any_syscall = syscall_number;
    pandalog_write_entry(&ple);
    */
}

bool init_plugin(void *self) {
    printf("Initializing plugin effects\n");
#ifdef TARGET_I386
    panda_arg_list *args;
    args = panda_get_args("effects");
    // name of process for which we want effects
    effects_proc_name = panda_parse_string(args, "process", "ALL");
    
    //    assert (pandalog);
    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();


    // all this stuff is about figuring out the current process
    // in linux accurately, and the current set of libs in memory
    panda_cb pcb;
    pcb.after_PGD_write = asid_changed;
    panda_register_callback(self, PANDA_CB_VMI_PGD_CHANGED, pcb);
    pcb.before_block_exec = osi_foo;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    panda_require("osi");
    assert(init_osi_api());

    /*
    pcb.virt_mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);
    pcb.virt_mem_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_READ, pcb);
    */

    panda_require("syscalls2");   
    PPP_REG_CB("syscalls2", on_all_sys_enter, all_sys_enter);
    printf("finished adding win7proc syscall hooks\n");
    return true;
#else
    fprintf(stderr, "Plugin is not supported on this platform.\n");
    return false;
#endif
}

void uninit_plugin(void *self) {
    printf("Unloading effects\n");
}
