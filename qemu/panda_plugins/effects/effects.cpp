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

#include "sys_effects.h"

bool init_plugin(void *);
void uninit_plugin(void *);
              
}

#include "../stpi/stpi_types.h"
#include "../stpi/stpi_ext.h"
#include "../dwarfp/dwarfp_ext.h"


#include "../common/prog_point.h"
#include "../callstack_instr/callstack_instr_ext.h"

// name of the process we want effects for
const char *effects_proc_name = NULL;

// current process
OsiProc *current_proc = NULL;
OsiModule *current_lib = NULL;
OsiModules *current_libs = NULL;

bool bbbexec_check_proc = false;

// asid changed -- start looking for valid proc info  
int asid_changed(CPUState *env, target_ulong old_asid, target_ulong new_asid) {
    bbbexec_check_proc = true;
    if (current_proc) {
        free_osiproc(current_proc);
        current_proc = NULL;
        current_libs = NULL;
        current_lib = NULL;
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

bool proc_changed = false;

target_ulong last_user_pc = 0;

int osi_foo(CPUState *env, TranslationBlock *tb) {
    // NB: we only really know the current process when we are in kernel
    if (bbbexec_check_proc) {
        if (panda_in_kernel(env)) {
            printf ("in kernel\n");
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
                printf ("proc changed to [%s]\n", current_proc->name);
            }
            free_osiproc(p);
            // turn this off until next asid change
            bbbexec_check_proc = false;                
            if (current_proc != NULL && proc_changed) {
                // if we get here, we have a valid proc in current_proc 
                // that is new.  That is, we believe process has changed 
                if (current_libs) {
                    free_osimodules(current_libs);
                }
                current_libs = get_libraries(env, current_proc);
                if (current_libs) {
                    for (unsigned i=0; i<current_libs->num; i++) {
                        OsiModule *m = &(current_libs->module[i]);   
                        if (tb->pc >= m->base && tb->pc < (m->base + m->size)) {
                            current_lib = m;
                        }
                    }
                }
            }
        } // in kernel
    }
    if (!panda_in_kernel(env)) {
        if (0 != strstr(current_proc->name, effects_proc_name)) {             
            printf ("in user: current_proc->name = %s pc=0x" TARGET_FMT_lx "\n", current_proc->name, tb->pc);
            last_user_pc = tb->pc;
        }
    }
    return 0;
}


void all_sys_enter(CPUState* env, target_ulong pc, target_ulong syscall_number) {
    // we need to know what process we are 'in'...
    if (current_proc) {
        //        printf ("proc_known ");
        if (0 != strstr(current_proc->name, effects_proc_name)) {
            // current proc is the one we care about
            printf ("all_sys_enter: instr=%" PRId64 " pc=0x" TARGET_FMT_lx "\n" , rr_get_guest_instr_count(), pc);
            printf (": ord=%4d effect=[%s] \n", (int) syscall_number, sys_effect[syscall_number]);
            target_ulong callers[32];
            int n = get_callers(callers, 32, env);
            printf ("call stack is %d\n", n);
            printf ("current_proc=%s \n", current_proc->name);
            printf ("current_libs %d\n", current_libs->num);            
            if (current_libs) {
                for (int i=0; i<n; i++) {
                    target_ulong pc = callers[i];
                    for (unsigned j=0; j<current_libs->num; j++) {
                        OsiModule *m = &(current_libs->module[j]);
                        if (pc >= m->base && pc < (m->base + m->size)) {
                            printf ("MATCH i=%d pc=0x" TARGET_FMT_lx" [" TARGET_FMT_lx".." TARGET_FMT_lx"] name=%s lib=%s : ", 
                                    i, pc, m->base, m->base + m->size, m->name, m->file);
                            PC_Info info;
                            int rv = stpi_get_source_info(env, pc, &info);
                            if (rv == 0) printf ("CODE LOC: (%s, %s, %d)\n", info.filename, info.funname, info.line);
                            else printf ("CODE LOC: unknown\n");
                        }
                    }
                }
            }                
        }
    }
}


void rw_message(const char *msg, CPUState *env, target_ulong pc) {
    PC_Info info;
    int rv = stpi_get_source_info(env, pc, &info);
    if (rv == 0) printf ("RWV_EFFECT: %s : CODE_LOC (%s, %s, %d)\n", info.filename, info.funname, info.line);
    else printf ("CODE LOC: unknown\n");
}

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    rw_message("WRITE", env, pc);    
}

int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    rw_message("READ", env, pc);        
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

    panda_require("callstack_instr");
    if(!init_callstack_instr_api()) return false;

    panda_require("dwarfp");
    assert (init_dwarfp_api());

    panda_require("stpi");
    assert (init_stpi_api());

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
