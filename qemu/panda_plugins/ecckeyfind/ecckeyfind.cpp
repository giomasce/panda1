/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *  Giovanni Mascellani    g.mascellani@gmail.com
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

extern "C" {

#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"
#include "disas.h"

#include "panda_plugin.h"

}

#include "ecckeyfind.h"
#include "ecc.h"

#include <unordered_set>
#include <vector>
#include <set>
#include <map>

#include "../common/prog_point.h"
#include "pandalog.h"
#include "../callstack_instr/callstack_instr_ext.h"
    
// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int before_block_translate_cb(CPUState *env, target_ulong pc);
int after_block_translate_cb(CPUState *env, TranslationBlock *tb);

}

// Utility functions
#define CHECK(var,label) \
    if (!var) { fprintf(stderr, label ": failed. Exiting.\n"); return false; }
#define MAX_KEY_SIZE 64

Curve curve;
Point gpoint;
Point pub;
CryptoCurve crypto_curve;

bool have_candidates = true;
std::unordered_set <prog_point, hash_prog_point > candidates;

// Optimization
std::unordered_set <target_ulong> cr3s;
std::vector <target_ulong> eips;

// Ringbuf-like structure
struct key_buf {
    uint8_t key[2*MAX_KEY_SIZE];
    unsigned int start;
    bool filled;
};

std::set<prog_point> matches;
std::map<prog_point,key_buf> key_tracker;

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    prog_point p = {};
    get_prog_point(env, &p);
    const size_t &key_size = crypto_curve.size_bytes;

    // Only use candidates found in config (pre-filtered for key-ness)
    if (have_candidates && candidates.find(p) == candidates.end()) {
        //printf("Skipping " TARGET_FMT_lx "\n", p.pc);
        return 1;
    }

    for (unsigned int i = 0; i < size; i++) {
        uint8_t val = ((uint8_t *)buf)[i];
        key_buf *k = &key_tracker[p];
        k->key[k->start+key_size] = val;
        k->key[k->start++] = val;
        if (k->start == key_size) {
            k->start = 0;
            k->filled = true;
        }
        if (likely(k->filled)) {
          const unsigned char *attempt = &k->key[k->start];
          bool match = cryptocurve_check_private_key_str(&crypto_curve, (char*) attempt, &pub);

            if (unlikely(match)) {
                fprintf(stderr, "ECC match found at " TARGET_FMT_lx " " TARGET_FMT_lx " " TARGET_FMT_lx "\n",
                    p.caller, p.pc, p.cr3);
                fprintf(stderr, "Key: ");
                for(unsigned int j = 0; j < key_size; j++)
                    fprintf(stderr, "%02x", attempt[j]);
                fprintf(stderr, "\n");
                matches.insert(p);
            }
        }
    }

    return 1;
}

#define ASSUMED_TB_SIZE 256

bool enabled_memcb = false;
int instrumented, total;
int before_block_translate_cb(CPUState *env, target_ulong pc) {
    // Don't bother with any of this if we don't have any canidates;
    // in this case precise pc and memcb will always be on.
    if (!have_candidates) return 1;
    
    target_ulong tb_cr3 = 0;
#if defined(TARGET_I386)
    if ((env->hflags & HF_CPL_MASK) != 0) // Lump all kernel-mode CR3s together
       tb_cr3 = env->cr[3];
#elif defined(TARGET_ARM)
    if ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_SVC) {
        if (pc & env->cp15.c2_mask)
            tb_cr3 = env->cp15.c2_base1 & 0xffffc000;
        else
            tb_cr3 = env->cp15.c2_base0 & env->cp15.c2_base_mask;
    }
#endif

    if (cr3s.find(tb_cr3) == cr3s.end()) return 1;

    // Slightly tricky: we ask for the lower bound of the TB start and
    // the lower bound of the (assumed) TB end in our sorted list of tap
    // EIPs. If that interval is nonempty then at least one of our taps
    // is in the upcoming TB, so we need to instrument it.
    std::vector<target_ulong>::iterator beg, end, it;
    beg = std::lower_bound(eips.begin(), eips.end(), pc);
    end = std::lower_bound(eips.begin(), eips.end(), pc+ASSUMED_TB_SIZE);

    if (std::distance(beg, end) != 0) {
        panda_enable_memcb();
        panda_enable_precise_pc();
        enabled_memcb = true;
        //printf("Enabling callbacks for TB " TARGET_FMT_lx " Interval:(%ld,%ld)\n", pc, beg-eips.begin(), end-eips.begin());
        //printf("Encompassed EIPs:");
        //for (it = beg; it != end; it++) {
        //    printf(" " TARGET_FMT_lx, *it);
        //}
        //printf("\n");
        instrumented++;
    }
    total++;

    return 1;
}

int after_block_translate_cb(CPUState *env, TranslationBlock *tb) {
    if (!have_candidates) return 1;

    if (enabled_memcb) {
        // Check our assumption
        if (tb->size > ASSUMED_TB_SIZE) {
            printf("WARN: TB " TARGET_FMT_lx " is larger than we thought (%d bytes)\n", tb->pc, tb->size);
        }
        panda_disable_memcb();
        panda_disable_precise_pc();
        enabled_memcb = false;
        //printf("Disabling callbacks for TB " TARGET_FMT_lx "\n", tb->pc);
    }
    return 1;
}

bool init_plugin(void *self) {
    // General PANDA stuff
    panda_cb pcb;

    printf("Initializing plugin ecckeyfind\n");

    if(!init_callstack_instr_api()) return false;

    // Read and parse list of candidate taps
    std::ifstream taps("keyfind_candidates.txt");
    if (!taps) {
        printf("Couldn't open keyfind_candidates.txt; no key tap candidates defined.\n");
        printf("We will proceed, but it may be SLOW.\n");
        have_candidates = false;
    }
    else {
        std::unordered_set <target_ulong> eipset;
        prog_point p = {};
        while (taps >> std::hex >> p.caller) {
            taps >> std::hex >> p.pc;
            taps >> std::hex >> p.cr3;

            eipset.insert(p.pc);
            cr3s.insert(p.cr3);

            //printf("Adding tap point (" TARGET_FMT_lx "," TARGET_FMT_lx "," TARGET_FMT_lx ")\n",
            //       p.caller, p.pc, p.cr3);
            candidates.insert(p);
        }
        printf("keyfind: Will check for keys on %ld taps.\n", candidates.size());
        taps.close();

        // Sort EIPs
        for(auto ii : eipset) {
            eips.push_back(ii);
        }
        std::sort(eips.begin(), eips.end());
    }

    // Read and parse the configuration file
    std::ifstream config("ecckeyfind_config.txt");
    if (!config) {
        printf("Couldn't open ecckeyfind_config.txt. Aborting.\n");
        return false;
    }

    bool found_p = false;
    bool found_a = false;
    bool found_b = false;
    bool found_g1 = false;
    bool found_g2 = false;
    bool found_pub1 = false;
    bool found_pub2 = false;

    std::string p, a, b, g1, g2, pub1, pub2;

    std::string line;
    while(std::getline(config, line)) {
        trim(line);

        // Skip comment lines
        if (line[0] == '#') continue;

        // Get Key: Value pairs
        std::istringstream iss(line);
        std::string key, value;
        std::getline(iss, key, ':');
        std::getline(iss, value, ':');
        trim(key); trim(value);

        if (key == "p") {
          p = value;
          found_p = true;
        } else if (key == "a") {
          a = value;
          found_a = true;
        } else if (key == "b") {
          b = value;
          found_b = true;
        } else if (key == "g1") {
          g1 = value;
          found_g1 = true;
        } else if (key == "g2") {
          g2 = value;
          found_g2 = true;
        } else if (key == "pub1") {
          pub1 = value;
          found_pub1 = true;
        } else if (key == "pub2") {
          pub2 = value;
          found_pub2 = true;
        }
    }

    if (!found_p) { fprintf(stderr, "Missing value for p\n"); return false; }
    if (!found_a) { fprintf(stderr, "Missing value for a\n"); return false; }
    if (!found_b) { fprintf(stderr, "Missing value for b\n"); return false; }
    if (!found_g1) { fprintf(stderr, "Missing value for g1\n"); return false; }
    if (!found_g2) { fprintf(stderr, "Missing value for g2\n"); return false; }
    if (!found_pub1) { fprintf(stderr, "Missing value for pub1\n"); return false; }
    if (!found_pub2) { fprintf(stderr, "Missing value for pub2\n"); return false; }

    curve_init(&curve);
    curve_set_str(&curve, p.c_str(), a.c_str(), b.c_str());
    point_init(&gpoint);
    point_set_str(&gpoint, g1.c_str(), g2.c_str());
    point_init(&pub);
    point_set_str(&pub, pub1.c_str(), pub2.c_str());
    cryptocurve_init(&crypto_curve);
    cryptocurve_set(&crypto_curve, &curve, &gpoint);

    if (crypto_curve.size_bytes > MAX_KEY_SIZE) {
      fprintf(stderr, "Key too big; try picking a larger MAX_KEY_SIZE\n");
      return false;
    }

    if (!have_candidates) {
        panda_enable_memcb();
        panda_enable_precise_pc();
        enabled_memcb = true;
    }

    // Enable our callbacks
    pcb.virt_mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);
    pcb.before_block_translate = before_block_translate_cb;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);
    pcb.after_block_translate = after_block_translate_cb;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);

    return true;
}

void uninit_plugin(void *self) {
    printf("%d / %d blocks instrumented.\n", instrumented, total);
    FILE *mem_report = fopen("key_matches.txt", "w");
    if(!mem_report) {
        printf("Couldn't write report:\n");
        perror("fopen");
        return;
    }
    std::set<prog_point>::iterator it;
    for(it = matches.begin(); it != matches.end(); it++) {
        // Print prog point
        fprintf(mem_report, TARGET_FMT_lx " " TARGET_FMT_lx " " TARGET_FMT_lx "\n",
            it->caller, it->pc, it->cr3);
        // Print strings that matched and how many times
    }
    fclose(mem_report);

    cryptocurve_clear(&crypto_curve);
    point_clear(&pub);
    point_clear(&gpoint);
    curve_clear(&curve);
}
