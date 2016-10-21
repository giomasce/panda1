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

#include "aesfind.h"

#include <unordered_set>
#include <vector>
#include <set>
#include <map>
#include <deque>
#include <algorithm>

#include "../common/prog_point.h"
#include "pandalog.h"
#include "../callstack_instr/callstack_instr_ext.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int cb_read(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int cb_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

}

#define CACHE_LEN 8

std::map< target_ulong, std::deque< std::pair< uint8_t, prog_point > > > past_bytes;
std::map< prog_point, uint64_t > read_num;
std::map< prog_point, uint64_t > found_num;

int cb_read(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {

  prog_point pp = {};
  auto cbuf = (unsigned char*) buf;
  get_prog_point(env, &pp);
  auto &cur = past_bytes[pp.cr3];
  for (auto i = 0; i < size; i++) {
    if (cbuf[i] == 0 || cbuf[i] == 0xff || sbox[cbuf[i]] == 0 || sbox[cbuf[i]] == 0xff) {
      //continue;
    }
    cur.push_front(std::make_pair(cbuf[i], pp));
    read_num[pp]++;
    if (found_num.count(pp) == 0) {
      found_num[pp] = 0;
    }
  }
  if (cur.size() > CACHE_LEN) {
    cur.resize(CACHE_LEN);
  }

}

int cb_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {

  prog_point pp = {};
  auto cbuf = (unsigned char*) buf;
  get_prog_point(env, &pp);
  auto &cur = past_bytes[pp.cr3];
  for (auto i = 0; i < size; i++) {
    auto sboxed = inv_sbox[cbuf[i]];
    for (auto j = cur.rbegin(); j != cur.rend(); j++) {
      if (sboxed == j->first) {
        found_num[j->second]++;
        cur.erase((j+1).base());
        break;
      }
    }
  }

}

bool init_plugin(void *self) {

  // General PANDA stuff
  panda_cb pcb;

  printf("Initializing plugin aesfind\n");

  if(!init_callstack_instr_api()) return false;

  panda_enable_memcb();
  panda_enable_precise_pc();

  pcb.virt_mem_after_read = cb_read;
  panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);
  pcb.virt_mem_after_write = cb_write;
  panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);

  return true;

}

void uninit_plugin(void *self) {

  std::vector< std::tuple< double, uint64_t, prog_point > > results;
  auto i = read_num.begin();
  auto j = found_num.begin();
  while (i != read_num.end()) {
    assert(i->first == j->first);
    if (j->second > 64) {
      results.push_back(std::make_tuple(((double) j->second) / ((double) i->second), i->second, i->first));
    }
    i++;
    j++;
  }
  assert(j == found_num.end());
  sort(results.rbegin(), results.rend());
  //sort(results.begin(), results.end());
  i = read_num.begin();
  for (int k = 0; k < 100; k++) {
    auto &res = results[k];
    printf("%f %d %s\n", std::get<0>(res), std::get<1>(res), std::get<2>(res).to_string().c_str());
  }

}
