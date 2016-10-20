#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#define RR_LOG_STANDALONE
#include "cpu.h"
#include "rr_log.h"

#define BUFFER_DUMP_LEN 60

/******************************************************************************************/
/* GLOBALS */
/******************************************************************************************/
//mz record/replay mode
volatile RR_mode rr_mode = RR_REPLAY;

//mz program execution state

//mz 11.06.2009 Flags to manage nested recording
volatile sig_atomic_t rr_record_in_progress = 0;
volatile sig_atomic_t rr_skipped_callsite_location = 0;

volatile sig_atomic_t rr_use_live_exit_request = 0;

//mz the log of non-deterministic events
RR_log *rr_nondet_log = NULL;

static inline uint8_t log_is_empty(void) {
    if ((rr_nondet_log->type == REPLAY) &&
        (rr_nondet_log->size - ftell(rr_nondet_log->fp) == 0)) {
        return 1;
    }
    else {
        return 0;
    }
}

RR_debug_level_type rr_debug_level = RR_DEBUG_WHISPER;

//mz Flags set by monitor to indicate requested record/replay action
volatile sig_atomic_t rr_replay_requested = 0;
volatile sig_atomic_t rr_record_requested = 0;
volatile sig_atomic_t rr_end_record_requested = 0;
volatile sig_atomic_t rr_end_replay_requested = 0;
char * rr_requested_name = NULL;

// write this program point to this file 
static void rr_spit_prog_point_fp(FILE *fp, RR_prog_point pp) {
  fprintf(fp, "{instr=%010llu, pc=0x%016llx, sec=0x%016llx} ", 
      (unsigned long long)pp.guest_instr_count,
	  (unsigned long long)pp.pc,
	  (unsigned long long)pp.secondary);
}

void rr_spit_prog_point(RR_prog_point pp) {
  rr_spit_prog_point_fp(stdout,pp);
}

void rr_spit_buffer(uint8_t *buf, uint64_t len);
void rr_spit_buffer(uint8_t *buf, uint64_t len) {

    printf("\tBuffer:");
    int i;
    for (i = 0; i < len && i < BUFFER_DUMP_LEN; i++) {
        printf(" %02x", buf[i]);
    }
    if (len > BUFFER_DUMP_LEN) {
        printf(" ... \n");
    } else {
        printf("\n");
    }

}

static void rr_spit_log_entry(RR_log_entry item) {
    rr_spit_prog_point(item.header.prog_point);
    switch (item.header.kind) {
        case RR_INPUT_1:
            printf("RR_INPUT_1 0x%02x from %s\n", item.variant.input_1, get_callsite_string(item.header.callsite_loc));
            break;
        case RR_INPUT_2:
            printf("RR_INPUT_2 0x%04x from %s\n", item.variant.input_2, get_callsite_string(item.header.callsite_loc));
            break;
        case RR_INPUT_4:
            printf("RR_INPUT_4 0x%08x from %s\n", item.variant.input_4, get_callsite_string(item.header.callsite_loc));
            break;
        case RR_INPUT_8:
            printf("RR_INPUT_8 0x%016lx from %s\n", item.variant.input_8, get_callsite_string(item.header.callsite_loc));
            break;
        case RR_INTERRUPT_REQUEST:
            printf("RR_INTERRUPT_REQUEST %d from %s\n", item.variant.interrupt_request, get_callsite_string(item.header.callsite_loc));
            break;
        case RR_EXIT_REQUEST:
            printf("RR_EXIT_REQUEST %d from %s\n", item.variant.exit_request, get_callsite_string(item.header.callsite_loc));
            break;
        case RR_SKIPPED_CALL:
            {
                RR_skipped_call_args *args = &item.variant.call_args;
                int callbytes = -1;
                switch (item.variant.call_args.kind) {
                    case RR_CALL_CPU_MEM_RW:
                        printf("RR_SKIPPED_CALL %s (addr: 0x%lx, len: %d) from %s\n",
                               get_skipped_call_kind_string(item.variant.call_args.kind),
                               args->variant.cpu_mem_rw_args.addr,
                               args->variant.cpu_mem_rw_args.len,
                               get_callsite_string(item.header.callsite_loc));
                        rr_spit_buffer(args->variant.cpu_mem_rw_args.buf, args->variant.cpu_mem_rw_args.len);
                        callbytes = sizeof(args->variant.cpu_mem_rw_args) + args->variant.cpu_mem_rw_args.len;
                        break;
                    case RR_CALL_CPU_REG_MEM_REGION:
                        printf("RR_SKIPPED_CALL %s (start: 0x%lx, size: 0x%lx, phys_off: 0x%lx) from %s\n",
                               get_skipped_call_kind_string(item.variant.call_args.kind),
                               args->variant.cpu_mem_reg_region_args.start_addr,
                               args->variant.cpu_mem_reg_region_args.size,
                               args->variant.cpu_mem_reg_region_args.phys_offset,
                               get_callsite_string(item.header.callsite_loc));
                        callbytes = sizeof(args->variant.cpu_mem_reg_region_args);
                        break;
                    case RR_CALL_CPU_MEM_UNMAP:
                        printf("RR_SKIPPED_CALL %s (addr: 0x%lx, len: %ld) from %s\n",
                               get_skipped_call_kind_string(item.variant.call_args.kind),
                               args->variant.cpu_mem_unmap.addr,
                               args->variant.cpu_mem_unmap.len,
                               get_callsite_string(item.header.callsite_loc));
                        rr_spit_buffer(args->variant.cpu_mem_unmap.buf, args->variant.cpu_mem_unmap.len);
                        callbytes = sizeof(args->variant.cpu_mem_unmap) + args->variant.cpu_mem_unmap.len;
                        break;
                    case RR_CALL_HD_TRANSFER:
                        printf("RR_SKIPPED_CALL %s (%s, src: 0x%lx, dst: 0x%lx, len: %d) from %s\n",
                               get_skipped_call_kind_string(item.variant.call_args.kind),
                               hd_transfer_str[args->variant.hd_transfer_args.type],
                               args->variant.hd_transfer_args.src_addr,
                               args->variant.hd_transfer_args.dest_addr,
                               args->variant.hd_transfer_args.num_bytes,
                               get_callsite_string(item.header.callsite_loc));
                        callbytes = sizeof(args->variant.hd_transfer_args);
                        break;
                    case RR_CALL_NET_TRANSFER:
                        printf("RR_SKIPPED_CALL %s (%s, src: 0x%lx, dst: 0x%lx, len: %d) from %s\n",
                               get_skipped_call_kind_string(item.variant.call_args.kind),
                               net_transfer_str[args->variant.net_transfer_args.type],
                               args->variant.net_transfer_args.src_addr,
                               args->variant.net_transfer_args.dest_addr,
                               args->variant.net_transfer_args.num_bytes,
                               get_callsite_string(item.header.callsite_loc));
                        callbytes = sizeof(args->variant.net_transfer_args);
                        break;
                    case RR_CALL_HANDLE_PACKET:
                        printf("RR_SKIPPED_CALL %s (dir: %d, size: %d) from %s\n",
                               get_skipped_call_kind_string(item.variant.call_args.kind),
                               args->variant.handle_packet_args.direction,
                               args->variant.handle_packet_args.size,
                               get_callsite_string(item.header.callsite_loc));
                        rr_spit_buffer(args->variant.handle_packet_args.buf, args->variant.handle_packet_args.size);
                        callbytes = sizeof(args->variant.handle_packet_args) + args->variant.handle_packet_args.size;
                        break;
                    default:
                        printf("RR_SKIPPED_CALL %s from %s\n",
                               get_skipped_call_kind_string(item.variant.call_args.kind),
                               get_callsite_string(item.header.callsite_loc));
                        break;
                }
                /*if (callbytes != -1) {
                  printf(" %d bytes\n", callbytes);
                } else {
                  printf("\n");
                }*/
                break;
            }
        case RR_LAST:
            printf("RR_LAST\n");
            break;
        case RR_DEBUG:
            printf("RR_DEBUG\n");
            break;
        default:
            printf("UNKNOWN RR log kind %d\n", item.header.kind);
            break;
    }
}

//mz allocate a new entry (not filled yet)
static inline RR_log_entry *alloc_new_entry(void) 
{
    static RR_log_entry *new_entry = NULL;
    if(!new_entry) new_entry = g_new(RR_log_entry, 1);
    memset(new_entry, 0, sizeof(RR_log_entry));
    return new_entry;
}

static inline void free_entry_params(RR_log_entry *entry) 
{
    //mz cleanup associated resources
    switch (entry->header.kind) {
        case RR_SKIPPED_CALL:
            switch (entry->variant.call_args.kind) {
                case RR_CALL_CPU_MEM_RW:
                    g_free(entry->variant.call_args.variant.cpu_mem_rw_args.buf);
                    entry->variant.call_args.variant.cpu_mem_rw_args.buf = NULL;
                    break;
                case RR_CALL_CPU_MEM_UNMAP:
                    g_free(entry->variant.call_args.variant.cpu_mem_unmap.buf);
                    entry->variant.call_args.variant.cpu_mem_unmap.buf = NULL;
                    break;
                case RR_CALL_HANDLE_PACKET:
                    g_free(entry->variant.call_args.variant.handle_packet_args.buf);
                    entry->variant.call_args.variant.handle_packet_args.buf = NULL;
            }
            break;
        case RR_INPUT_1:
        case RR_INPUT_2:
        case RR_INPUT_4:
        case RR_INPUT_8:
        case RR_INTERRUPT_REQUEST:
        default:
             break;
    }
}

//mz fill an entry
static RR_log_entry *rr_read_item(void) {
    RR_log_entry *item = alloc_new_entry();

    //mz read header
    assert (rr_in_replay());
    assert ( ! log_is_empty());
    assert (rr_nondet_log->fp != NULL);

    //mz XXX we assume that the log is not trucated - should probably fix this.
    if (fread(&(item->header.prog_point), sizeof(RR_prog_point), 1, rr_nondet_log->fp) != 1) {
        //mz an error occurred
        if (feof(rr_nondet_log->fp)) {
            // replay is done - we've reached the end of file
            //mz we should never get here!
            assert(0);
        } 
        else {
            //mz some other kind of error
            //mz XXX something more graceful, perhaps?
            assert(0);
        }
    }
    //mz this is more compact, as it doesn't include extra padding.
    assert(fread(&(item->header.kind), sizeof(item->header.kind), 1, rr_nondet_log->fp) == 1);
    assert(fread(&(item->header.callsite_loc), sizeof(item->header.callsite_loc), 1, rr_nondet_log->fp) == 1);

    //mz read the rest of the item
    switch (item->header.kind) {
        case RR_INPUT_1:
            assert(fread(&(item->variant.input_1), sizeof(item->variant.input_1), 1, rr_nondet_log->fp) == 1);
            break;
        case RR_INPUT_2:
            assert(fread(&(item->variant.input_2), sizeof(item->variant.input_2), 1, rr_nondet_log->fp) == 1);
            break;
        case RR_INPUT_4:
            assert(fread(&(item->variant.input_4), sizeof(item->variant.input_4), 1, rr_nondet_log->fp) == 1);
            break;
        case RR_INPUT_8:
            assert(fread(&(item->variant.input_8), sizeof(item->variant.input_8), 1, rr_nondet_log->fp) == 1);
            break;
        case RR_INTERRUPT_REQUEST:
            assert(fread(&(item->variant.interrupt_request), sizeof(item->variant.interrupt_request), 1, rr_nondet_log->fp) == 1);
            break;
        case RR_EXIT_REQUEST:
            assert(fread(&(item->variant.exit_request), sizeof(item->variant.exit_request), 1, rr_nondet_log->fp) == 1);
            break;
        case RR_SKIPPED_CALL:
            {
                RR_skipped_call_args *args = &item->variant.call_args;
                //mz read kind first!
                assert(fread(&(args->kind), sizeof(args->kind), 1, rr_nondet_log->fp) == 1);
                switch(args->kind) {
                    case RR_CALL_CPU_MEM_RW:
                        assert(fread(&(args->variant.cpu_mem_rw_args), sizeof(args->variant.cpu_mem_rw_args), 1, rr_nondet_log->fp) == 1);
                        //mz buffer length in args->variant.cpu_mem_rw_args.len
                        //mz always allocate a new one. we free it when the item is added to the recycle list
                        args->variant.cpu_mem_rw_args.buf = g_malloc(args->variant.cpu_mem_rw_args.len);
                        //mz read the buffer
                        assert(fread(args->variant.cpu_mem_rw_args.buf, 1, args->variant.cpu_mem_rw_args.len, rr_nondet_log->fp) > 0);
                        //fseek(rr_nondet_log->fp, args->variant.cpu_mem_rw_args.len, SEEK_CUR);
                        break;
                    case RR_CALL_CPU_MEM_UNMAP:
                        assert(fread(&(args->variant.cpu_mem_unmap), sizeof(args->variant.cpu_mem_unmap), 1, rr_nondet_log->fp) == 1);
                        //mz buffer length in args->variant.cpu_mem_unmap.len
                        //mz always allocate a new one. we free it when the item is added to the recycle list
                        args->variant.cpu_mem_unmap.buf = g_malloc(args->variant.cpu_mem_unmap.len);
                        //mz read the buffer
                        assert(fread(args->variant.cpu_mem_unmap.buf, 1, args->variant.cpu_mem_unmap.len, rr_nondet_log->fp) > 0);
                        //fseek(rr_nondet_log->fp, args->variant.cpu_mem_unmap.len, SEEK_CUR);
                        break;
                    case RR_CALL_CPU_REG_MEM_REGION:
                        assert(fread(&(args->variant.cpu_mem_reg_region_args), 
                              sizeof(args->variant.cpu_mem_reg_region_args), 1, rr_nondet_log->fp) == 1);
                        break;
                    case RR_CALL_HD_TRANSFER:
                        assert(fread(&(args->variant.hd_transfer_args),
                              sizeof(args->variant.hd_transfer_args), 1, rr_nondet_log->fp) == 1);
                        break;
                    case RR_CALL_HANDLE_PACKET:
                        assert(fread(&(args->variant.handle_packet_args),
                              sizeof(args->variant.handle_packet_args), 1, rr_nondet_log->fp) == 1);
                        args->variant.handle_packet_args.buf = g_malloc(args->variant.handle_packet_args.size);
                        assert(fread(args->variant.handle_packet_args.buf, 1, args->variant.handle_packet_args.size, rr_nondet_log->fp) > 0);
                        //fseek(rr_nondet_log->fp,
                        //    args->variant.handle_packet_args.size, SEEK_CUR);
                        break;
                    case RR_CALL_NET_TRANSFER:
                        assert(fread(&(args->variant.net_transfer_args),
                              sizeof(args->variant.net_transfer_args), 1, rr_nondet_log->fp) == 1);
                        break;
                    default:
                        //mz unimplemented
                        assert(0);
                }
            }
            break;
        case RR_LAST:
        case RR_DEBUG:
            //mz nothing to read
            break;
        default:
            //mz unimplemented
            assert(0);
    }
    rr_nondet_log->item_number++;

    return item;
}

// create replay log
void rr_create_replay_log (const char *filename) {
  struct stat statbuf = {0};
  // create log
  rr_nondet_log = (RR_log *) g_malloc (sizeof (RR_log));
  assert (rr_nondet_log != NULL);
  memset(rr_nondet_log, 0, sizeof(RR_log));

  rr_nondet_log->type = REPLAY;
  rr_nondet_log->name = g_strdup(filename);
  rr_nondet_log->fp = fopen(rr_nondet_log->name, "r");
  assert(rr_nondet_log->fp != NULL);

  //mz fill in log size
  stat(rr_nondet_log->name, &statbuf);
  rr_nondet_log->size = statbuf.st_size;
  if (rr_debug_whisper()) {
    fprintf (stdout, "opened %s for read.  len=%llu bytes.\n",
	     rr_nondet_log->name, rr_nondet_log->size);
  }
  //mz read the last program point from the log header.
  assert(fread(&(rr_nondet_log->last_prog_point), sizeof(RR_prog_point), 1, rr_nondet_log->fp) == 1);
}

int main(int argc, char **argv) {
    rr_create_replay_log(argv[1]);
    printf("RR Log with %llu instructions\n", (unsigned long long) rr_nondet_log->last_prog_point.guest_instr_count);
    RR_log_entry *log_entry = NULL;
    while(!log_is_empty()) {
        log_entry = rr_read_item();
        rr_spit_log_entry(*log_entry);
    }
    if (log_entry) g_free(log_entry);
    return 0;
}
