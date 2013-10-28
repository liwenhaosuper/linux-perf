/*
 * intel_pt.c: Intel Processor Trace support
 * Copyright (c) 2013-2014, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include "../perf.h"
#include "session.h"
#include "machine.h"
#include "tool.h"
#include "event.h"
#include "evlist.h"
#include "evsel.h"
#include "map.h"
#include "cpumap.h"
#include "color.h"
#include "util.h"
#include "thread.h"
#include "thread-stack.h"
#include "symbol.h"
#include "callchain.h"
#include "parse-options.h"
#include "parse-events.h"
#include "pmu.h"
#include "dso.h"
#include "debug.h"
#include "itrace.h"
#include "tsc.h"
#include "intel-pt.h"

#include "intel-pt-decoder/intel-pt-log.h"
#include "intel-pt-decoder/intel-pt-decoder.h"
#include "intel-pt-decoder/intel-pt-insn-decoder.h"
#include "intel-pt-decoder/intel-pt-pkt-decoder.h"

#define MAX_TIMESTAMP (~0ULL)

#define KiB(x) ((x) * 1024)
#define MiB(x) ((x) * 1024 * 1024)
#define KiB_MASK(x) (KiB(x) - 1)
#define MiB_MASK(x) (MiB(x) - 1)

#define INTEL_PT_DEFAULT_SAMPLE_SIZE	KiB(4)

#define INTEL_PT_MAX_SAMPLE_SIZE	KiB(60)

#define INTEL_PT_PSB_PERIOD_NEAR	256

struct intel_pt_snapshot_ref {
	void *ref_buf;
	size_t ref_offset;
	bool wrapped;
};

struct intel_pt_recording {
	struct itrace_record		itr;
	struct perf_pmu			*intel_pt_pmu;
	int				have_sched_switch;
	struct perf_evlist		*evlist;
	bool				snapshot_mode;
	bool				snapshot_init_done;
	size_t				snapshot_size;
	size_t				snapshot_ref_buf_size;
	int				snapshot_ref_cnt;
	struct intel_pt_snapshot_ref	*snapshot_refs;
};

struct intel_pt {
	struct itrace itrace;
	struct itrace_queues queues;
	struct itrace_heap heap;
	u32 itrace_type;
	struct perf_session *session;
	struct machine *machine;
	struct perf_evsel *switch_evsel;
	struct thread *unknown_thread;
	bool timeless_decoding;
	bool sampling_mode;
	bool snapshot_mode;
	bool per_cpu_mmaps;
	bool have_tsc;
	bool data_queued;
	bool est_tsc;
	bool sync_switch;
	bool est_tsc_orig;
	int have_sched_switch;
	u32 pmu_type;
	u64 kernel_start;
	u64 switch_ip;
	u64 ptss_ip;

	struct perf_tsc_conversion tc;
	bool cap_user_time_zero;

	struct itrace_synth_opts synth_opts;

	bool sample_instructions;
	u64 instructions_sample_type;
	u64 instructions_sample_period;
	u64 instructions_id;

	bool sample_branches;
	u32 branches_filter;
	u64 branches_sample_type;
	u64 branches_id;

	bool synth_needs_swap;

	u64 tsc_bit;
	u64 noretcomp_bit;
};

enum switch_state {
	INTEL_PT_SS_NOT_TRACING,
	INTEL_PT_SS_UNKNOWN,
	INTEL_PT_SS_TRACING,
	INTEL_PT_SS_EXPECTING_SWITCH_EVENT,
	INTEL_PT_SS_EXPECTING_SWITCH_IP,
};

struct intel_pt_queue {
	struct intel_pt *pt;
	unsigned int queue_nr;
	struct itrace_buffer *buffer;
	void *decoder;
	const struct intel_pt_state *state;
	struct ip_callchain *chain;
	union perf_event *event_buf;
	bool on_heap;
	bool stop;
	bool step_through_buffers;
	bool use_buffer_pid_tid;
	pid_t pid, tid;
	int cpu;
	int switch_state;
	pid_t next_tid;
	struct thread *thread;
	bool exclude_kernel;
	bool have_sample;
	u64 time;
	u64 timestamp;
	u32 flags;
	u16 insn_len;
};

static void intel_pt_dump(struct intel_pt *pt __maybe_unused,
			  unsigned char *buf, size_t len)
{
	struct intel_pt_pkt packet;
	size_t pos = 0;
	int ret, pkt_len, i;
	char desc[INTEL_PT_PKT_DESC_MAX];
	const char *color = PERF_COLOR_BLUE;

	color_fprintf(stdout, color,
		      ". ... Intel Processor Trace data: size %zu bytes\n",
		      len);

	while (len) {
		ret = intel_pt_get_packet(buf, len, &packet);
		if (ret > 0)
			pkt_len = ret;
		else
			pkt_len = 1;
		printf(".");
		color_fprintf(stdout, color, "  %08x: ", pos);
		for (i = 0; i < pkt_len; i++)
			color_fprintf(stdout, color, " %02x", buf[i]);
		for (; i < 16; i++)
			color_fprintf(stdout, color, "   ");
		if (ret > 0) {
			ret = intel_pt_pkt_desc(&packet, desc,
						INTEL_PT_PKT_DESC_MAX);
			if (ret > 0)
				color_fprintf(stdout, color, " %s\n", desc);
		} else {
			color_fprintf(stdout, color, " Bad packet!\n");
		}
		pos += pkt_len;
		buf += pkt_len;
		len -= pkt_len;
	}
}

static void intel_pt_dump_event(struct intel_pt *pt, unsigned char *buf,
				size_t len)
{
	printf(".\n");
	intel_pt_dump(pt, buf, len);
}

static void intel_pt_dump_sample(struct perf_session *session,
				 struct perf_sample *sample)
{
	struct intel_pt *pt = container_of(session->itrace, struct intel_pt,
					   itrace);

	intel_pt_dump(pt, sample->aux_sample.data,
		      sample->aux_sample.size);
	printf(".\n");
}

static int intel_pt_do_fix_overlap(struct intel_pt *pt, struct itrace_buffer *a,
				   struct itrace_buffer *b)
{
	void *start;

	start = intel_pt_find_overlap(a->data, a->size, b->data, b->size,
				      pt->have_tsc);
	if (!start)
		return -EINVAL;
	b->use_size = b->data + b->size - start;
	b->use_data = start;
	return 0;
}

static int intel_pt_fix_overlap(struct intel_pt *pt, unsigned int queue_nr)
{
	struct itrace_queue *queue = &pt->queues.queue_array[queue_nr];
	struct itrace_buffer *a, *b;

	b = list_entry(queue->head.prev, struct itrace_buffer, list);
	if (b->list.prev == &queue->head)
		return 0;
	a = list_entry(b->list.prev, struct itrace_buffer, list);
	return intel_pt_do_fix_overlap(pt, a, b);
}

static void intel_pt_use_buffer_pid_tid(struct intel_pt_queue *ptq,
					struct itrace_queue *queue,
					struct itrace_buffer *buffer)
{
	if (queue->cpu == -1 && buffer->cpu != -1)
		ptq->cpu = buffer->cpu;

	ptq->pid = buffer->pid;
	ptq->tid = buffer->tid;

	intel_pt_log("queue %u cpu %d pid %d tid %d\n",
		     ptq->queue_nr, ptq->cpu, ptq->pid, ptq->tid);

	ptq->thread = NULL;

	if (ptq->tid != -1) {
		if (ptq->pid != -1)
			ptq->thread = machine__findnew_thread(ptq->pt->machine,
							      ptq->pid,
							      ptq->tid);
		else
			ptq->thread = machine__find_thread(ptq->pt->machine, -1,
							   ptq->tid);
	}
}

/* This function assumes data is processed sequentially only */
static int intel_pt_get_trace(struct intel_pt_buffer *b, void *data)
{
	struct intel_pt_queue *ptq = data;
	struct itrace_buffer *buffer = ptq->buffer, *old_buffer = buffer;
	struct itrace_queue *queue;

	if (ptq->stop) {
		b->len = 0;
		return 0;
	}

	queue = &ptq->pt->queues.queue_array[ptq->queue_nr];

	buffer = itrace_buffer__next(queue, buffer);
	if (!buffer) {
		if (old_buffer)
			itrace_buffer__drop_data(old_buffer);
		b->len = 0;
		return 0;
	}

	ptq->buffer = buffer;

	if (!buffer->data) {
		int fd = perf_data_file__fd(ptq->pt->session->file);

		buffer->data = itrace_buffer__get_data(buffer, fd);
		if (!buffer->data)
			return -ENOMEM;
	}

	if (ptq->pt->snapshot_mode && !buffer->consecutive && old_buffer &&
	    intel_pt_do_fix_overlap(ptq->pt, old_buffer, buffer))
		return -ENOMEM;

	if (old_buffer)
		itrace_buffer__drop_data(old_buffer);

	if (buffer->use_data) {
		b->len = buffer->use_size;
		b->buf = buffer->use_data;
	} else {
		b->len = buffer->size;
		b->buf = buffer->data;
	}
	b->ref_timestamp = buffer->reference;

	if (!old_buffer || ptq->pt->sampling_mode || (ptq->pt->snapshot_mode &&
						      !buffer->consecutive)) {
		b->consecutive = false;
		b->trace_nr = buffer->buffer_nr;
	} else {
		b->consecutive = true;
	}

	if (ptq->use_buffer_pid_tid && (ptq->pid != buffer->pid ||
					ptq->tid != buffer->tid))
		intel_pt_use_buffer_pid_tid(ptq, queue, buffer);

	if (ptq->step_through_buffers)
		ptq->stop = true;

	if (!b->len)
		return intel_pt_get_trace(b, data);

	return 0;
}

struct intel_pt_cache_entry {
	struct itrace_cache_entry	entry;
	u64				insn_cnt;
	u64				byte_cnt;
	enum intel_pt_insn_op		op;
	enum intel_pt_insn_branch	branch;
	int				length;
	int32_t				rel;
};

static int intel_pt_config_div(const char *var, const char *value, void *data)
{
	int *div = data;
	long val;

	if (!strcmp(var, "intel-pt.cache-divisor")) {
		val = strtol(value, NULL, 0);
		if (val > 0 && val <= INT_MAX)
			*div = val;
	}

	return 0;
}

static int intel_pt_cache_divisor(void)
{
	static int div;

	if (div)
		return div;

	perf_config(intel_pt_config_div, &div);

	if (!div)
		div = 64;

	return div;
}

static unsigned int intel_pt_cache_size(struct dso *dso,
					struct machine *machine)
{
	off_t size;

	size = dso__data_size(dso, machine);
	size /= intel_pt_cache_divisor();
	if (size < 1000)
		return 10;
	if (size > (1 << 21))
		return 21;
	return 32 - __builtin_clz(size);
}

static struct itrace_cache *intel_pt_cache(struct dso *dso,
					   struct machine *machine)
{
	struct itrace_cache *c;
	unsigned int bits;

	if (dso->itrace_cache)
		return dso->itrace_cache;

	bits = intel_pt_cache_size(dso, machine);

	/* Ignoring cache creation failure */
	c = itrace_cache__new(bits, sizeof(struct intel_pt_cache_entry), 200);

	dso->itrace_cache = c;

	return c;
}

static int intel_pt_cache_add(struct dso *dso, struct machine *machine,
			      u64 offset, u64 insn_cnt, u64 byte_cnt,
			      struct intel_pt_insn *intel_pt_insn)
{
	struct itrace_cache *c = intel_pt_cache(dso, machine);
	struct intel_pt_cache_entry *e;
	int err;

	if (!c)
		return -ENOMEM;

	e = itrace_cache__alloc_entry(c);
	if (!e)
		return -ENOMEM;

	e->insn_cnt = insn_cnt;
	e->byte_cnt = byte_cnt;
	e->op = intel_pt_insn->op;
	e->branch = intel_pt_insn->branch;
	e->length = intel_pt_insn->length;
	e->rel = intel_pt_insn->rel;

	err = itrace_cache__add(c, offset, &e->entry);
	if (err)
		itrace_cache__free_entry(c, e);

	return err;
}

static struct intel_pt_cache_entry *
intel_pt_cache_lookup(struct dso *dso, struct machine *machine, u64 offset)
{
	struct itrace_cache *c = intel_pt_cache(dso, machine);

	if (!c)
		return NULL;

	return itrace_cache__lookup(dso->itrace_cache, offset);
}

static int intel_pt_walk_next_insn(struct intel_pt_insn *intel_pt_insn,
				   uint64_t *insn_cnt_ptr, uint64_t *ip,
				   uint64_t to_ip, uint64_t max_insn_cnt,
				   void *data)
{
	struct intel_pt_queue *ptq = data;
	struct machine *machine = ptq->pt->machine;
	struct thread *thread;
	struct addr_location al;
	unsigned char buf[1024];
	size_t bufsz;
	ssize_t len;
	int x86_64;
	u8 cpumode;
	u64 offset, start_offset, start_ip;
	u64 insn_cnt = 0;
	bool one_map = true;

	if (to_ip && *ip == to_ip)
		goto out_no_cache;

	bufsz = intel_pt_insn_max_size();

	if (*ip >= ptq->pt->kernel_start)
		cpumode = PERF_RECORD_MISC_KERNEL;
	else
		cpumode = PERF_RECORD_MISC_USER;

	thread = ptq->thread;
	if (!thread) {
		if (cpumode != PERF_RECORD_MISC_KERNEL)
			return -EINVAL;
		thread = ptq->pt->unknown_thread;
	}

	while (1) {
		thread__find_addr_map(thread, cpumode, MAP__FUNCTION, *ip, &al);
		if (!al.map || !al.map->dso)
			return -EINVAL;

		if (al.map->dso->data.status == DSO_DATA_STATUS_ERROR &&
		    dso__data_status_seen(al.map->dso,
					  DSO_DATA_STATUS_SEEN_ITRACE))
			return -ENOENT;

		offset = al.map->map_ip(al.map, *ip);

		if (!to_ip && one_map) {
			struct intel_pt_cache_entry *e;

			e = intel_pt_cache_lookup(al.map->dso, machine, offset);
			if (e &&
			    (!max_insn_cnt || e->insn_cnt <= max_insn_cnt)) {
				*insn_cnt_ptr = e->insn_cnt;
				*ip += e->byte_cnt;
				intel_pt_insn->op = e->op;
				intel_pt_insn->branch = e->branch;
				intel_pt_insn->length = e->length;
				intel_pt_insn->rel = e->rel;
				intel_pt_log_insn_no_data(intel_pt_insn, *ip);
				return 0;
			}
		}

		start_offset = offset;
		start_ip = *ip;

		/* Load maps to ensure dso->is_64_bit has been updated */
		map__load(al.map, machine->symbol_filter);

		x86_64 = al.map->dso->is_64_bit;

		while (1) {
			len = dso__data_read_offset(al.map->dso, machine,
						    offset, buf, bufsz);
			if (len <= 0)
				return -EINVAL;

			if (intel_pt_get_insn(buf, len, x86_64, intel_pt_insn))
				return -EINVAL;

			intel_pt_log_insn(intel_pt_insn, *ip);

			insn_cnt += 1;

			if (intel_pt_insn->branch != INTEL_PT_BR_NO_BRANCH)
				goto out;

			if (max_insn_cnt && insn_cnt >= max_insn_cnt)
				goto out_no_cache;

			*ip += intel_pt_insn->length;

			if (to_ip && *ip == to_ip)
				goto out_no_cache;

			if (*ip >= al.map->end)
				break;

			offset += intel_pt_insn->length;
		}
		one_map = false;
	}
out:
	*insn_cnt_ptr = insn_cnt;

	if (!one_map)
		goto out_no_cache;

	/*
	 * Didn't lookup in the 'to_ip' case, so do it now to prevent duplicate
	 * entries.
	 */
	if (to_ip) {
		struct intel_pt_cache_entry *e;

		e = intel_pt_cache_lookup(al.map->dso, machine, start_offset);
		if (e)
			return 0;
	}

	/* Ignore cache errors */
	intel_pt_cache_add(al.map->dso, machine, start_offset, insn_cnt,
			   *ip - start_ip, intel_pt_insn);

	return 0;

out_no_cache:
	*insn_cnt_ptr = insn_cnt;
	return 0;
}

static bool intel_pt_get_config(struct intel_pt *pt,
				struct perf_event_attr *attr, u64 *config)
{
	if (attr->type == pt->pmu_type) {
		if (config)
			*config = attr->config;
		return true;
	}

	if (attr->aux_sample_type == pt->pmu_type &&
	    (attr->sample_type & PERF_SAMPLE_AUX)) {
		if (config)
			*config = attr->aux_sample_config;
		return true;
	}

	return false;
}

static bool intel_pt_exclude_kernel(struct intel_pt *pt)
{
	struct perf_evsel *evsel;

	evlist__for_each(pt->session->evlist, evsel) {
		if (intel_pt_get_config(pt, &evsel->attr, NULL) &&
		    !evsel->attr.exclude_kernel)
			return false;
	}
	return true;
}

static bool intel_pt_return_compression(struct intel_pt *pt)
{
	struct perf_evsel *evsel;
	u64 config;

	if (!pt->noretcomp_bit)
		return true;

	evlist__for_each(pt->session->evlist, evsel) {
		if (intel_pt_get_config(pt, &evsel->attr, &config) &&
		    (config & pt->noretcomp_bit))
			return false;
	}
	return true;
}

static bool intel_pt_timeless_decoding(struct intel_pt *pt)
{
	struct perf_evsel *evsel;
	bool timeless_decoding = true;
	u64 config;

	if (!pt->tsc_bit || !pt->cap_user_time_zero)
		return true;

	evlist__for_each(pt->session->evlist, evsel) {
		if (!(evsel->attr.sample_type & PERF_SAMPLE_TIME))
			return true;
		if (intel_pt_get_config(pt, &evsel->attr, &config)) {
			if (config & pt->tsc_bit)
				timeless_decoding = false;
			else
				return true;
		}
	}
	return timeless_decoding;
}

static bool intel_pt_tracing_kernel(struct intel_pt *pt)
{
	struct perf_evsel *evsel;

	evlist__for_each(pt->session->evlist, evsel) {
		if (intel_pt_get_config(pt, &evsel->attr, NULL) &&
		    !evsel->attr.exclude_kernel)
			return true;
	}
	return false;
}

static bool intel_pt_have_tsc(struct intel_pt *pt)
{
	struct perf_evsel *evsel;
	bool have_tsc = false;
	u64 config;

	if (!pt->tsc_bit)
		return false;

	evlist__for_each(pt->session->evlist, evsel) {
		if (intel_pt_get_config(pt, &evsel->attr, &config)) {
			if (config & pt->tsc_bit)
				have_tsc = true;
			else
				return false;
		}
	}
	return have_tsc;
}

static bool intel_pt_sampling_mode(struct intel_pt *pt)
{
	struct perf_evsel *evsel;

	evlist__for_each(pt->session->evlist, evsel) {
		if (evsel->attr.type == pt->pmu_type)
			return false;
		if (evsel->attr.aux_sample_type == pt->pmu_type &&
		    (evsel->attr.sample_type & PERF_SAMPLE_AUX))
			return true;
	}
	return false;
}

static u64 intel_pt_ns_to_ticks(const struct intel_pt *pt, u64 ns)
{
	u64 quot, rem;

	quot = ns / pt->tc.time_mult;
	rem  = ns % pt->tc.time_mult;
	return (quot << pt->tc.time_shift) + (rem << pt->tc.time_shift) /
		pt->tc.time_mult;
}

static struct intel_pt_queue *intel_pt_alloc_queue(struct intel_pt *pt,
						   unsigned int queue_nr)
{
	struct intel_pt_params params = {0};
	struct intel_pt_queue *ptq;

	ptq = zalloc(sizeof(struct intel_pt_queue));
	if (!ptq)
		return NULL;

	if (pt->synth_opts.callchain) {
		size_t sz = sizeof(struct ip_callchain);

		sz += pt->synth_opts.callchain_sz * sizeof(u64);
		ptq->chain = zalloc(sz);
		if (!ptq->chain)
			goto out_free;
	}

	ptq->event_buf = malloc(PERF_SAMPLE_MAX_SIZE);
	if (!ptq->event_buf)
		goto out_free;

	ptq->pt = pt;
	ptq->queue_nr = queue_nr;
	ptq->exclude_kernel = intel_pt_exclude_kernel(pt);
	ptq->pid = -1;
	ptq->tid = -1;
	ptq->cpu = -1;
	ptq->next_tid = -1;

	params.get_trace = intel_pt_get_trace;
	params.walk_insn = intel_pt_walk_next_insn;
	params.data = ptq;
	params.return_compression = intel_pt_return_compression(pt);

	if (pt->synth_opts.instructions) {
		if (pt->synth_opts.period) {
			switch (pt->synth_opts.period_type) {
			case PERF_ITRACE_PERIOD_INSTRUCTIONS:
				params.period_type =
						INTEL_PT_PERIOD_INSTRUCTIONS;
				params.period = pt->synth_opts.period;
				break;
			case PERF_ITRACE_PERIOD_TICKS:
				params.period_type = INTEL_PT_PERIOD_TICKS;
				params.period = pt->synth_opts.period;
				break;
			case PERF_ITRACE_PERIOD_NANOSECS:
				params.period_type = INTEL_PT_PERIOD_TICKS;
				params.period = intel_pt_ns_to_ticks(pt,
							pt->synth_opts.period);
				break;
			default:
				break;
			}
		}

		if (!params.period) {
			params.period_type = INTEL_PT_PERIOD_INSTRUCTIONS;
			params.period = 1000;
		}
	}

	ptq->decoder = intel_pt_decoder_new(&params);
	if (!ptq->decoder)
		goto out_free;

	return ptq;

out_free:
	zfree(&ptq->event_buf);
	zfree(&ptq->chain);
	free(ptq);
	return NULL;
}

static void intel_pt_free_queue(void *priv)
{
	struct intel_pt_queue *ptq = priv;

	if (!ptq)
		return;
	intel_pt_decoder_free(ptq->decoder);
	zfree(&ptq->event_buf);
	zfree(&ptq->chain);
	free(ptq);
}

static void intel_pt_set_pid_tid_cpu(struct intel_pt *pt,
				     struct itrace_queue *queue)
{
	struct intel_pt_queue *ptq = queue->priv;

	if (queue->tid == -1 || pt->have_sched_switch) {
		ptq->tid = machine__get_current_tid(pt->machine, ptq->cpu);
		ptq->thread = NULL;
	}

	if (!ptq->thread && ptq->tid != -1)
		ptq->thread = machine__find_thread(pt->machine, -1, ptq->tid);

	if (ptq->thread) {
		ptq->pid = ptq->thread->pid_;
		if (queue->cpu == -1)
			ptq->cpu = ptq->thread->cpu;
	}
}

static void intel_pt_sample_flags(struct intel_pt_queue *ptq)
{
	if (ptq->state->flags & INTEL_PT_ABORT_TX) {
		ptq->flags = PERF_IP_FLAG_BRANCH | PERF_IP_FLAG_TX_ABORT;
	} else if (ptq->state->flags & INTEL_PT_ASYNC) {
		if (ptq->state->to_ip)
			ptq->flags = PERF_IP_FLAG_BRANCH | PERF_IP_FLAG_CALL |
				     PERF_IP_FLAG_ASYNC |
				     PERF_IP_FLAG_INTERRUPT;
		else
			ptq->flags = PERF_IP_FLAG_BRANCH |
				     PERF_IP_FLAG_TRACE_END;
		ptq->insn_len = 0;
	} else {
		if (ptq->state->from_ip)
			ptq->flags = intel_pt_insn_type(ptq->state->insn_op);
		else
			ptq->flags = PERF_IP_FLAG_BRANCH |
				     PERF_IP_FLAG_TRACE_BEGIN;
		if (ptq->state->flags & INTEL_PT_IN_TX)
			ptq->flags |= PERF_IP_FLAG_IN_TX;
		ptq->insn_len = ptq->state->insn_len;
	}
}

static int intel_pt_setup_queue(struct intel_pt *pt, struct itrace_queue *queue,
				unsigned int queue_nr)
{
	struct intel_pt_queue *ptq = queue->priv;

	if (list_empty(&queue->head))
		return 0;

	if (!ptq) {
		ptq = intel_pt_alloc_queue(pt, queue_nr);
		if (!ptq)
			return -ENOMEM;
		queue->priv = ptq;

		if (queue->cpu != -1)
			ptq->cpu = queue->cpu;
		ptq->tid = queue->tid;

		if (pt->sampling_mode) {
			if (pt->timeless_decoding)
				ptq->step_through_buffers = true;
			if (pt->timeless_decoding || !pt->have_sched_switch)
				ptq->use_buffer_pid_tid = true;
		}
	}

	if (!ptq->on_heap &&
	    (!pt->sync_switch ||
	     ptq->switch_state != INTEL_PT_SS_EXPECTING_SWITCH_EVENT)) {
		const struct intel_pt_state *state;
		int ret;

		if (pt->timeless_decoding)
			return 0;

		intel_pt_log("queue %u getting timestamp\n", queue_nr);
		intel_pt_log("queue %u decoding cpu %d pid %d tid %d\n",
			     queue_nr, ptq->cpu, ptq->pid, ptq->tid);
		while (1) {
			state = intel_pt_decode(ptq->decoder);
			if (state->err) {
				if (state->err == -ENODATA) {
					intel_pt_log("queue %u has no timestamp\n",
						     queue_nr);
					return 0;
				}
				continue;
			}
			if (state->timestamp)
				break;
		}

		ptq->timestamp = state->timestamp;
		intel_pt_log("queue %u timestamp 0x%" PRIx64 "\n",
			     queue_nr, ptq->timestamp);
		ptq->state = state;
		ptq->have_sample = true;
		intel_pt_sample_flags(ptq);
		ret = itrace_heap__add(&pt->heap, queue_nr, ptq->timestamp);
		if (ret)
			return ret;
		ptq->on_heap = true;
	}

	return 0;
}

static int intel_pt_setup_queues(struct intel_pt *pt)
{
	unsigned int i;
	int ret;

	for (i = 0; i < pt->queues.nr_queues; i++) {
		ret = intel_pt_setup_queue(pt, &pt->queues.queue_array[i], i);
		if (ret)
			return ret;
	}
	return 0;
}

static int intel_pt_inject_event(union perf_event *event,
				 struct perf_sample *sample, u64 type,
				 bool swapped)
{
	event->header.size = perf_event__sample_event_size(sample, type, 0);
	return perf_event__synthesize_sample(event, type, 0, sample, swapped);
}

static int intel_pt_synth_branch_sample(struct intel_pt_queue *ptq,
					struct perf_tool *tool)
{
	int ret;
	struct intel_pt *pt = ptq->pt;
	union perf_event *event = ptq->event_buf;
	struct perf_sample sample = {0};

	event->sample.header.type = PERF_RECORD_SAMPLE;
	event->sample.header.misc = PERF_RECORD_MISC_USER;
	event->sample.header.size = sizeof(struct perf_event_header);

	if (!pt->timeless_decoding)
		sample.time = tsc_to_perf_time(ptq->timestamp, &pt->tc);

	sample.ip = ptq->state->from_ip;
	sample.pid = ptq->pid;
	sample.tid = ptq->tid;
	sample.addr = ptq->state->to_ip;
	sample.id = ptq->pt->branches_id;
	sample.stream_id = ptq->pt->branches_id;
	sample.period = 1;
	sample.cpu = ptq->cpu;

	if (pt->branches_filter && !(pt->branches_filter & ptq->flags))
		return 0;

	if (pt->synth_opts.inject) {
		ret = intel_pt_inject_event(event, &sample,
					    pt->branches_sample_type,
					    pt->synth_needs_swap);
		if (ret)
			return ret;
	}

	ret = perf_session__deliver_synth_event(pt->session, event, &sample,
						tool);
	if (ret)
		pr_err("Intel Processor Trace: failed to deliver branch event, error %d\n",
		       ret);

	return ret;
}

static int intel_pt_synth_instruction_sample(struct intel_pt_queue *ptq,
					     struct perf_tool *tool)
{
	int ret;
	struct intel_pt *pt = ptq->pt;
	union perf_event *event = ptq->event_buf;
	struct perf_sample sample = {0};

	event->sample.header.type = PERF_RECORD_SAMPLE;
	event->sample.header.misc = PERF_RECORD_MISC_USER;
	event->sample.header.size = sizeof(struct perf_event_header);

	if (!pt->timeless_decoding)
		sample.time = tsc_to_perf_time(ptq->timestamp, &pt->tc);

	sample.ip = ptq->state->from_ip;
	sample.pid = ptq->pid;
	sample.tid = ptq->tid;
	sample.addr = ptq->state->to_ip;
	sample.id = ptq->pt->instructions_id;
	sample.stream_id = ptq->pt->instructions_id;
	sample.period = ptq->pt->instructions_sample_period;
	sample.cpu = ptq->cpu;

	if (pt->synth_opts.callchain) {
		thread_stack__sample(ptq->thread, ptq->chain,
				     pt->synth_opts.callchain_sz, sample.ip);
		sample.callchain = ptq->chain;
	}

	if (pt->synth_opts.inject) {
		ret = intel_pt_inject_event(event, &sample,
					    pt->instructions_sample_type,
					    pt->synth_needs_swap);
		if (ret)
			return ret;
	}

	ret = perf_session__deliver_synth_event(pt->session, event, &sample,
						tool);
	if (ret)
		pr_err("Intel Processor Trace: failed to deliver instruction event, error %d\n",
		       ret);

	return ret;
}

static int intel_pt_synth_error(struct intel_pt *pt, struct perf_tool *tool,
				int code, int cpu, pid_t pid, pid_t tid, u64 ip)
{
	union perf_event event;
	const char *msg;
	int err;

	msg = intel_pt_error_message(code);

	itrace_synth_error(&event.itrace_error, PERF_ITRACE_DECODER_ERROR, code,
			   cpu, pid, tid, ip, msg);

	err = perf_session__deliver_synth_event(pt->session, &event, NULL,
						tool);
	if (err)
		pr_err("Intel Processor Trace: failed to deliver error event, error %d\n",
		       err);

	return err;
}

static int intel_pt_next_tid(struct intel_pt *pt, struct intel_pt_queue *ptq)
{
	struct itrace_queue *queue;
	pid_t tid = ptq->next_tid;
	int err;

	if (tid == -1)
		return 0;

	intel_pt_log("switch: cpu %d tid %d\n", ptq->cpu, tid);

	err = machine__set_current_tid(pt->machine, ptq->cpu, -1, tid);

	queue = &pt->queues.queue_array[ptq->queue_nr];
	intel_pt_set_pid_tid_cpu(pt, queue);

	ptq->next_tid = -1;

	return err;
}

static int intel_pt_sample(struct intel_pt_queue *ptq, struct perf_tool *tool)
{
	const struct intel_pt_state *state = ptq->state;
	struct intel_pt *pt = ptq->pt;
	int err;

	if (!ptq->have_sample)
		return 0;

	ptq->have_sample = false;

	if (pt->sample_instructions &&
	    (state->type & INTEL_PT_INSTRUCTION)) {
		err = intel_pt_synth_instruction_sample(ptq, tool);
		if (err)
			return err;
	}

	if (!(state->type & INTEL_PT_BRANCH))
		return 0;

	if (pt->synth_opts.callchain)
		thread_stack__event(ptq->thread, ptq->flags, state->from_ip,
				    state->to_ip, ptq->insn_len,
				    state->trace_nr);

	if (pt->sample_branches) {
		err = intel_pt_synth_branch_sample(ptq, tool);
		if (err)
			return err;
	}

	if (!pt->sync_switch)
		return 0;

	if (state->to_ip == pt->switch_ip &&
	    (ptq->flags & PERF_IP_FLAG_CALL)) {
		switch (ptq->switch_state) {
		case INTEL_PT_SS_UNKNOWN:
		case INTEL_PT_SS_EXPECTING_SWITCH_IP:
			err = intel_pt_next_tid(pt, ptq);
			if (err)
				return err;
			ptq->switch_state = INTEL_PT_SS_TRACING;
			break;
		default:
			ptq->switch_state = INTEL_PT_SS_EXPECTING_SWITCH_EVENT;
			return 1;
		}
	} else if (!state->to_ip) {
		ptq->switch_state = INTEL_PT_SS_NOT_TRACING;
	} else if (ptq->switch_state == INTEL_PT_SS_NOT_TRACING) {
		ptq->switch_state = INTEL_PT_SS_UNKNOWN;
	} else if (ptq->switch_state == INTEL_PT_SS_UNKNOWN &&
		   state->to_ip == pt->ptss_ip &&
		   (ptq->flags & PERF_IP_FLAG_CALL)) {
		ptq->switch_state = INTEL_PT_SS_TRACING;
	}

	return 0;
}

static u64 intel_pt_switch_ip(struct machine *machine, u64 *ptss_ip)
{
	struct map *map;
	struct symbol *sym, *start;
	u64 ip, switch_ip = 0;

	if (ptss_ip)
		*ptss_ip = 0;

	map = machine__kernel_map(machine, MAP__FUNCTION);
	if (!map)
		return 0;

	if (map__load(map, machine->symbol_filter))
		return 0;

	start = dso__first_symbol(map->dso, MAP__FUNCTION);

	for (sym = start; sym; sym = dso__next_symbol(sym)) {
		if (sym->binding == STB_GLOBAL &&
		    !strcmp(sym->name, "__switch_to")) {
			ip = map->unmap_ip(map, sym->start);
			if (ip >= map->start && ip < map->end) {
				switch_ip = ip;
				break;
			}
		}
	}

	if (!switch_ip || !ptss_ip)
		return 0;

	for (sym = start; sym; sym = dso__next_symbol(sym)) {
		if (!strcmp(sym->name, "perf_trace_sched_switch")) {
			ip = map->unmap_ip(map, sym->start);
			if (ip >= map->start && ip < map->end) {
				*ptss_ip = ip;
				break;
			}
		}
	}

	return switch_ip;
}

static int intel_pt_run_decoder(struct intel_pt_queue *ptq, u64 *timestamp,
				struct perf_tool *tool)
{
	const struct intel_pt_state *state = ptq->state;
	struct intel_pt *pt = ptq->pt;
	int err;

	if (!pt->kernel_start) {
		pt->kernel_start = machine__kernel_start(pt->machine);
		if (pt->per_cpu_mmaps && pt->have_sched_switch &&
		    !pt->timeless_decoding && intel_pt_tracing_kernel(pt) &&
		    !pt->sampling_mode) {
			pt->switch_ip = intel_pt_switch_ip(pt->machine,
							   &pt->ptss_ip);
			if (pt->switch_ip) {
				intel_pt_log("switch_ip: %"PRIx64" ptss_ip: %"PRIx64,
					     pt->switch_ip, pt->ptss_ip);
				pt->sync_switch = true;
				pt->est_tsc_orig = pt->est_tsc;
				pt->est_tsc = false;
			}
		}
	}

	intel_pt_log("queue %u decoding cpu %d pid %d tid %d\n",
		     ptq->queue_nr, ptq->cpu, ptq->pid, ptq->tid);
	while (1) {
		err = intel_pt_sample(ptq, tool);
		if (err)
			return err;

		state = intel_pt_decode(ptq->decoder);
		if (state->err) {
			if (state->err == -ENODATA)
				return 1;
			if (pt->sync_switch &&
			    state->from_ip >= pt->kernel_start) {
				pt->sync_switch = false;
				pt->est_tsc = pt->est_tsc_orig;
				intel_pt_next_tid(pt, ptq);
			}
			if (pt->synth_opts.errors) {
				err = intel_pt_synth_error(pt, tool,
							   -state->err,
							   ptq->cpu, ptq->pid,
							   ptq->tid,
							   state->from_ip);
				if (err)
					return err;
			}
			continue;
		}

		ptq->state = state;
		ptq->have_sample = true;
		intel_pt_sample_flags(ptq);

		/* Use estimated TSC upon return to user space */
		if (pt->est_tsc) {
			if (state->from_ip >= pt->kernel_start &&
			    state->to_ip &&
			    state->to_ip < pt->kernel_start)
				ptq->timestamp = state->est_timestamp;
			else if (state->timestamp > ptq->timestamp)
				ptq->timestamp = state->timestamp;
		/* Use estimated TSC in unknown switch state */
		} else if (pt->sync_switch &&
			   ptq->switch_state == INTEL_PT_SS_UNKNOWN &&
			   state->to_ip == pt->switch_ip &&
			   (ptq->flags & PERF_IP_FLAG_CALL) &&
			   ptq->next_tid == -1) {
			ptq->timestamp = state->est_timestamp;
		} else if (state->timestamp > ptq->timestamp) {
			ptq->timestamp = state->timestamp;
		}

		if (!pt->timeless_decoding && ptq->timestamp >= *timestamp) {
			*timestamp = ptq->timestamp;
			return 0;
		}
	}
	return 0;
}

static inline int intel_pt_update_queues(struct intel_pt *pt)
{
	if (pt->queues.new_data) {
		pt->queues.new_data = false;
		return intel_pt_setup_queues(pt);
	}
	return 0;
}

static int intel_pt_process_queues(struct intel_pt *pt, u64 timestamp,
				   struct perf_tool *tool)
{
	unsigned int queue_nr;
	u64 ts;
	int ret;

	while (1) {
		struct itrace_queue *queue;
		struct intel_pt_queue *ptq;

		if (!pt->heap.heap_cnt)
			return 0;

		if (pt->heap.heap_array[0].ordinal >= timestamp)
			return 0;

		queue_nr = pt->heap.heap_array[0].queue_nr;
		queue = &pt->queues.queue_array[queue_nr];
		ptq = queue->priv;

		intel_pt_log("queue %u processing 0x%" PRIx64 " to 0x%" PRIx64 "\n",
			     queue_nr, pt->heap.heap_array[0].ordinal,
			     timestamp);

		itrace_heap__pop(&pt->heap);

		if (pt->heap.heap_cnt) {
			ts = pt->heap.heap_array[0].ordinal + 1;
			if (ts > timestamp)
				ts = timestamp;
		} else {
			ts = timestamp;
		}

		intel_pt_set_pid_tid_cpu(pt, queue);

		ret = intel_pt_run_decoder(ptq, &ts, tool);

		if (ret < 0) {
			itrace_heap__add(&pt->heap, queue_nr, ts);
			return ret;
		}

		if (!ret) {
			ret = itrace_heap__add(&pt->heap, queue_nr, ts);
			if (ret < 0)
				return ret;
		} else {
			ptq->on_heap = false;
		}
	}

	return 0;
}

static int intel_pt_process_sample_queues(struct intel_pt *pt, u64 timestamp,
					  struct perf_tool *tool)
{
	unsigned int queue_nr;
	u64 ts;
	int ret;

	while (1) {
		struct itrace_queue *queue;
		struct intel_pt_queue *ptq;

		if (!pt->heap.heap_cnt)
			return 0;

		if (pt->heap.heap_array[0].ordinal >= timestamp)
			return 0;

		queue_nr = pt->heap.heap_array[0].queue_nr;
		queue = &pt->queues.queue_array[queue_nr];
		ptq = queue->priv;

		intel_pt_log("queue %u processing 0x%" PRIx64 " to 0x%" PRIx64 "\n",
			     queue_nr, pt->heap.heap_array[0].ordinal,
			     timestamp);

		itrace_heap__pop(&pt->heap);

		if (pt->heap.heap_cnt) {
			ts = pt->heap.heap_array[0].ordinal + 1;
			if (ts > timestamp)
				ts = timestamp;
		} else {
			ts = timestamp;
		}

		if (!ptq->use_buffer_pid_tid)
			intel_pt_set_pid_tid_cpu(pt, queue);

		ret = intel_pt_run_decoder(ptq, &ts, tool);
		if (ret < 0) {
			itrace_heap__add(&pt->heap, queue_nr, ts);
			return ret;
		}

		if (ret) {
			ptq->on_heap = false;
		} else {
			ret = itrace_heap__add(&pt->heap, queue_nr, ts);
			if (ret < 0)
				return ret;
		}
	}

	return 0;
}

static int intel_pt_process_timeless_queues(struct intel_pt *pt, pid_t tid,
					    u64 time_, struct perf_tool *tool)
{
	struct itrace_queues *queues = &pt->queues;
	unsigned int i;
	u64 ts = 0;

	for (i = 0; i < queues->nr_queues; i++) {
		struct itrace_queue *queue = &pt->queues.queue_array[i];
		struct intel_pt_queue *ptq = queue->priv;

		if (ptq && (tid == -1 || ptq->tid == tid)) {
			ptq->time = time_;
			intel_pt_set_pid_tid_cpu(pt, queue);
			intel_pt_run_decoder(ptq, &ts, tool);
		}
	}
	return 0;
}

static int intel_pt_process_timeless_sample(struct intel_pt *pt,
					    struct perf_sample *sample,
					    struct perf_tool *tool)
{
	struct itrace_queue *queue = itrace_queues__sample_queue(&pt->queues,
								 sample,
								 pt->session);
	struct intel_pt_queue *ptq = queue->priv;
	u64 ts = 0;

	if (!ptq)
		return 0;

	ptq->stop = false;
	ptq->time = sample->time;
	intel_pt_set_pid_tid_cpu(pt, queue);
	intel_pt_run_decoder(ptq, &ts, tool);
	return 0;
}

static int intel_pt_lost(struct intel_pt *pt, struct perf_sample *sample,
			 struct perf_tool *tool)
{
	union perf_event event;
	int err;

	itrace_synth_error(&event.itrace_error, PERF_ITRACE_DECODER_ERROR,
			   ENOSPC, sample->cpu, sample->pid, sample->tid, 0,
			   "Lost trace data");

	err = perf_session__deliver_synth_event(pt->session, &event, NULL,
						tool);
	if (err)
		pr_err("Intel Processor Trace: failed to deliver error event, error %d\n",
		       err);

	return err;
}

static struct intel_pt_queue *intel_pt_cpu_to_ptq(struct intel_pt *pt, int cpu)
{
	unsigned i, j;

	if (cpu < 0 || !pt->queues.nr_queues)
		return NULL;

	if ((unsigned)cpu >= pt->queues.nr_queues)
		i = pt->queues.nr_queues - 1;
	else
		i = cpu;

	if (pt->queues.queue_array[i].cpu == cpu)
		return pt->queues.queue_array[i].priv;

	for (j = 0; i > 0; j++) {
		if (pt->queues.queue_array[--i].cpu == cpu)
			return pt->queues.queue_array[i].priv;
	}

	for (; j < pt->queues.nr_queues; j++) {
		if (pt->queues.queue_array[j].cpu == cpu)
			return pt->queues.queue_array[j].priv;
	}

	return NULL;
}

static int intel_pt_process_switch(struct intel_pt *pt,
				   struct perf_sample *sample)
{
	struct intel_pt_queue *ptq;
	struct perf_evsel *evsel;
	pid_t tid;
	int cpu, err;

	evsel = perf_evlist__id2evsel(pt->session->evlist, sample->id);
	if (evsel != pt->switch_evsel)
		return 0;

	tid = perf_evsel__intval(evsel, sample, "next_pid");
	cpu = sample->cpu;

	intel_pt_log("sched_switch: cpu %d tid %d time %"PRIu64" tsc %#"PRIx64"\n",
		     cpu, tid, sample->time, perf_time_to_tsc(sample->time,
		     &pt->tc));

	if (!pt->sync_switch)
		goto out;

	ptq = intel_pt_cpu_to_ptq(pt, cpu);
	if (!ptq)
		goto out;

	switch (ptq->switch_state) {
	case INTEL_PT_SS_NOT_TRACING:
		ptq->next_tid = -1;
		break;
	case INTEL_PT_SS_UNKNOWN:
	case INTEL_PT_SS_TRACING:
		ptq->next_tid = tid;
		ptq->switch_state = INTEL_PT_SS_EXPECTING_SWITCH_IP;
		return 0;
	case INTEL_PT_SS_EXPECTING_SWITCH_EVENT:
		if (!ptq->on_heap) {
			ptq->timestamp = perf_time_to_tsc(sample->time,
							  &pt->tc);
			err = itrace_heap__add(&pt->heap, ptq->queue_nr,
					       ptq->timestamp);
			if (err)
				return err;
			ptq->on_heap = true;
		}
		ptq->switch_state = INTEL_PT_SS_TRACING;
		break;
	case INTEL_PT_SS_EXPECTING_SWITCH_IP:
		ptq->next_tid = tid;
		intel_pt_log("ERROR: cpu %d expecting switch ip\n", cpu);
		break;
	default:
		break;
	}
out:
	return machine__set_current_tid(pt->machine, cpu, -1, tid);
}

static int intel_pt_process_itrace_start(struct intel_pt *pt,
					 union perf_event *event,
					 struct perf_sample *sample)
{
	if (!pt->per_cpu_mmaps)
		return 0;

	intel_pt_log("itrace_start: cpu %d pid %d tid %d time %"PRIu64" tsc %#"PRIx64"\n",
		     sample->cpu, event->itrace_start.pid,
		     event->itrace_start.tid, sample->time,
		     perf_time_to_tsc(sample->time, &pt->tc));

	return machine__set_current_tid(pt->machine, sample->cpu,
					event->itrace_start.pid,
					event->itrace_start.tid);
}

static int intel_pt_process_event(struct perf_session *session,
				  union perf_event *event,
				  struct perf_sample *sample,
				  struct perf_tool *tool)
{
	struct intel_pt *pt = container_of(session->itrace, struct intel_pt,
					   itrace);
	u64 timestamp;
	int err = 0;

	if (dump_trace)
		return 0;

	if (!tool->ordered_events) {
		pr_err("Intel Processor Trace requires ordered events\n");
		return -EINVAL;
	}

	if (sample->time)
		timestamp = perf_time_to_tsc(sample->time, &pt->tc);
	else
		timestamp = 0;

	if (timestamp || pt->timeless_decoding) {
		err = intel_pt_update_queues(pt);
		if (err)
			return err;
	}

	if (pt->timeless_decoding) {
		if (pt->sampling_mode) {
			if (sample->aux_sample.size)
				err = intel_pt_process_timeless_sample(pt,
								       sample,
								       tool);
		} else if (event->header.type == PERF_RECORD_EXIT) {
			err = intel_pt_process_timeless_queues(pt,
							       event->comm.tid,
							       sample->time,
							       tool);
		}
	} else if (timestamp) {
		if (pt->sampling_mode)
			err = intel_pt_process_sample_queues(pt, timestamp,
							     tool);
		else
			err = intel_pt_process_queues(pt, timestamp, tool);
	}
	if (err)
		return err;

	if (event->header.type == PERF_RECORD_AUX &&
	    (event->aux.flags & PERF_AUX_FLAG_TRUNCATED) &&
	    pt->synth_opts.errors)
		err = intel_pt_lost(pt, sample, tool);

	if (pt->switch_evsel && event->header.type == PERF_RECORD_SAMPLE)
		err = intel_pt_process_switch(pt, sample);
	else if (event->header.type == PERF_RECORD_ITRACE_START)
		err = intel_pt_process_itrace_start(pt, event, sample);

	return err;
}

static int intel_pt_flush(struct perf_session *session, struct perf_tool *tool)
{
	struct intel_pt *pt = container_of(session->itrace, struct intel_pt,
					   itrace);
	int ret;

	if (dump_trace)
		return 0;

	if (!tool->ordered_events)
		return -EINVAL;

	ret = intel_pt_update_queues(pt);
	if (ret < 0)
		return ret;

	if (pt->timeless_decoding)
		return intel_pt_process_timeless_queues(pt, -1,
						MAX_TIMESTAMP - 1, tool);

	return intel_pt_process_queues(pt, MAX_TIMESTAMP, tool);
}

static void intel_pt_free_events(struct perf_session *session)
{
	struct intel_pt *pt = container_of(session->itrace, struct intel_pt,
					   itrace);
	struct itrace_queues *queues = &pt->queues;
	unsigned int i;

	for (i = 0; i < queues->nr_queues; i++) {
		intel_pt_free_queue(queues->queue_array[i].priv);
		queues->queue_array[i].priv = NULL;
	}
	intel_pt_log_disable();
	itrace_queues__free(queues);
}

static void intel_pt_free(struct perf_session *session)
{
	struct intel_pt *pt = container_of(session->itrace, struct intel_pt,
					   itrace);

	itrace_heap__free(&pt->heap);
	intel_pt_free_events(session);
	session->itrace = NULL;
	thread__delete(pt->unknown_thread);
	free(pt);
}

static int intel_pt_process_itrace_event(struct perf_session *session,
					 union perf_event *event,
					 struct perf_tool *tool __maybe_unused)
{
	struct intel_pt *pt = container_of(session->itrace, struct intel_pt,
					   itrace);

	if (pt->sampling_mode)
		return 0;

	if (!pt->data_queued) {
		struct itrace_buffer *buffer;
		off_t data_offset;
		int fd = perf_data_file__fd(session->file);
		int err;

		if (perf_data_file__is_pipe(session->file)) {
			data_offset = 0;
		} else {
			data_offset = lseek(fd, 0, SEEK_CUR);
			if (data_offset == -1)
				return -errno;
		}

		err = itrace_queues__add_event(&pt->queues, session, event,
					       data_offset, &buffer);
		if (err)
			return err;

		/* Dump here now we have copied a piped trace out of the pipe */
		if (dump_trace) {
			if (itrace_buffer__get_data(buffer, fd)) {
				intel_pt_dump_event(pt, buffer->data,
						    buffer->size);
				itrace_buffer__put_data(buffer);
			}
		}
	}

	return 0;
}

static int intel_pt_queue_event(struct perf_session *session,
				union perf_event *event __maybe_unused,
				struct perf_sample *sample)
{
	struct intel_pt *pt = container_of(session->itrace, struct intel_pt,
					   itrace);
	unsigned int queue_nr;
	u64 timestamp;
	int err;

	if (!sample->aux_sample.size)
		return 0;

	if (!pt->sampling_mode)
		return 0;

	if (sample->time)
		timestamp = perf_time_to_tsc(sample->time, &pt->tc);
	else
		timestamp = 0;

	err = itrace_queues__add_sample(&pt->queues, sample, session, &queue_nr,
					timestamp);
	if (err)
		return err;

	return intel_pt_fix_overlap(pt, queue_nr);
}

struct intel_pt_synth {
	struct perf_tool dummy_tool;
	struct perf_tool *tool;
	struct perf_session *session;
};

static int intel_pt_event_synth(struct perf_tool *tool,
				union perf_event *event,
				struct perf_sample *sample __maybe_unused,
				struct machine *machine __maybe_unused)
{
	struct intel_pt_synth *intel_pt_synth =
			container_of(tool, struct intel_pt_synth, dummy_tool);

	return perf_session__deliver_synth_event(intel_pt_synth->session, event,
						 NULL, intel_pt_synth->tool);
}

static int intel_pt_synth_event(struct perf_session *session,
				struct perf_tool *tool,
				struct perf_event_attr *attr, u64 id)
{
	struct intel_pt_synth intel_pt_synth;

	memset(&intel_pt_synth, 0, sizeof(struct intel_pt_synth));
	intel_pt_synth.tool = tool;
	intel_pt_synth.session = session;

	return perf_event__synthesize_attr(&intel_pt_synth.dummy_tool, attr, 1,
					   &id, intel_pt_event_synth);
}

static int intel_pt_synth_events(struct intel_pt *pt,
				 struct perf_session *session,
				 struct perf_tool *tool)
{
	struct perf_evlist *evlist = session->evlist;
	struct perf_evsel *evsel;
	struct perf_event_attr attr;
	bool found = false;
	u64 id;
	int err;

	list_for_each_entry(evsel, &evlist->entries, node) {
		if ((evsel->attr.type == pt->pmu_type ||
		     (evsel->attr.sample_type & PERF_SAMPLE_AUX)) &&
		    evsel->ids) {
			found = true;
			break;
		}
	}

	if (!found) {
		pr_debug("There are no selected events with Intel Processor Trace data\n");
		return 0;
	}

	memset(&attr, 0, sizeof(struct perf_event_attr));
	attr.size = sizeof(struct perf_event_attr);
	attr.type = PERF_TYPE_HARDWARE;
	attr.sample_type = evsel->attr.sample_type & PERF_SAMPLE_MASK;
	attr.sample_type |= PERF_SAMPLE_IP | PERF_SAMPLE_TID |
			    PERF_SAMPLE_PERIOD;
	if (pt->timeless_decoding)
		attr.sample_type &= ~(u64)PERF_SAMPLE_TIME;
	else
		attr.sample_type |= PERF_SAMPLE_TIME;
	if (!pt->per_cpu_mmaps)
		attr.sample_type &= ~(u64)PERF_SAMPLE_CPU;
	attr.exclude_user = evsel->attr.exclude_user;
	attr.exclude_kernel = evsel->attr.exclude_kernel;
	attr.exclude_hv = evsel->attr.exclude_hv;
	attr.exclude_host = evsel->attr.exclude_host;
	attr.exclude_guest = evsel->attr.exclude_guest;
	attr.sample_id_all = evsel->attr.sample_id_all;
	attr.read_format = evsel->attr.read_format;

	id = evsel->id[0] + 1000000000;
	if (!id)
		id = 1;

	if (pt->synth_opts.instructions) {
		attr.config = PERF_COUNT_HW_INSTRUCTIONS;
		if (pt->synth_opts.period_type == PERF_ITRACE_PERIOD_NANOSECS)
			attr.sample_period =
				intel_pt_ns_to_ticks(pt, pt->synth_opts.period);
		else
			attr.sample_period = pt->synth_opts.period;
		pt->instructions_sample_period = attr.sample_period;
		if (pt->synth_opts.callchain)
			attr.sample_type |= PERF_SAMPLE_CALLCHAIN;
		pr_debug("Synthesizing 'instructions' event with id %" PRIu64 " sample type %#" PRIx64 "\n",
			 id, (u64)attr.sample_type);
		err = intel_pt_synth_event(session, tool, &attr, id);
		if (err) {
			pr_err("%s: failed to synthesize 'instructions' event type\n",
			       __func__);
			return err;
		}
		pt->sample_instructions = true;
		pt->instructions_sample_type = attr.sample_type;
		pt->instructions_id = id;
		id += 1;
	}

	if (pt->synth_opts.branches) {
		attr.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
		attr.sample_period = 1;
		attr.sample_type |= PERF_SAMPLE_ADDR;
		attr.sample_type &= ~(u64)PERF_SAMPLE_CALLCHAIN;
		pr_debug("Synthesizing 'branches' event with id %" PRIu64 " sample type %#" PRIx64 "\n",
			 id, (u64)attr.sample_type);
		err = intel_pt_synth_event(session, tool, &attr, id);
		if (err) {
			pr_err("%s: failed to synthesize 'branches' event type\n",
			       __func__);
			return err;
		}
		pt->sample_branches = true;
		pt->branches_sample_type = attr.sample_type;
		pt->branches_id = id;
	}

	pt->synth_needs_swap = evsel->needs_swap;

	return 0;
}

static struct perf_evsel *intel_pt_find_sched_switch(struct perf_evlist *evlist)
{
	struct perf_evsel *evsel;

	list_for_each_entry_reverse(evsel, &evlist->entries, node) {
		const char *name = perf_evsel__name(evsel);

		if (!strcmp(name, "sched:sched_switch"))
			return evsel;
	}

	return NULL;
}

enum {
	INTEL_PT_PMU_TYPE,
	INTEL_PT_TIME_SHIFT,
	INTEL_PT_TIME_MULT,
	INTEL_PT_TIME_ZERO,
	INTEL_PT_CAP_USER_TIME_ZERO,
	INTEL_PT_TSC_BIT,
	INTEL_PT_NORETCOMP_BIT,
	INTEL_PT_HAVE_SCHED_SWITCH,
	INTEL_PT_SNAPSHOT_MODE,
	INTEL_PT_PER_CPU_MMAPS,
	INTEL_PT_ITRACE_PRIV_SIZE,
};

static const char * const intel_pt_info_fmts[] = {
	[INTEL_PT_PMU_TYPE]		= "  PMU Type           %"PRId64"\n",
	[INTEL_PT_TIME_SHIFT]		= "  Time Shift         %"PRIu64"\n",
	[INTEL_PT_TIME_MULT]		= "  Time Muliplier     %"PRIu64"\n",
	[INTEL_PT_TIME_ZERO]		= "  Time Zero          %"PRIu64"\n",
	[INTEL_PT_CAP_USER_TIME_ZERO]	= "  Cap Time Zero      %"PRId64"\n",
	[INTEL_PT_TSC_BIT]		= "  TSC bit            %#"PRIx64"\n",
	[INTEL_PT_NORETCOMP_BIT]	= "  NoRETComp bit      %#"PRIx64"\n",
	[INTEL_PT_HAVE_SCHED_SWITCH]	= "  Have sched_switch  %"PRId64"\n",
	[INTEL_PT_SNAPSHOT_MODE]	= "  Snapshot mode      %"PRId64"\n",
	[INTEL_PT_PER_CPU_MMAPS]	= "  Per-cpu maps       %"PRId64"\n",
};

static void intel_pt_print_info(u64 *arr, int start, int finish)
{
	int i;

	if (!dump_trace)
		return;

	for (i = start; i <= finish; i++)
		fprintf(stdout, intel_pt_info_fmts[i], arr[i]);
}

u64 intel_pt_itrace_info_priv[INTEL_PT_ITRACE_PRIV_SIZE];

int intel_pt_process_itrace_info(struct perf_tool *tool,
				 union perf_event *event,
				 struct perf_session *session)
{
	struct itrace_info_event *itrace_info = &event->itrace_info;
	size_t min_sz = sizeof(u64) * INTEL_PT_PER_CPU_MMAPS;
	struct intel_pt *pt;
	int err;

	if (itrace_info->header.size < sizeof(struct itrace_info_event) +
					min_sz)
		return -EINVAL;

	pt = zalloc(sizeof(struct intel_pt));
	if (!pt)
		return -ENOMEM;

	err = itrace_queues__init(&pt->queues);
	if (err)
		goto err_free;

	intel_pt_log_set_name(INTEL_PT_PMU_NAME);

	pt->session = session;
	pt->machine = &session->machines.host; /* No kvm support */
	pt->itrace_type = itrace_info->type;
	pt->pmu_type = itrace_info->priv[INTEL_PT_PMU_TYPE];
	pt->tc.time_shift = itrace_info->priv[INTEL_PT_TIME_SHIFT];
	pt->tc.time_mult = itrace_info->priv[INTEL_PT_TIME_MULT];
	pt->tc.time_zero = itrace_info->priv[INTEL_PT_TIME_ZERO];
	pt->cap_user_time_zero = itrace_info->priv[INTEL_PT_CAP_USER_TIME_ZERO];
	pt->tsc_bit = itrace_info->priv[INTEL_PT_TSC_BIT];
	pt->noretcomp_bit = itrace_info->priv[INTEL_PT_NORETCOMP_BIT];
	pt->have_sched_switch = itrace_info->priv[INTEL_PT_HAVE_SCHED_SWITCH];
	pt->snapshot_mode = itrace_info->priv[INTEL_PT_SNAPSHOT_MODE];
	pt->per_cpu_mmaps = itrace_info->priv[INTEL_PT_PER_CPU_MMAPS];
	intel_pt_print_info(&itrace_info->priv[0], INTEL_PT_PMU_TYPE,
			    INTEL_PT_PER_CPU_MMAPS);

	pt->timeless_decoding = intel_pt_timeless_decoding(pt);
	pt->have_tsc = intel_pt_have_tsc(pt);
	pt->sampling_mode = intel_pt_sampling_mode(pt);
	pt->est_tsc = pt->per_cpu_mmaps && !pt->timeless_decoding;

	pt->unknown_thread = thread__new(999999999, 999999999);
	if (!pt->unknown_thread) {
		err = -ENOMEM;
		goto err_free_queues;
	}
	err = thread__set_comm(pt->unknown_thread, "unknown", 0);
	if (err)
		goto err_delete_thread;
	if (thread__init_map_groups(pt->unknown_thread, pt->machine)) {
		err = -ENOMEM;
		goto err_delete_thread;
	}

	pt->itrace.process_event = intel_pt_process_event;
	pt->itrace.queue_event = intel_pt_queue_event;
	pt->itrace.process_itrace_event = intel_pt_process_itrace_event;
	pt->itrace.dump_itrace_sample = intel_pt_dump_sample;
	pt->itrace.flush_events = intel_pt_flush;
	pt->itrace.free_events = intel_pt_free_events;
	pt->itrace.free = intel_pt_free;
	session->itrace = &pt->itrace;

	if (dump_trace)
		return 0;

	if (pt->have_sched_switch == 1) {
		pt->switch_evsel = intel_pt_find_sched_switch(session->evlist);
		if (!pt->switch_evsel) {
			pr_err("%s: missing sched_switch event\n", __func__);
			goto err_delete_thread;
		}
	}

	if (session->itrace_synth_opts && session->itrace_synth_opts->set) {
		pt->synth_opts = *session->itrace_synth_opts;
	} else {
		itrace_synth_opts__set_default(&pt->synth_opts);
		if (use_browser != -1) {
			pt->synth_opts.branches = false;
			pt->synth_opts.callchain = true;
		}
	}

	if (pt->synth_opts.log)
		intel_pt_log_enable();

	if (pt->synth_opts.calls)
		pt->branches_filter |= PERF_IP_FLAG_CALL | PERF_IP_FLAG_ASYNC |
				       PERF_IP_FLAG_TRACE_END;
	if (pt->synth_opts.returns)
		pt->branches_filter |= PERF_IP_FLAG_RETURN |
				       PERF_IP_FLAG_TRACE_BEGIN;

	if (pt->synth_opts.callchain && !symbol_conf.use_callchain) {
		symbol_conf.use_callchain = true;
		if (callchain_register_param(&callchain_param) < 0) {
			symbol_conf.use_callchain = false;
			pt->synth_opts.callchain = false;
		}
	}

	err = intel_pt_synth_events(pt, session, tool);
	if (err)
		goto err_delete_thread;

	err = itrace_queues__process_index(&pt->queues, session);
	if (err)
		goto err_delete_thread;

	if (pt->queues.populated)
		pt->data_queued = true;

	if (pt->timeless_decoding)
		pr_debug2("Intel PT decoding without timestamps\n");

	return 0;

err_delete_thread:
	thread__delete(pt->unknown_thread);
err_free_queues:
	intel_pt_log_disable();
	itrace_queues__free(&pt->queues);
	session->itrace = NULL;
err_free:
	free(pt);
	return err;
}

static int intel_pt_parse_terms_with_default(struct list_head *formats,
					     const char *str,
					     u64 *config)
{
	struct list_head *terms;
	struct perf_event_attr attr = {0};
	int err;

	terms = malloc(sizeof(struct list_head));
	if (!terms)
		return -ENOMEM;

	INIT_LIST_HEAD(terms);

	err = parse_events_terms(terms, str);
	if (err)
		goto out_free;

	attr.config = *config;
	err = perf_pmu__config_terms(formats, &attr, terms, true);
	if (err)
		goto out_free;

	*config = attr.config;
out_free:
	parse_events__free_terms(terms);
	return err;
}

static int intel_pt_parse_terms(struct list_head *formats, const char *str,
				u64 *config)
{
	*config = 0;
	return intel_pt_parse_terms_with_default(formats, str, config);
}

static size_t intel_pt_psb_period(struct perf_pmu *intel_pt_pmu __maybe_unused,
				  struct perf_evlist *evlist __maybe_unused)
{
	return 256;
}

static u64 intel_pt_default_config(struct perf_pmu *intel_pt_pmu)
{
	u64 config;

	intel_pt_parse_terms(&intel_pt_pmu->format, "tsc", &config);
	return config;
}

static int intel_pt_parse_sample_options(struct itrace_record *itr,
					 size_t sample_size,
					 struct record_opts *opts,
					 const char *str)
{
	struct intel_pt_recording *ptr =
			container_of(itr, struct intel_pt_recording, itr);
	struct perf_pmu *intel_pt_pmu = ptr->intel_pt_pmu;
	u64 *itrace_sample_config = &opts->itrace_sample_config;
	int err;

	opts->itrace_sample_size = sample_size;
	if (opts->itrace_sample_size > INTEL_PT_MAX_SAMPLE_SIZE) {
		pr_err("Intel Processor Trace: sample size too big\n");
		return -1;
	}

	*itrace_sample_config = intel_pt_default_config(intel_pt_pmu);
	opts->itrace_sample_type = intel_pt_pmu->type;
	opts->sample_itrace = true;

	if (!str || !*str)
		return 0;

	err = intel_pt_parse_terms_with_default(&intel_pt_pmu->format, str,
						itrace_sample_config);
	if (err)
		goto bad_options;

	return 0;

bad_options:
	pr_err("Intel Processor Trace: bad sampling options \"%s\"\n", str);
	return -1;
}

static int intel_pt_parse_snapshot_options(struct itrace_record *itr,
					   struct record_opts *opts,
					   const char *str)
{
	struct intel_pt_recording *ptr =
			container_of(itr, struct intel_pt_recording, itr);
	unsigned long long snapshot_size = 0;
	char *endptr;

	if (str) {
		snapshot_size = strtoull(str, &endptr, 0);
		if (*endptr || snapshot_size > SIZE_MAX)
			return -1;
	}

	opts->itrace_snapshot_mode = true;
	opts->itrace_snapshot_size = snapshot_size;

	ptr->snapshot_size = snapshot_size;

	return 0;
}

struct perf_event_attr *
intel_pt_pmu_default_config(struct perf_pmu *intel_pt_pmu)
{
	struct perf_event_attr *attr;

	attr = zalloc(sizeof(struct perf_event_attr));
	if (!attr)
		return NULL;

	attr->config = intel_pt_default_config(intel_pt_pmu);

	intel_pt_pmu->selectable = true;

	return attr;
}

static size_t intel_pt_info_priv_size(struct itrace_record *itr __maybe_unused)
{
	return sizeof(intel_pt_itrace_info_priv);
}

static int intel_pt_info_fill(struct itrace_record *itr,
			      struct perf_session *session,
			      struct itrace_info_event *itrace_info,
			      size_t priv_size)
{
	struct intel_pt_recording *ptr =
			container_of(itr, struct intel_pt_recording, itr);
	struct perf_pmu *intel_pt_pmu = ptr->intel_pt_pmu;
	struct perf_event_mmap_page *pc;
	struct perf_tsc_conversion tc = {0};
	bool cap_user_time_zero = false, per_cpu_mmaps;
	u64 tsc_bit, noretcomp_bit;
	int err;

	if (priv_size != sizeof(intel_pt_itrace_info_priv))
		return -EINVAL;

	intel_pt_parse_terms(&intel_pt_pmu->format, "tsc", &tsc_bit);
	intel_pt_parse_terms(&intel_pt_pmu->format, "noretcomp",
			     &noretcomp_bit);

	if (!session->evlist->nr_mmaps)
		return -EINVAL;

	pc = session->evlist->mmap[0].base;
	if (pc) {
		err = perf_read_tsc_conversion(pc, &tc);
		if (err) {
			if (err != -EOPNOTSUPP)
				return err;
		} else {
			cap_user_time_zero = tc.time_mult != 0;
		}
		if (!cap_user_time_zero)
			ui__warning("Intel Processor Trace: TSC not available\n");
	}

	per_cpu_mmaps = !cpu_map__empty(session->evlist->cpus);

	itrace_info->type = PERF_ITRACE_INTEL_PT;
	itrace_info->priv[INTEL_PT_PMU_TYPE] = intel_pt_pmu->type;
	itrace_info->priv[INTEL_PT_TIME_SHIFT] = tc.time_shift;
	itrace_info->priv[INTEL_PT_TIME_MULT] = tc.time_mult;
	itrace_info->priv[INTEL_PT_TIME_ZERO] = tc.time_zero;
	itrace_info->priv[INTEL_PT_CAP_USER_TIME_ZERO] = cap_user_time_zero;
	itrace_info->priv[INTEL_PT_TSC_BIT] = tsc_bit;
	itrace_info->priv[INTEL_PT_NORETCOMP_BIT] = noretcomp_bit;
	itrace_info->priv[INTEL_PT_HAVE_SCHED_SWITCH] = ptr->have_sched_switch;
	itrace_info->priv[INTEL_PT_SNAPSHOT_MODE] = ptr->snapshot_mode;
	itrace_info->priv[INTEL_PT_PER_CPU_MMAPS] = per_cpu_mmaps;

	return 0;
}

static int intel_pt_track_switches(struct perf_evlist *evlist)
{
	const char *sched_switch = "sched:sched_switch";
	struct perf_evsel *evsel;
	int err;

	if (!perf_evlist__can_select_event(evlist, sched_switch))
		return -EPERM;

	err = parse_events(evlist, sched_switch);
	if (err) {
		pr_debug2("%s: failed to parse %s, error %d\n",
			  __func__, sched_switch, err);
		return err;
	}

	evsel = perf_evlist__last(evlist);

	perf_evsel__set_sample_bit(evsel, CPU);
	perf_evsel__set_sample_bit(evsel, TIME);

	evsel->system_wide = true;
	evsel->no_aux_samples = true;
	evsel->immediate = true;

	return 0;
}

static int intel_pt_recording_options(struct itrace_record *itr,
				      struct perf_evlist *evlist,
				      struct record_opts *opts)
{
	struct intel_pt_recording *ptr =
			container_of(itr, struct intel_pt_recording, itr);
	struct perf_pmu *intel_pt_pmu = ptr->intel_pt_pmu;
	bool have_timing_info;
	struct perf_evsel *evsel, *intel_pt_evsel = NULL;
	const struct cpu_map *cpus = evlist->cpus;
	bool privileged = geteuid() == 0 || perf_event_paranoid() < 0;
	u64 tsc_bit;

	ptr->evlist = evlist;
	ptr->snapshot_mode = opts->itrace_snapshot_mode;

	list_for_each_entry(evsel, &evlist->entries, node) {
		if (evsel->attr.type == intel_pt_pmu->type) {
			if (intel_pt_evsel) {
				pr_err("There may be only one " INTEL_PT_PMU_NAME " event\n");
				return -EINVAL;
			}
			evsel->attr.freq = 0;
			evsel->attr.sample_period = 1;
			intel_pt_evsel = evsel;
			opts->full_itrace = true;
		}
	}

	if (opts->itrace_snapshot_mode && !opts->full_itrace) {
		pr_err("Snapshot mode (-S option) requires " INTEL_PT_PMU_NAME " PMU event (-e " INTEL_PT_PMU_NAME ")\n");
		return -EINVAL;
	}

	if (!opts->full_itrace && !opts->sample_itrace)
		return 0;

	if (opts->full_itrace && opts->sample_itrace) {
		pr_err("Full trace (" INTEL_PT_PMU_NAME " PMU) and sample trace (-I option) cannot be used together\n");
		return -EINVAL;
	}

	/* Set default size for sample mode */
	if (opts->sample_itrace) {
		size_t psb_period = intel_pt_psb_period(intel_pt_pmu, evlist);

		if (!opts->itrace_sample_size)
			opts->itrace_sample_size = INTEL_PT_DEFAULT_SAMPLE_SIZE;
		pr_debug2("Intel PT sample size: %zu\n",
			  opts->itrace_sample_size);
		if (psb_period &&
		    opts->itrace_sample_size <= psb_period +
						INTEL_PT_PSB_PERIOD_NEAR)
			ui__warning("Intel PT sample size (%zu) may be too small for PSB period (%zu)\n",
				    opts->itrace_sample_size, psb_period);
	}

	/* Set default sizes for snapshot mode */
	if (opts->itrace_snapshot_mode) {
		size_t psb_period = intel_pt_psb_period(intel_pt_pmu, evlist);

		if (!opts->itrace_snapshot_size && !opts->itrace_mmap_pages) {
			if (privileged) {
				opts->itrace_mmap_pages = MiB(4) / page_size;
			} else {
				opts->itrace_mmap_pages = KiB(128) / page_size;
				if (opts->mmap_pages == UINT_MAX)
					opts->mmap_pages = KiB(256) / page_size;
			}
		} else if (!opts->itrace_mmap_pages && !privileged &&
			   opts->mmap_pages == UINT_MAX) {
			opts->mmap_pages = KiB(256) / page_size;
		}
		if (!opts->itrace_snapshot_size)
			opts->itrace_snapshot_size =
				opts->itrace_mmap_pages * (size_t)page_size;
		if (!opts->itrace_mmap_pages) {
			size_t sz = opts->itrace_snapshot_size;

			sz = round_up(sz, page_size) / page_size;
			opts->itrace_mmap_pages = next_pow2_l(sz);
		}
		if (opts->itrace_snapshot_size >
				opts->itrace_mmap_pages * (size_t)page_size) {
			pr_err("Snapshot size %zu must not be greater than instruction tracing mmap size %zu\n",
			       opts->itrace_snapshot_size,
			       opts->itrace_mmap_pages * (size_t)page_size);
			return -EINVAL;
		}
		if (!opts->itrace_snapshot_size || !opts->itrace_mmap_pages) {
			pr_err("Failed to calculate default snapshot size and/or instruction tracing mmap pages\n");
			return -EINVAL;
		}
		pr_debug2("Intel PT snapshot size: %zu\n",
			  opts->itrace_snapshot_size);
		if (psb_period &&
		    opts->itrace_snapshot_size <= psb_period +
						  INTEL_PT_PSB_PERIOD_NEAR)
			ui__warning("Intel PT snapshot size (%zu) may be too small for PSB period (%zu)\n",
				    opts->itrace_sample_size, psb_period);
	}

	/* Set default sizes for full trace mode */
	if (opts->full_itrace && !opts->itrace_mmap_pages) {
		if (privileged) {
			opts->itrace_mmap_pages = MiB(4) / page_size;
		} else {
			opts->itrace_mmap_pages = KiB(128) / page_size;
			if (opts->mmap_pages == UINT_MAX)
				opts->mmap_pages = KiB(256) / page_size;
		}
	}

	/* Validate itrace_mmap_pages */
	if (opts->itrace_mmap_pages) {
		size_t sz = opts->itrace_mmap_pages * (size_t)page_size;
		size_t min_sz;

		if (opts->itrace_snapshot_mode)
			min_sz = KiB(4);
		else
			min_sz = KiB(8);

		if (sz < min_sz || !is_power_of_2(sz)) {
			pr_err("Invalid mmap size for Intel Processor Trace: must be at least %zuKiB and a power of 2\n",
			       min_sz / 1024);
			return -EINVAL;
		}
	}

	intel_pt_parse_terms(&intel_pt_pmu->format, "tsc", &tsc_bit);

	if ((opts->sample_itrace && (opts->itrace_sample_config & tsc_bit)) ||
	    (opts->full_itrace && (intel_pt_evsel->attr.config & tsc_bit)))
		have_timing_info = true;
	else
		have_timing_info = false;

	/*
	 * Per-cpu recording needs sched_switch events to distinguish different
	 * threads.
	 */
	if (have_timing_info && !cpu_map__empty(cpus)) {
		int err;

		err = intel_pt_track_switches(evlist);
		if (err == -EPERM)
			pr_debug2("Unable to select sched:sched_switch\n");
		else if (err)
			return err;
		else
			ptr->have_sched_switch = 1;
	}

	if (intel_pt_evsel) {
		/*
		 * To obtain the itrace buffer file descriptor, the itrace event
		 * must come first.
		 */
		perf_evlist__to_front(evlist, intel_pt_evsel);
		/*
		 * In the case of per-cpu mmaps, we need the CPU on the
		 * AUX event.
		 */
		if (!cpu_map__empty(cpus))
			perf_evsel__set_sample_bit(intel_pt_evsel, CPU);
	}

	/* Add dummy event to keep tracking */
	if (opts->full_itrace) {
		struct perf_evsel *tracking_evsel;
		int err;

		err = parse_events(evlist, "dummy:u");
		if (err)
			return err;

		tracking_evsel = perf_evlist__last(evlist);

		perf_evlist__set_tracking_event(evlist, tracking_evsel);

		tracking_evsel->attr.freq = 0;
		tracking_evsel->attr.sample_period = 1;

		/* In per-cpu case, always need the time of mmap events etc */
		if (!cpu_map__empty(cpus))
			perf_evsel__set_sample_bit(tracking_evsel, TIME);
	}

	/*
	 * Warn the user when we do not have enough information to decode i.e.
	 * per-cpu with no sched_switch (except workload-only).
	 */
	if (!ptr->have_sched_switch && !opts->sample_itrace &&
	    !cpu_map__empty(cpus) && !target__none(&opts->target))
		ui__warning("Intel Processor Trace decoding will not be possible except for kernel tracing!\n");

	return 0;
}

static int intel_pt_snapshot_start(struct itrace_record *itr)
{
	struct intel_pt_recording *ptr =
			container_of(itr, struct intel_pt_recording, itr);
	struct perf_evsel *evsel;

	list_for_each_entry(evsel, &ptr->evlist->entries, node) {
		if (evsel->attr.type == ptr->intel_pt_pmu->type)
			return perf_evlist__disable_event(ptr->evlist, evsel);
	}
	return -EINVAL;
}

static int intel_pt_snapshot_finish(struct itrace_record *itr)
{
	struct intel_pt_recording *ptr =
			container_of(itr, struct intel_pt_recording, itr);
	struct perf_evsel *evsel;

	list_for_each_entry(evsel, &ptr->evlist->entries, node) {
		if (evsel->attr.type == ptr->intel_pt_pmu->type)
			return perf_evlist__enable_event(ptr->evlist, evsel);
	}
	return -EINVAL;
}

static int intel_pt_alloc_snapshot_refs(struct intel_pt_recording *ptr, int idx)
{
	const size_t sz = sizeof(struct intel_pt_snapshot_ref);
	int cnt = ptr->snapshot_ref_cnt, new_cnt = cnt * 2;
	struct intel_pt_snapshot_ref *refs;

	if (!new_cnt)
		new_cnt = 16;

	while (new_cnt <= idx)
		new_cnt *= 2;

	refs = calloc(new_cnt, sz);
	if (!refs)
		return -ENOMEM;

	memcpy(refs, ptr->snapshot_refs, cnt * sz);

	ptr->snapshot_refs = refs;
	ptr->snapshot_ref_cnt = new_cnt;

	return 0;
}

static void intel_pt_free_snapshot_refs(struct intel_pt_recording *ptr)
{
	int i;

	for (i = 0; i < ptr->snapshot_ref_cnt; i++)
		free(ptr->snapshot_refs[i].ref_buf);
	free(ptr->snapshot_refs);
}

static void intel_pt_recording_free(struct itrace_record *itr)
{
	struct intel_pt_recording *ptr =
			container_of(itr, struct intel_pt_recording, itr);

	intel_pt_free_snapshot_refs(ptr);
	free(ptr);
}

static int intel_pt_alloc_snapshot_ref(struct intel_pt_recording *ptr, int idx,
				       size_t snapshot_buf_size)
{
	size_t ref_buf_size = ptr->snapshot_ref_buf_size;
	void *ref_buf;

	ref_buf = zalloc(ref_buf_size);
	if (!ref_buf)
		return -ENOMEM;

	ptr->snapshot_refs[idx].ref_buf = ref_buf;
	ptr->snapshot_refs[idx].ref_offset = snapshot_buf_size - ref_buf_size;

	return 0;
}

static size_t intel_pt_snapshot_ref_buf_size(struct intel_pt_recording *ptr,
					     size_t snapshot_buf_size)
{
	const size_t max_size = 256 * 1024;
	size_t buf_size = 0, psb_period;

	if (ptr->snapshot_size <= 64 * 1024)
		return 0;

	psb_period = intel_pt_psb_period(ptr->intel_pt_pmu, ptr->evlist);
	if (psb_period)
		buf_size = psb_period * 2;

	if (!buf_size || buf_size > max_size)
		buf_size = max_size;

	if (buf_size >= snapshot_buf_size)
		return 0;

	if (buf_size >= ptr->snapshot_size / 2)
		return 0;

	return buf_size;
}

static int intel_pt_snapshot_init(struct intel_pt_recording *ptr,
				  size_t snapshot_buf_size)
{
	if (ptr->snapshot_init_done)
		return 0;

	ptr->snapshot_init_done = true;

	ptr->snapshot_ref_buf_size = intel_pt_snapshot_ref_buf_size(ptr,
							snapshot_buf_size);

	return 0;
}

/**
 * intel_pt_compare_buffers - compare bytes in a buffer to a circular buffer.
 * @buf1: first buffer
 * @compare_size: number of bytes to compare
 * @buf2: second buffer (a circular buffer)
 * @offs2: offset in second buffer
 * @buf2_size: size of second buffer
 *
 * The comparison allows for the possibility that the bytes to compare in the
 * circular buffer are not contiguous.  It is assumed that @compare_size <=
 * @buf2_size.  This function returns %false if the bytes are identical, %true
 * otherwise.
 */
static bool intel_pt_compare_buffers(void *buf1, size_t compare_size,
				     void *buf2, size_t offs2, size_t buf2_size)
{
	size_t end2 = offs2 + compare_size, part_size;

	if (end2 <= buf2_size)
		return memcmp(buf1, buf2 + offs2, compare_size);

	part_size = end2 - buf2_size;
	if (memcmp(buf1, buf2 + offs2, part_size))
		return true;

	compare_size -= part_size;

	return memcmp(buf1 + part_size, buf2, compare_size);
}

static bool intel_pt_compare_ref(void *ref_buf, size_t ref_offset,
				 size_t ref_size, size_t buf_size,
				 void *data, size_t head)
{
	size_t ref_end = ref_offset + ref_size;

	if (ref_end > buf_size) {
		if (head > ref_offset || head < ref_end - buf_size)
			return true;
	} else if (head > ref_offset && head < ref_end) {
		return true;
	}

	return intel_pt_compare_buffers(ref_buf, ref_size, data, ref_offset,
					buf_size);
}

static void intel_pt_copy_ref(void *ref_buf, size_t ref_size, size_t buf_size,
			      void *data, size_t head)
{
	if (head >= ref_size) {
		memcpy(ref_buf, data + head - ref_size, ref_size);
	} else {
		memcpy(ref_buf, data, head);
		ref_size -= head;
		memcpy(ref_buf + head, data + buf_size - ref_size, ref_size);
	}
}

static bool intel_pt_wrapped(struct intel_pt_recording *ptr, int idx,
			     struct itrace_mmap *mm, unsigned char *data,
			     u64 head)
{
	struct intel_pt_snapshot_ref *ref = &ptr->snapshot_refs[idx];
	bool wrapped;

	wrapped = intel_pt_compare_ref(ref->ref_buf, ref->ref_offset,
				       ptr->snapshot_ref_buf_size, mm->len,
				       data, head);

	intel_pt_copy_ref(ref->ref_buf, ptr->snapshot_ref_buf_size, mm->len,
			  data, head);

	return wrapped;
}

static bool intel_pt_first_wrap(u64 *data, size_t buf_size)
{
	int i, a, b;

	b = buf_size >> 3;
	a = b - 512;
	if (a < 0)
		a = 0;

	for (i = a; i < b; i++) {
		if (data[i])
			return true;
	}

	return false;
}

static int intel_pt_find_snapshot(struct itrace_record *itr, int idx,
				  struct itrace_mmap *mm, unsigned char *data,
				  u64 *head, u64 *old)
{
	struct intel_pt_recording *ptr =
			container_of(itr, struct intel_pt_recording, itr);
	bool wrapped;
	int err;

	pr_debug3("%s: mmap index %d old head %zu new head %zu\n",
		  __func__, idx, (size_t)*old, (size_t)*head);

	err = intel_pt_snapshot_init(ptr, mm->len);
	if (err)
		goto out_err;

	if (idx >= ptr->snapshot_ref_cnt) {
		err = intel_pt_alloc_snapshot_refs(ptr, idx);
		if (err)
			goto out_err;
	}

	if (ptr->snapshot_ref_buf_size) {
		if (!ptr->snapshot_refs[idx].ref_buf) {
			err = intel_pt_alloc_snapshot_ref(ptr, idx, mm->len);
			if (err)
				goto out_err;
		}
		wrapped = intel_pt_wrapped(ptr, idx, mm, data, *head);
	} else {
		wrapped = ptr->snapshot_refs[idx].wrapped;
		if (!wrapped && intel_pt_first_wrap((u64 *)data, mm->len)) {
			ptr->snapshot_refs[idx].wrapped = true;
			wrapped = true;
		}
	}

	/*
	 * In full trace mode 'head' continually increases.  However in snapshot
	 * mode 'head' is an offset within the buffer.  Here 'old' and 'head'
	 * are adjusted to match the full trace case which expects that 'old' is
	 * always less than 'head'.
	 */
	if (wrapped) {
		*old = *head;
		*head += mm->len;
	} else {
		if (mm->mask)
			*old &= mm->mask;
		else
			*old %= mm->len;
		if (*old > *head)
			*head += mm->len;
	}

	pr_debug3("%s: wrap-around %sdetected, adjusted old head %zu adjusted new head %zu\n",
		  __func__, wrapped ? "" : "not ", (size_t)*old, (size_t)*head);

	return 0;

out_err:
	pr_err("%s: failed, error %d\n", __func__, err);
	return err;
}

static u64 intel_pt_reference(struct itrace_record *itr __maybe_unused)
{
	return rdtsc();
}

static int intel_pt_read_finish(struct itrace_record *itr, int idx)
{
	struct intel_pt_recording *ptr =
			container_of(itr, struct intel_pt_recording, itr);
	struct perf_evsel *evsel;

	list_for_each_entry(evsel, &ptr->evlist->entries, node) {
		if (evsel->attr.type == ptr->intel_pt_pmu->type)
			return perf_evlist__enable_event_idx(ptr->evlist, evsel,
							     idx);
	}
	return -EINVAL;
}

struct itrace_record *intel_pt_recording_init(int *err)
{
	struct perf_pmu *intel_pt_pmu = perf_pmu__find(INTEL_PT_PMU_NAME);
	struct intel_pt_recording *ptr;

	if (!intel_pt_pmu)
		return NULL;

	ptr = zalloc(sizeof(struct intel_pt_recording));
	if (!ptr) {
		*err = -ENOMEM;
		return NULL;
	}

	ptr->intel_pt_pmu = intel_pt_pmu;
	ptr->itr.parse_sample_options = intel_pt_parse_sample_options;
	ptr->itr.recording_options = intel_pt_recording_options;
	ptr->itr.info_priv_size = intel_pt_info_priv_size;
	ptr->itr.info_fill = intel_pt_info_fill;
	ptr->itr.free = intel_pt_recording_free;
	ptr->itr.snapshot_start = intel_pt_snapshot_start;
	ptr->itr.snapshot_finish = intel_pt_snapshot_finish;
	ptr->itr.find_snapshot = intel_pt_find_snapshot;
	ptr->itr.parse_snapshot_options = intel_pt_parse_snapshot_options;
	ptr->itr.reference = intel_pt_reference;
	ptr->itr.read_finish = intel_pt_read_finish;
	return &ptr->itr;
}
