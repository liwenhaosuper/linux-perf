/*
 * itrace.c: Instruction Tracing support
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

#include <sys/types.h>
#include <sys/mman.h>
#include <stdbool.h>

#include <linux/kernel.h>
#include <linux/perf_event.h>
#include <linux/types.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "../perf.h"
#include "util.h"
#include "evlist.h"
#include "cpumap.h"
#include "thread_map.h"
#include "itrace.h"

#include "event.h"
#include "debug.h"
#include "parse-options.h"

int itrace_mmap__mmap(struct itrace_mmap *mm, struct itrace_mmap_params *mp,
		      void *userpg, int fd)
{
#if BITS_PER_LONG != 64 && !defined(HAVE_SYNC_COMPARE_AND_SWAP_SUPPORT)
	pr_err("Cannot use Instruction Tracing mmaps\n");
	return -1;
#endif

	mm->userpg = userpg;
	mm->mask = mp->mask;
	mm->len = mp->len;
	mm->prev = 0;
	mm->idx = mp->idx;
	mm->tid = mp->tid;
	mm->cpu = mp->cpu;

	if (!mp->len) {
		mm->base = NULL;
		return 0;
	}

	mm->base = mmap(NULL, mp->len, mp->prot, MAP_SHARED, fd, mp->offset);
	if (mm->base == MAP_FAILED) {
		pr_debug2("failed to mmap itrace ring buffer\n");
		mm->base = NULL;
		return -1;
	}

	return 0;
}

void itrace_mmap__munmap(struct itrace_mmap *mm)
{
	if (mm->base)
		munmap(mm->base, mm->len);
}

void itrace_mmap_params__init(struct itrace_mmap_params *mp,
			      off_t itrace_offset,
			      unsigned int itrace_pages, bool itrace_overwrite)
{
	if (itrace_pages) {
		mp->offset = itrace_offset;
		mp->len = itrace_pages * (size_t)page_size;
		mp->mask = is_power_of_2(mp->len) ? mp->len - 1 : 0;
		mp->prot = PROT_READ | (itrace_overwrite ? 0 : PROT_WRITE);
		pr_debug2("itrace mmap length %zu\n", mp->len);
	} else {
		mp->len = 0;
	}
}

void itrace_mmap_params__set_idx(struct itrace_mmap_params *mp,
				 struct perf_evlist *evlist, int idx,
				 bool per_cpu)
{
	mp->idx = idx;

	if (per_cpu) {
		mp->cpu = evlist->cpus->map[idx];
		if (evlist->threads)
			mp->tid = evlist->threads->map[0];
		else
			mp->tid = -1;
	} else {
		mp->cpu = -1;
		mp->tid = evlist->threads->map[idx];
	}
}

size_t itrace_record__info_priv_size(struct itrace_record *itr)
{
	if (itr)
		return itr->info_priv_size(itr);
	return 0;
}

static int itrace_not_supported(void)
{
	pr_err("Instruction tracing is not supported on this architecture\n");
	return -EINVAL;
}

int itrace_record__info_fill(struct itrace_record *itr,
			     struct perf_session *session,
			     struct itrace_info_event *itrace_info,
			     size_t priv_size)
{
	if (itr)
		return itr->info_fill(itr, session, itrace_info, priv_size);
	return itrace_not_supported();
}

void itrace_record__free(struct itrace_record *itr)
{
	if (itr)
		itr->free(itr);
}

int itrace_record__options(struct itrace_record *itr,
			   struct perf_evlist *evlist,
			   struct record_opts *opts)
{
	if (itr)
		return itr->recording_options(itr, evlist, opts);
	return 0;
}

u64 itrace_record__reference(struct itrace_record *itr)
{
	if (itr)
		return itr->reference(itr);
	return 0;
}

struct itrace_record *__weak
itrace_record__init(struct perf_evlist *evlist __maybe_unused, int *err)
{
	*err = 0;
	return NULL;
}

int perf_event__synthesize_itrace_info(struct itrace_record *itr,
				       struct perf_tool *tool,
				       struct perf_session *session,
				       perf_event__handler_t process)
{
	union perf_event *ev;
	size_t priv_size;
	int err;

	pr_debug2("Synthesizing itrace information\n");
	priv_size = itrace_record__info_priv_size(itr);
	ev = zalloc(sizeof(struct itrace_info_event) + priv_size);
	if (!ev)
		return -ENOMEM;

	ev->itrace_info.header.type = PERF_RECORD_ITRACE_INFO;
	ev->itrace_info.header.size = sizeof(struct itrace_info_event) +
				      priv_size;
	err = itrace_record__info_fill(itr, session, &ev->itrace_info,
				       priv_size);
	if (err)
		goto out_free;

	err = process(tool, ev, NULL, NULL);
out_free:
	free(ev);
	return err;
}

int perf_event__synthesize_itrace(struct perf_tool *tool,
				  perf_event__handler_t process,
				  size_t size, u64 offset, u64 ref, int idx,
				  u32 tid, u32 cpu)
{
	union perf_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.itrace.header.type = PERF_RECORD_ITRACE;
	ev.itrace.header.size = sizeof(ev.itrace);
	ev.itrace.size = size;
	ev.itrace.offset = offset;
	ev.itrace.reference = ref;
	ev.itrace.idx = idx;
	ev.itrace.tid = tid;
	ev.itrace.cpu = cpu;

	return process(tool, &ev, NULL, NULL);
}

#define PERF_ITRACE_DEFAULT_PERIOD_TYPE		PERF_ITRACE_PERIOD_NANOSECS
#define PERF_ITRACE_DEFAULT_PERIOD		100000
#define PERF_ITRACE_DEFAULT_CALLCHAIN_SZ	16
#define PERF_ITRACE_MAX_CALLCHAIN_SZ		1024

void itrace_synth_opts__set_default(struct itrace_synth_opts *synth_opts)
{
	synth_opts->instructions = true;
	synth_opts->branches = true;
	synth_opts->errors = true;
	synth_opts->period_type = PERF_ITRACE_DEFAULT_PERIOD_TYPE;
	synth_opts->period = PERF_ITRACE_DEFAULT_PERIOD;
	synth_opts->callchain_sz = PERF_ITRACE_DEFAULT_CALLCHAIN_SZ;
}

int itrace_parse_synth_opts(const struct option *opt, const char *str,
			    int unset)
{
	struct itrace_synth_opts *synth_opts = opt->value;
	const char *p;
	char *endptr;

	synth_opts->set = true;

	if (unset) {
		synth_opts->dont_decode = true;
		return 0;
	}

	if (!str) {
		itrace_synth_opts__set_default(synth_opts);
		return 0;
	}

	for (p = str; *p;) {
		switch (*p++) {
		case 'i':
			synth_opts->instructions = true;
			while (*p == ' ' || *p == ',')
				p += 1;
			if (isdigit(*p)) {
				synth_opts->period = strtoull(p, &endptr, 10);
				p = endptr;
				while (*p == ' ' || *p == ',')
					p += 1;
				switch (*p++) {
				case 'i':
					synth_opts->period_type =
						PERF_ITRACE_PERIOD_INSTRUCTIONS;
					break;
				case 't':
					synth_opts->period_type =
						PERF_ITRACE_PERIOD_TICKS;
					break;
				case 'm':
					synth_opts->period *= 1000;
					/* Fall through */
				case 'u':
					synth_opts->period *= 1000;
					/* Fall through */
				case 'n':
					if (*p++ != 's')
						goto out_err;
					synth_opts->period_type =
						PERF_ITRACE_PERIOD_NANOSECS;
					break;
				case '\0':
					goto out;
				default:
					goto out_err;
				}
			}
			break;
		case 'b':
			synth_opts->branches = true;
			break;
		case 'e':
			synth_opts->errors = true;
			break;
		case 'd':
			synth_opts->log = true;
			break;
		case 'c':
			synth_opts->branches = true;
			synth_opts->calls = true;
			break;
		case 'r':
			synth_opts->branches = true;
			synth_opts->returns = true;
			break;
		case 'g':
			synth_opts->instructions = true;
			synth_opts->callchain = true;
			synth_opts->callchain_sz =
					PERF_ITRACE_DEFAULT_CALLCHAIN_SZ;
			while (*p == ' ' || *p == ',')
				p += 1;
			if (isdigit(*p)) {
				unsigned int val;

				val = strtoul(p, &endptr, 10);
				p = endptr;
				if (!val || val > PERF_ITRACE_MAX_CALLCHAIN_SZ)
					goto out_err;
				synth_opts->callchain_sz = val;
			}
			break;
		case ' ':
		case ',':
			break;
		default:
			goto out_err;
		}
	}
out:
	if (synth_opts->instructions) {
		if (!synth_opts->period_type)
			synth_opts->period_type =
					PERF_ITRACE_DEFAULT_PERIOD_TYPE;
		if (!synth_opts->period)
			synth_opts->period = PERF_ITRACE_DEFAULT_PERIOD;
	}

	return 0;

out_err:
	pr_err("Bad instruction trace options '%s'\n", str);
	return -EINVAL;
}

int itrace_mmap__read(struct itrace_mmap *mm, struct itrace_record *itr,
		      struct perf_tool *tool, process_itrace_t fn)
{
	u64 head = itrace_mmap__read_head(mm);
	u64 old = mm->prev, offset, ref;
	unsigned char *data = mm->base;
	size_t size, head_off, old_off, len1, len2, padding;
	union perf_event ev;
	void *data1, *data2;

	if (old == head)
		return 0;

	pr_debug3("itrace idx %d old %#"PRIx64" head %#"PRIx64" diff %#"PRIx64"\n",
		  mm->idx, old, head, head - old);

	if (mm->mask) {
		head_off = head & mm->mask;
		old_off = old & mm->mask;
	} else {
		head_off = head % mm->len;
		old_off = old % mm->len;
	}

	if (head_off > old_off)
		size = head_off - old_off;
	else
		size = mm->len - (old_off - head_off);

	ref = itrace_record__reference(itr);

	if (head > old || size <= head || mm->mask) {
		offset = head - size;
	} else {
		/*
		 * When the buffer size is not a power of 2, 'head' wraps at the
		 * highest multiple of the buffer size, so we have to subtract
		 * the remainder here.
		 */
		u64 rem = (0ULL - mm->len) % mm->len;

		offset = head - size - rem;
	}

	if (size > head_off) {
		len1 = size - head_off;
		data1 = &data[mm->len - len1];
		len2 = head_off;
		data2 = &data[0];
	} else {
		len1 = size;
		data1 = &data[head_off - len1];
		len2 = 0;
		data2 = NULL;
	}

	/* padding must be written by fn() e.g. record__process_itrace() */
	padding = size & 7;
	if (padding)
		padding = 8 - padding;

	memset(&ev, 0, sizeof(ev));
	ev.itrace.header.type = PERF_RECORD_ITRACE;
	ev.itrace.header.size = sizeof(ev.itrace);
	ev.itrace.size = size + padding;
	ev.itrace.offset = offset;
	ev.itrace.reference = ref;
	ev.itrace.idx = mm->idx;
	ev.itrace.tid = mm->tid;
	ev.itrace.cpu = mm->cpu;

	if (fn(tool, &ev, data1, len1, data2, len2))
		return -1;

	mm->prev = head;

	itrace_mmap__write_tail(mm, head);
	if (itr->read_finish) {
		int err;

		err = itr->read_finish(itr, mm->idx);
		if (err < 0)
			return err;
	}

	return 1;
}
