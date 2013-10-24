/*
 * itrace.h: Instruction Tracing support
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

#ifndef __PERF_ITRACE_H
#define __PERF_ITRACE_H

#include <sys/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <linux/perf_event.h>
#include <linux/types.h>

#include "../perf.h"

union perf_event;
struct perf_session;
struct perf_evlist;
struct perf_tool;
struct record_opts;
struct itrace_info_event;

/**
 * struct itrace_mmap - records an mmap of the itrace buffer.
 * @base: address of mapped area
 * @userpg: pointer to buffer's perf_event_mmap_page
 * @mask: %0 if @len is not a power of two, otherwise (@len - %1)
 * @len: size of mapped area
 * @prev: previous aux_head
 * @idx: index of this mmap
 * @tid: tid for a per-thread mmap (also set if there is only 1 tid on a per-cpu
 *       mmap) otherwise %0
 * @cpu: cpu number for a per-cpu mmap otherwise %-1
 */
struct itrace_mmap {
	void		*base;
	void		*userpg;
	size_t		mask;
	size_t		len;
	u64		prev;
	int		idx;
	pid_t		tid;
	int		cpu;
};

/**
 * struct itrace_mmap_params - parameters to set up struct itrace_mmap.
 * @mask: %0 if @len is not a power of two, otherwise (@len - %1)
 * @offset: file offset of mapped area
 * @len: size of mapped area
 * @prot: mmap memory protection
 * @idx: index of this mmap
 * @tid: tid for a per-thread mmap (also set if there is only 1 tid on a per-cpu
 *       mmap) otherwise %0
 * @cpu: cpu number for a per-cpu mmap otherwise %-1
 */
struct itrace_mmap_params {
	size_t		mask;
	off_t		offset;
	size_t		len;
	int		prot;
	int		idx;
	pid_t		tid;
	int		cpu;
};

/**
 * struct itrace_record - callbacks for recording Instruction Trace data.
 * @recording_options: validate and process recording options
 * @info_priv_size: return the size of the private data in itrace_info_event
 * @info_fill: fill-in the private data in itrace_info_event
 * @free: free this itrace record structure
 * @reference: provide a 64-bit reference number for itrace_event
 * @read_finish: called after reading from an itrace mmap
 */
struct itrace_record {
	int (*recording_options)(struct itrace_record *itr,
				 struct perf_evlist *evlist,
				 struct record_opts *opts);
	size_t (*info_priv_size)(struct itrace_record *itr);
	int (*info_fill)(struct itrace_record *itr,
			 struct perf_session *session,
			 struct itrace_info_event *itrace_info,
			 size_t priv_size);
	void (*free)(struct itrace_record *itr);
	u64 (*reference)(struct itrace_record *itr);
	int (*read_finish)(struct itrace_record *itr, int idx);
};

static inline u64 itrace_mmap__read_head(struct itrace_mmap *mm __maybe_unused)
{
	/* Not yet implemented */
	return 0;
}

static inline void itrace_mmap__write_tail(struct itrace_mmap *mm __maybe_unused,
					   u64 tail __maybe_unused)
{
	/* Not yet implemented */
}

int itrace_mmap__mmap(struct itrace_mmap *mm,
		      struct itrace_mmap_params *mp,
		      void *userpg, int fd);
void itrace_mmap__munmap(struct itrace_mmap *mm);
void itrace_mmap_params__init(struct itrace_mmap_params *mp,
			      off_t itrace_offset,
			      unsigned int itrace_pages, bool itrace_overwrite);
void itrace_mmap_params__set_idx(struct itrace_mmap_params *mp,
				 struct perf_evlist *evlist, int idx,
				 bool per_cpu);

typedef int (*process_itrace_t)(struct perf_tool *tool, union perf_event *event,
				void *data1, size_t len1, void *data2,
				size_t len2);

int itrace_mmap__read(struct itrace_mmap *mm, struct itrace_record *itr,
		      struct perf_tool *tool, process_itrace_t fn);

struct itrace_record *itrace_record__init(struct perf_evlist *evlist, int *err);

int itrace_record__options(struct itrace_record *itr,
			   struct perf_evlist *evlist,
			   struct record_opts *opts);
size_t itrace_record__info_priv_size(struct itrace_record *itr);
int itrace_record__info_fill(struct itrace_record *itr,
			     struct perf_session *session,
			     struct itrace_info_event *itrace_info,
			     size_t priv_size);
void itrace_record__free(struct itrace_record *itr);
u64 itrace_record__reference(struct itrace_record *itr);

int perf_event__synthesize_itrace_info(struct itrace_record *itr,
				       struct perf_tool *tool,
				       struct perf_session *session,
				       perf_event__handler_t process);
int perf_event__synthesize_itrace(struct perf_tool *tool,
				  perf_event__handler_t process,
				  size_t size, u64 offset, u64 ref, int idx,
				  u32 tid, u32 cpu);

#endif
