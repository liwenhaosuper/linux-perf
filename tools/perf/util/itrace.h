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
#include <linux/list.h>
#include <linux/perf_event.h>
#include <linux/types.h>

#include "../perf.h"
#include "session.h"

union perf_event;
struct perf_session;
struct perf_evlist;
struct perf_tool;
struct option;
struct record_opts;
struct itrace_info_event;

enum itrace_type {
	PERF_ITRACE_UNKNOWN,
};

enum itrace_error_type {
	PERF_ITRACE_DECODER_ERROR = 1,
};

enum itrace_period_type {
	PERF_ITRACE_PERIOD_INSTRUCTIONS,
	PERF_ITRACE_PERIOD_TICKS,
	PERF_ITRACE_PERIOD_NANOSECS,
};

/**
 * struct itrace_synth_opts - Instruction Tracing synthesis options.
 * @set: indicates whether or not options have been set
 * @inject: indicates the event (not just the sample) must be fully synthesized
 *          because 'perf inject' will write it out
 * @instructions: whether to synthesize 'instructions' events
 * @branches: whether to synthesize 'branches' events
 * @errors: whether to synthesize decoder error events
 * @dont_decode: whether to skip decoding entirely
 * @log: write a decoding log
 * @calls: limit branch samples to calls (can be combined with @returns)
 * @returns: limit branch samples to returns (can be combined with @calls)
 * @callchain: add callchain to 'instructions' events
 * @callchain_sz: maximum callchain size
 * @period: 'instructions' events period
 * @period_type: 'instructions' events period type
 */
struct itrace_synth_opts {
	bool			set;
	bool			inject;
	bool			instructions;
	bool			branches;
	bool			errors;
	bool			dont_decode;
	bool			log;
	bool			calls;
	bool			returns;
	bool			callchain;
	unsigned int		callchain_sz;
	unsigned long long	period;
	enum itrace_period_type	period_type;
};

/**
 * struct itrace_index_entry - indexes a Instruction Tracing event within a
 *                             perf.data file.
 * @file_offset: offset within the perf.data file
 * @sz: size of the event
 */
struct itrace_index_entry {
	u64			file_offset;
	u64			sz;
};

#define PERF_ITRACE_INDEX_ENTRY_COUNT 256

/**
 * struct itrace_index - index of Instruction Tracing events within a perf.data
 *                       file.
 * @list: linking a number of arrays of entries
 * @nr: number of entries
 * @entries: array of entries
 */
struct itrace_index {
	struct list_head	list;
	size_t			nr;
	struct itrace_index_entry entries[PERF_ITRACE_INDEX_ENTRY_COUNT];
};

/**
 * struct itrace - session callbacks to allow Instruction Trace data decoding.
 * @process_event: lets the decoder see all session events
 * @flush_events: process any remaining data
 * @free_events: free resources associated with event processing
 * @free: free resources associated with the session
 * @error_count: number of errors
 */
struct itrace {
	int (*process_event)(struct perf_session *session,
			     union perf_event *event,
			     struct perf_sample *sample,
			     struct perf_tool *tool);
	int (*process_itrace_event)(struct perf_session *session,
				    union perf_event *event,
				    struct perf_tool *tool);
	int (*flush_events)(struct perf_session *session,
			    struct perf_tool *tool);
	void (*free_events)(struct perf_session *session);
	void (*free)(struct perf_session *session);
	unsigned long long error_count;
};

/**
 * struct itrace_buffer - a buffer containing Instruction Tracing data.
 * @list: buffers are queued in a list held by struct itrace_queue
 * @size: size of the buffer in bytes
 * @pid: in per-thread mode, the pid this buffer is associated with
 * @tid: in per-thread mode, the tid this buffer is associated with
 * @cpu: in per-cpu mode, the cpu this buffer is associated with
 * @data: actual buffer data (can be null if the data has not been loaded)
 * @data_offset: file offset at which the buffer can be read
 * @mmap_addr: mmap address at which the buffer can be read
 * @mmap_size: size of the mmap at @mmap_addr
 * @data_needs_freeing: @data was malloc'd so free it when it is no longer
 *                      needed
 * @consecutive: the original data was split up and this buffer is consecutive
 *               to the previous buffer
 * @offset: offset as determined by aux_head / aux_tail members of struct
 *          perf_event_mmap_page
 * @reference: an implementation-specific reference determined when the data is
 *             recorded
 * @buffer_nr: used to number each buffer
 * @use_size: implementation actually only uses this number of bytes
 * @use_data: implementation actually only uses data starting at this address
 */
struct itrace_buffer {
	struct list_head	list;
	size_t			size;
	pid_t			pid;
	pid_t			tid;
	int			cpu;
	void			*data;
	off_t			data_offset;
	void			*mmap_addr;
	size_t			mmap_size;
	bool			data_needs_freeing;
	bool			consecutive;
	u64			offset;
	u64			reference;
	u64			buffer_nr;
	size_t			use_size;
	void			*use_data;
};

/**
 * struct itrace_queue - a queue of Instruction Tracing data buffers.
 * @head: head of buffer list
 * @tid: in per-thread mode, the tid this queue is associated with
 * @cpu: in per-cpu mode, the cpu this queue is associated with
 * @set: %true once this queue has been dedicated to a specific thread or cpu
 * @priv: implementation-specific data
 */
struct itrace_queue {
	struct list_head	head;
	pid_t			tid;
	int			cpu;
	bool			set;
	void			*priv;
};

/**
 * struct itrace_queues - an array of Instruction Tracing queues.
 * @queue_array: array of queues
 * @nr_queues: number of queues
 * @new_data: set whenever new data is queued
 * @populated: queues have been fully populated using the itrace_index
 * @next_buffer_nr: used to number each buffer
 */
struct itrace_queues {
	struct itrace_queue	*queue_array;
	unsigned int		nr_queues;
	bool			new_data;
	bool			populated;
	u64			next_buffer_nr;
};

/**
 * struct itrace_heap_item - element of struct itrace_heap.
 * @queue_nr: queue number
 * @ordinal: value used for sorting (lowest ordinal is top of the heap) expected
 *           to be a timestamp
 */
struct itrace_heap_item {
	unsigned int		queue_nr;
	u64			ordinal;
};

/**
 * struct itrace_heap - a heap suitable for sorting Instruction Tracing queues.
 * @heap_array: the heap
 * @heap_cnt: the number of elements in the heap
 * @heap_sz: maximum number of elements (grows as needed)
 */
struct itrace_heap {
	struct itrace_heap_item	*heap_array;
	unsigned int		heap_cnt;
	unsigned int		heap_sz;
};

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

static inline u64 itrace_mmap__read_head(struct itrace_mmap *mm)
{
	struct perf_event_mmap_page *pc = mm->userpg;
#if BITS_PER_LONG == 64 || !defined(HAVE_SYNC_COMPARE_AND_SWAP_SUPPORT)
	u64 head = ACCESS_ONCE(pc->aux_head);
#else
	u64 head = __sync_val_compare_and_swap(&pc->aux_head, 0, 0);
#endif

	/* Ensure all reads are done after we read the head */
	rmb();
	return head;
}

static inline void itrace_mmap__write_tail(struct itrace_mmap *mm, u64 tail)
{
	struct perf_event_mmap_page *pc = mm->userpg;
#if BITS_PER_LONG != 64 && defined(HAVE_SYNC_COMPARE_AND_SWAP_SUPPORT)
	u64 old_tail;
#endif

	/* Ensure all reads are done before we write the tail out */
	mb();
#if BITS_PER_LONG == 64 || !defined(HAVE_SYNC_COMPARE_AND_SWAP_SUPPORT)
	pc->aux_tail = tail;
#else
	do {
		old_tail = __sync_val_compare_and_swap(&pc->aux_tail, 0, 0);
	} while (!__sync_bool_compare_and_swap(&pc->aux_tail, old_tail, tail));
#endif
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

int itrace_queues__init(struct itrace_queues *queues);
int itrace_queues__add_event(struct itrace_queues *queues,
			     struct perf_session *session,
			     union perf_event *event, off_t data_offset,
			     struct itrace_buffer **buffer_ptr);
void itrace_queues__free(struct itrace_queues *queues);
int itrace_queues__process_index(struct itrace_queues *queues,
				 struct perf_session *session);
struct itrace_buffer *itrace_buffer__next(struct itrace_queue *queue,
					  struct itrace_buffer *buffer);
void *itrace_buffer__get_data(struct itrace_buffer *buffer, int fd);
void itrace_buffer__put_data(struct itrace_buffer *buffer);
void itrace_buffer__drop_data(struct itrace_buffer *buffer);
void itrace_buffer__free(struct itrace_buffer *buffer);

int itrace_heap__add(struct itrace_heap *heap, unsigned int queue_nr,
		     u64 ordinal);
void itrace_heap__pop(struct itrace_heap *heap);
void itrace_heap__free(struct itrace_heap *heap);

struct itrace_cache_entry {
	struct hlist_node hash;
	u32 key;
};

struct itrace_cache *itrace_cache__new(unsigned int bits, size_t entry_size,
				       unsigned int limit_percent);
void itrace_cache__free(struct itrace_cache *itrace_cache);
void *itrace_cache__alloc_entry(struct itrace_cache *c);
void itrace_cache__free_entry(struct itrace_cache *c, void *entry);
int itrace_cache__add(struct itrace_cache *c, u32 key,
		      struct itrace_cache_entry *entry);
void *itrace_cache__lookup(struct itrace_cache *c, u32 key);

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

int itrace_index__itrace_event(struct list_head *head, union perf_event *event,
			       off_t file_offset);
int itrace_index__write(int fd, struct list_head *head);
int itrace_index__process(int fd, u64 size, struct perf_session *session,
			  bool needs_swap);
void itrace_index__free(struct list_head *head);

void itrace_synth_error(struct itrace_error_event *itrace_error, int type,
			int code, int cpu, pid_t pid, pid_t tid, u64 ip,
			const char *msg);

int perf_event__synthesize_itrace_info(struct itrace_record *itr,
				       struct perf_tool *tool,
				       struct perf_session *session,
				       perf_event__handler_t process);
int perf_event__process_itrace_info(struct perf_tool *tool,
				    union perf_event *event,
				    struct perf_session *session);
int perf_event__synthesize_itrace(struct perf_tool *tool,
				  perf_event__handler_t process,
				  size_t size, u64 offset, u64 ref, int idx,
				  u32 tid, u32 cpu);
s64 perf_event__process_itrace(struct perf_tool *tool,
			       union perf_event *event,
			       struct perf_session *session);
int perf_event__process_itrace_error(struct perf_tool *tool,
				     union perf_event *event,
				     struct perf_session *session);
int perf_event__count_itrace_error(struct perf_tool *tool __maybe_unused,
				   union perf_event *event __maybe_unused,
				   struct perf_session *session);
int itrace_parse_synth_opts(const struct option *opt, const char *str,
			    int unset);
void itrace_synth_opts__set_default(struct itrace_synth_opts *synth_opts);

size_t perf_event__fprintf_itrace_error(union perf_event *event, FILE *fp);

static inline int itrace__process_event(struct perf_session *session,
					union perf_event *event,
					struct perf_sample *sample,
					struct perf_tool *tool)
{
	if (!session->itrace)
		return 0;

	return session->itrace->process_event(session, event, sample, tool);
}

static inline int itrace__flush_events(struct perf_session *session,
				       struct perf_tool *tool)
{
	if (!session->itrace)
		return 0;

	return session->itrace->flush_events(session, tool);
}

static inline void itrace__free_events(struct perf_session *session)
{
	if (!session->itrace)
		return;

	return session->itrace->free_events(session);
}

static inline void itrace__free(struct perf_session *session)
{
	if (!session->itrace)
		return;

	return session->itrace->free(session);
}

#endif
