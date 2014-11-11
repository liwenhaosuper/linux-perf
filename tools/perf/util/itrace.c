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
#include <linux/string.h>

#include <sys/param.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <linux/list.h>

#include "../perf.h"
#include "util.h"
#include "evlist.h"
#include "cpumap.h"
#include "thread_map.h"
#include "itrace.h"

#include <linux/hash.h>

#include "event.h"
#include "session.h"
#include "debug.h"
#include "parse-options.h"

int itrace_mmap__mmap(struct itrace_mmap *mm, struct itrace_mmap_params *mp,
		      void *userpg, int fd)
{
	struct perf_event_mmap_page *pc = userpg;

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

	pc->aux_offset = mp->offset;
	pc->aux_size = mp->len;

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

#define ITRACE_INIT_NR_QUEUES	32

static struct itrace_queue *itrace_alloc_queue_array(unsigned int nr_queues)
{
	struct itrace_queue *queue_array;
	unsigned int max_nr_queues, i;

	max_nr_queues = MIN(UINT_MAX, SIZE_MAX) / sizeof(struct itrace_queue);
	if (nr_queues > max_nr_queues)
		return NULL;

	queue_array = calloc(nr_queues, sizeof(struct itrace_queue));
	if (!queue_array)
		return NULL;

	for (i = 0; i < nr_queues; i++) {
		INIT_LIST_HEAD(&queue_array[i].head);
		queue_array[i].priv = NULL;
	}

	return queue_array;
}

int itrace_queues__init(struct itrace_queues *queues)
{
	queues->nr_queues = ITRACE_INIT_NR_QUEUES;
	queues->queue_array = itrace_alloc_queue_array(queues->nr_queues);
	if (!queues->queue_array)
		return -ENOMEM;
	return 0;
}

static int itrace_queues__grow(struct itrace_queues *queues,
			       unsigned int new_nr_queues)
{
	unsigned int nr_queues = queues->nr_queues;
	struct itrace_queue *queue_array;
	unsigned int i;

	if (!nr_queues)
		nr_queues = ITRACE_INIT_NR_QUEUES;

	while (nr_queues && nr_queues < new_nr_queues)
		nr_queues <<= 1;

	if (nr_queues < queues->nr_queues || nr_queues < new_nr_queues)
		return -EINVAL;

	queue_array = itrace_alloc_queue_array(nr_queues);
	if (!queue_array)
		return -ENOMEM;

	for (i = 0; i < queues->nr_queues; i++) {
		list_splice_tail(&queues->queue_array[i].head,
				 &queue_array[i].head);
		queue_array[i].priv = queues->queue_array[i].priv;
	}

	queues->nr_queues = nr_queues;
	queues->queue_array = queue_array;

	return 0;
}

static void *itrace_copy_data(u64 size, struct perf_session *session)
{
	int fd = perf_data_file__fd(session->file);
	void *p;
	ssize_t ret;

	if (size > SSIZE_MAX)
		return NULL;

	p = malloc(size);
	if (!p)
		return NULL;

	ret = readn(fd, p, size);
	if (ret != (ssize_t)size) {
		free(p);
		return NULL;
	}

	return p;
}

static int itrace_queues__add_buffer(struct itrace_queues *queues,
				     unsigned int idx,
				     struct itrace_buffer *buffer)
{
	struct itrace_queue *queue;
	int err;

	if (idx >= queues->nr_queues) {
		err = itrace_queues__grow(queues, idx + 1);
		if (err)
			return err;
	}

	queue = &queues->queue_array[idx];

	if (!queue->set) {
		queue->set = true;
		queue->tid = buffer->tid;
		queue->cpu = buffer->cpu;
	} else if (buffer->cpu != queue->cpu || buffer->tid != queue->tid) {
		pr_err("itrace queue conflict: cpu %d, tid %d vs cpu %d, tid %d\n",
		       queue->cpu, queue->tid, buffer->cpu, buffer->tid);
		return -EINVAL;
	}

	buffer->buffer_nr = queues->next_buffer_nr++;

	list_add_tail(&buffer->list, &queue->head);

	queues->new_data = true;
	queues->populated = true;

	return 0;
}

/* Limit buffers to 32MiB on 32-bit */
#define BUFFER_LIMIT_FOR_32_BIT (32 * 1024 * 1024)

static int itrace_queues__split_buffer(struct itrace_queues *queues,
				       unsigned int idx,
				       struct itrace_buffer *buffer)
{
	u64 sz = buffer->size;
	bool consecutive = false;
	struct itrace_buffer *b;
	int err;

	while (sz > BUFFER_LIMIT_FOR_32_BIT) {
		b = memdup(buffer, sizeof(struct itrace_buffer));
		if (!b)
			return -ENOMEM;
		b->size = BUFFER_LIMIT_FOR_32_BIT;
		b->consecutive = consecutive;
		err = itrace_queues__add_buffer(queues, idx, b);
		if (err) {
			itrace_buffer__free(b);
			return err;
		}
		buffer->data_offset += BUFFER_LIMIT_FOR_32_BIT;
		sz -= BUFFER_LIMIT_FOR_32_BIT;
		consecutive = true;
	}

	buffer->size = sz;
	buffer->consecutive = consecutive;

	return 0;
}

static int itrace_queues__add_event_buffer(struct itrace_queues *queues,
					   struct perf_session *session,
					   unsigned int idx,
					   struct itrace_buffer *buffer)
{
	if (session->one_mmap) {
		buffer->data = buffer->data_offset - session->one_mmap_offset +
			       session->one_mmap_addr;
	} else if (perf_data_file__is_pipe(session->file)) {
		buffer->data = itrace_copy_data(buffer->size, session);
		if (!buffer->data)
			return -ENOMEM;
		buffer->data_needs_freeing = true;
	} else if (BITS_PER_LONG == 32 &&
		   buffer->size > BUFFER_LIMIT_FOR_32_BIT) {
		int err;

		err = itrace_queues__split_buffer(queues, idx, buffer);
		if (err)
			return err;
	}

	return itrace_queues__add_buffer(queues, idx, buffer);
}

int itrace_queues__add_event(struct itrace_queues *queues,
			     struct perf_session *session,
			     union perf_event *event, off_t data_offset,
			     struct itrace_buffer **buffer_ptr)
{
	struct itrace_buffer *buffer;
	unsigned int idx;
	int err;

	buffer = zalloc(sizeof(struct itrace_buffer));
	if (!buffer)
		return -ENOMEM;

	buffer->pid = -1;
	buffer->tid = event->itrace.tid;
	buffer->cpu = event->itrace.cpu;
	buffer->data_offset = data_offset;
	buffer->offset = event->itrace.offset;
	buffer->reference = event->itrace.reference;
	buffer->size = event->itrace.size;
	idx = event->itrace.idx;

	err = itrace_queues__add_event_buffer(queues, session, idx, buffer);
	if (err)
		goto out_err;

	if (buffer_ptr)
		*buffer_ptr = buffer;

	return 0;

out_err:
	itrace_buffer__free(buffer);
	return err;
}

static int itrace_queues__add_indexed_event(struct itrace_queues *queues,
					    struct perf_session *session,
					    off_t file_offset, size_t sz)
{
	union perf_event *event;
	int err;
	char buf[PERF_SAMPLE_MAX_SIZE];

	err = perf_session__peek_event(session, file_offset, buf,
				       PERF_SAMPLE_MAX_SIZE, &event, NULL);
	if (err)
		return err;

	if (event->header.type == PERF_RECORD_ITRACE) {
		if (event->header.size != sizeof(struct itrace_event) ||
		    event->header.size != sz) {
			err = -EINVAL;
			goto out;
		}
		file_offset += event->header.size;
		err = itrace_queues__add_event(queues, session, event,
					       file_offset, NULL);
	}
out:
	return err;
}

void itrace_queues__free(struct itrace_queues *queues)
{
	unsigned int i;

	for (i = 0; i < queues->nr_queues; i++) {
		while (!list_empty(&queues->queue_array[i].head)) {
			struct itrace_buffer *buffer;

			buffer = list_entry(queues->queue_array[i].head.next,
					    struct itrace_buffer, list);
			list_del(&buffer->list);
			itrace_buffer__free(buffer);
		}
	}

	zfree(&queues->queue_array);
	queues->nr_queues = 0;
}

static void itrace_heapify(struct itrace_heap_item *heap_array,
			   unsigned int pos, unsigned int queue_nr,
			   u64 ordinal)
{
	unsigned int parent;

	while (pos) {
		parent = (pos - 1) >> 1;
		if (heap_array[parent].ordinal <= ordinal)
			break;
		heap_array[pos] = heap_array[parent];
		pos = parent;
	}
	heap_array[pos].queue_nr = queue_nr;
	heap_array[pos].ordinal = ordinal;
}

int itrace_heap__add(struct itrace_heap *heap, unsigned int queue_nr,
		     u64 ordinal)
{
	struct itrace_heap_item *heap_array;

	if (queue_nr >= heap->heap_sz) {
		unsigned int heap_sz = ITRACE_INIT_NR_QUEUES;

		while (heap_sz <= queue_nr)
			heap_sz <<= 1;
		heap_array = realloc(heap->heap_array,
				     heap_sz * sizeof(struct itrace_heap_item));
		if (!heap_array)
			return -ENOMEM;
		heap->heap_array = heap_array;
		heap->heap_sz = heap_sz;
	}

	itrace_heapify(heap->heap_array, heap->heap_cnt++, queue_nr, ordinal);

	return 0;
}

void itrace_heap__free(struct itrace_heap *heap)
{
	zfree(&heap->heap_array);
	heap->heap_cnt = 0;
	heap->heap_sz = 0;
}

void itrace_heap__pop(struct itrace_heap *heap)
{
	unsigned int pos, last, heap_cnt = heap->heap_cnt;
	struct itrace_heap_item *heap_array;

	if (!heap_cnt)
		return;

	heap->heap_cnt -= 1;

	heap_array = heap->heap_array;

	pos = 0;
	while (1) {
		unsigned int left, right;

		left = (pos << 1) + 1;
		if (left >= heap_cnt)
			break;
		right = left + 1;
		if (right >= heap_cnt) {
			heap_array[pos] = heap_array[left];
			return;
		}
		if (heap_array[left].ordinal < heap_array[right].ordinal) {
			heap_array[pos] = heap_array[left];
			pos = left;
		} else {
			heap_array[pos] = heap_array[right];
			pos = right;
		}
	}

	last = heap_cnt - 1;
	itrace_heapify(heap_array, pos, heap_array[last].queue_nr,
		       heap_array[last].ordinal);
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

static int itrace_index__alloc(struct list_head *head)
{
	struct itrace_index *itrace_index;

	itrace_index = malloc(sizeof(struct itrace_index));
	if (!itrace_index)
		return -ENOMEM;

	itrace_index->nr = 0;
	INIT_LIST_HEAD(&itrace_index->list);

	list_add_tail(&itrace_index->list, head);

	return 0;
}

void itrace_index__free(struct list_head *head)
{
	struct itrace_index *itrace_index, *n;

	list_for_each_entry_safe(itrace_index, n, head, list) {
		list_del(&itrace_index->list);
		free(itrace_index);
	}
}

static struct itrace_index *itrace_index__last(struct list_head *head)
{
	struct itrace_index *itrace_index;
	int err;

	if (list_empty(head)) {
		err = itrace_index__alloc(head);
		if (err)
			return NULL;
	}

	itrace_index = list_entry(head->prev, struct itrace_index, list);

	if (itrace_index->nr >= PERF_ITRACE_INDEX_ENTRY_COUNT) {
		err = itrace_index__alloc(head);
		if (err)
			return NULL;
		itrace_index = list_entry(head->prev, struct itrace_index,
					  list);
	}

	return itrace_index;
}

int itrace_index__itrace_event(struct list_head *head, union perf_event *event,
			       off_t file_offset)
{
	struct itrace_index *itrace_index;
	size_t nr;

	itrace_index = itrace_index__last(head);
	if (!itrace_index)
		return -ENOMEM;

	nr = itrace_index->nr;
	itrace_index->entries[nr].file_offset = file_offset;
	itrace_index->entries[nr].sz = event->header.size;
	itrace_index->nr += 1;

	return 0;
}

static int itrace_index__do_write(int fd, struct itrace_index *itrace_index)
{
	struct itrace_index_entry index;
	size_t i;

	for (i = 0; i < itrace_index->nr; i++) {
		index.file_offset = itrace_index->entries[i].file_offset;
		index.sz = itrace_index->entries[i].sz;
		if (writen(fd, &index, sizeof(index)) != sizeof(index))
			return -errno;
	}
	return 0;
}

int itrace_index__write(int fd, struct list_head *head)
{
	struct itrace_index *itrace_index;
	u64 total = 0;
	int err;

	list_for_each_entry(itrace_index, head, list)
		total += itrace_index->nr;

	if (writen(fd, &total, sizeof(total)) != sizeof(total))
		return -errno;

	list_for_each_entry(itrace_index, head, list) {
		err = itrace_index__do_write(fd, itrace_index);
		if (err)
			return err;
	}

	return 0;
}

static int itrace_index__process_entry(int fd, struct list_head *head,
				       bool needs_swap)
{
	struct itrace_index *itrace_index;
	struct itrace_index_entry index;
	size_t nr;

	if (readn(fd, &index, sizeof(index)) != sizeof(index))
		return -1;

	itrace_index = itrace_index__last(head);
	if (!itrace_index)
		return -1;

	nr = itrace_index->nr;
	if (needs_swap) {
		itrace_index->entries[nr].file_offset =
						bswap_64(index.file_offset);
		itrace_index->entries[nr].sz = bswap_64(index.sz);
	} else {
		itrace_index->entries[nr].file_offset = index.file_offset;
		itrace_index->entries[nr].sz = index.sz;
	}

	itrace_index->nr = nr + 1;

	return 0;
}

int itrace_index__process(int fd, u64 size, struct perf_session *session,
			  bool needs_swap)
{
	struct list_head *head = &session->itrace_index;
	u64 nr;

	if (readn(fd, &nr, sizeof(u64)) != sizeof(u64))
		return -1;

	if (needs_swap)
		nr = bswap_64(nr);

	if (sizeof(u64) + nr * sizeof(struct itrace_index_entry) != size)
		return -1;

	while (nr--) {
		int err;

		err = itrace_index__process_entry(fd, head, needs_swap);
		if (err)
			return -1;
	}

	return 0;
}

static int itrace_queues__process_index_entry(struct itrace_queues *queues,
					      struct perf_session *session,
					      struct itrace_index_entry *index)
{
	return itrace_queues__add_indexed_event(queues, session,
						index->file_offset, index->sz);
}

int itrace_queues__process_index(struct itrace_queues *queues,
				 struct perf_session *session)
{
	struct itrace_index *itrace_index;
	struct itrace_index_entry *index;
	size_t i;
	int err;

	list_for_each_entry(itrace_index, &session->itrace_index, list) {
		for (i = 0; i < itrace_index->nr; i++) {
			index = &itrace_index->entries[i];
			err = itrace_queues__process_index_entry(queues,
								 session,
								 index);
			if (err)
				return err;
		}
	}
	return 0;
}

struct itrace_buffer *itrace_buffer__next(struct itrace_queue *queue,
					  struct itrace_buffer *buffer)
{
	if (buffer) {
		if (list_is_last(&buffer->list, &queue->head))
			return NULL;
		return list_entry(buffer->list.next, struct itrace_buffer,
				  list);
	} else {
		if (list_empty(&queue->head))
			return NULL;
		return list_entry(queue->head.next, struct itrace_buffer, list);
	}
}

void *itrace_buffer__get_data(struct itrace_buffer *buffer, int fd)
{
	size_t adj = buffer->data_offset & (page_size - 1);
	size_t size = buffer->size + adj;
	off_t file_offset = buffer->data_offset - adj;
	void *addr;

	if (buffer->data)
		return buffer->data;

	addr = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, file_offset);
	if (addr == MAP_FAILED)
		return NULL;

	buffer->mmap_addr = addr;
	buffer->mmap_size = size;

	buffer->data = addr + adj;

	return buffer->data;
}

void itrace_buffer__put_data(struct itrace_buffer *buffer)
{
	if (!buffer->data || !buffer->mmap_addr)
		return;
	munmap(buffer->mmap_addr, buffer->mmap_size);
	buffer->mmap_addr = NULL;
	buffer->mmap_size = 0;
	buffer->data = NULL;
	buffer->use_data = NULL;
}

void itrace_buffer__drop_data(struct itrace_buffer *buffer)
{
	itrace_buffer__put_data(buffer);
	if (buffer->data_needs_freeing) {
		buffer->data_needs_freeing = false;
		zfree(&buffer->data);
		buffer->use_data = NULL;
		buffer->size = 0;
	}
}

void itrace_buffer__free(struct itrace_buffer *buffer)
{
	itrace_buffer__drop_data(buffer);
	free(buffer);
}

void itrace_synth_error(struct itrace_error_event *itrace_error, int type,
			int code, int cpu, pid_t pid, pid_t tid, u64 ip,
			const char *msg)
{
	size_t size;

	memset(itrace_error, 0, sizeof(struct itrace_error_event));

	itrace_error->header.type = PERF_RECORD_ITRACE_ERROR;
	itrace_error->type = type;
	itrace_error->code = code;
	itrace_error->cpu = cpu;
	itrace_error->pid = pid;
	itrace_error->tid = tid;
	itrace_error->ip = ip;
	strlcpy(itrace_error->msg, msg, MAX_ITRACE_ERROR_MSG);

	size = (void *)itrace_error->msg - (void *)itrace_error +
	       strlen(itrace_error->msg) + 1;
	itrace_error->header.size = PERF_ALIGN(size, sizeof(u64));
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

static bool itrace__dont_decode(struct perf_session *session)
{
	return !session->itrace_synth_opts ||
	       session->itrace_synth_opts->dont_decode;
}

int perf_event__process_itrace_info(struct perf_tool *tool __maybe_unused,
				    union perf_event *event,
				    struct perf_session *session __maybe_unused)
{
	enum itrace_type type = event->itrace_info.type;

	if (dump_trace)
		fprintf(stdout, " type: %u\n", type);

	switch (type) {
	case PERF_ITRACE_UNKNOWN:
	default:
		return -EINVAL;
	}
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

s64 perf_event__process_itrace(struct perf_tool *tool, union perf_event *event,
			       struct perf_session *session)
{
	s64 err;

	if (dump_trace)
		fprintf(stdout, " size: %#"PRIx64"  offset: %#"PRIx64"  ref: %#"PRIx64"  idx: %u  tid: %d  cpu: %d\n",
			event->itrace.size, event->itrace.offset,
			event->itrace.reference, event->itrace.idx,
			event->itrace.tid, event->itrace.cpu);

	if (itrace__dont_decode(session))
		return event->itrace.size;

	if (!session->itrace || event->header.type != PERF_RECORD_ITRACE)
		return -EINVAL;

	err = session->itrace->process_itrace_event(session, event, tool);
	if (err < 0)
		return err;

	return event->itrace.size;
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

size_t perf_event__fprintf_itrace_error(union perf_event *event, FILE *fp)
{
	struct itrace_error_event *e = &event->itrace_error;
	int ret;

	ret = fprintf(fp, " Instruction trace error type %u", e->type);
	ret += fprintf(fp, " cpu %d pid %d tid %d ip %#"PRIx64" code %u: %s\n",
		       e->cpu, e->pid, e->tid, e->ip, e->code, e->msg);
	return ret;
}

int perf_event__process_itrace_error(struct perf_tool *tool __maybe_unused,
				     union perf_event *event,
				     struct perf_session *session)
{
	if (itrace__dont_decode(session))
		return 0;

	if (session->itrace)
		session->itrace->error_count += 1;

	perf_event__fprintf_itrace_error(event, stdout);
	return 0;
}

int perf_event__count_itrace_error(struct perf_tool *tool __maybe_unused,
				   union perf_event *event __maybe_unused,
				   struct perf_session *session)
{
	if (session->itrace)
		session->itrace->error_count += 1;
	return 0;
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

/**
 * struct itrace_cache - hash table to cache decoded instruction blocks
 * @hashtable: the hashtable
 * @sz: hashtable size (number of hlists)
 * @entry_size: size of an entry
 * @limit: limit the number of entries to this maximum, when reached the cache
 *         is dropped and caching begins again with an empty cache
 * @cnt: current number of entries
 * @bits: hashtable size (@sz = 2^@bits)
 */
struct itrace_cache {
	struct hlist_head *hashtable;
	size_t sz;
	size_t entry_size;
	size_t limit;
	size_t cnt;
	unsigned int bits;
};

struct itrace_cache *itrace_cache__new(unsigned int bits, size_t entry_size,
				       unsigned int limit_percent)
{
	struct itrace_cache *c;
	struct hlist_head *ht;
	size_t sz, i;

	c = zalloc(sizeof(struct itrace_cache));
	if (!c)
		return NULL;

	sz = 1UL << bits;

	ht = calloc(sz, sizeof(struct hlist_head));
	if (!ht)
		goto out_free;

	for (i = 0; i < sz; i++)
		INIT_HLIST_HEAD(&ht[i]);

	c->hashtable = ht;
	c->sz = sz;
	c->entry_size = entry_size;
	c->limit = (c->sz * limit_percent) / 100;
	c->bits = bits;

	return c;

out_free:
	free(c);
	return NULL;
}

static void itrace_cache__drop(struct itrace_cache *c)
{
	struct itrace_cache_entry *entry;
	struct hlist_node *tmp;
	size_t i;

	if (!c)
		return;

	for (i = 0; i < c->sz; i++) {
		hlist_for_each_entry_safe(entry, tmp, &c->hashtable[i], hash) {
			hlist_del(&entry->hash);
			itrace_cache__free_entry(c, entry);
		}
	}

	c->cnt = 0;
}

void itrace_cache__free(struct itrace_cache *c)
{
	if (!c)
		return;

	itrace_cache__drop(c);
	free(c->hashtable);
	free(c);
}

void *itrace_cache__alloc_entry(struct itrace_cache *c)
{
	return malloc(c->entry_size);
}

void itrace_cache__free_entry(struct itrace_cache *c __maybe_unused,
			      void *entry)
{
	free(entry);
}

int itrace_cache__add(struct itrace_cache *c, u32 key,
		      struct itrace_cache_entry *entry)
{
	if (c->limit && ++c->cnt > c->limit)
		itrace_cache__drop(c);

	entry->key = key;
	hlist_add_head(&entry->hash, &c->hashtable[hash_32(key, c->bits)]);

	return 0;
}

void *itrace_cache__lookup(struct itrace_cache *c, u32 key)
{
	struct itrace_cache_entry *entry;
	struct hlist_head *hlist;

	if (!c)
		return NULL;

	hlist = &c->hashtable[hash_32(key, c->bits)];
	hlist_for_each_entry(entry, hlist, hash) {
		if (entry->key == key)
			return entry;
	}

	return NULL;
}
