#ifndef __PERF_TOOL_H
#define __PERF_TOOL_H

#include <stdbool.h>

#include <linux/types.h>

struct perf_session;
union perf_event;
struct perf_evlist;
struct perf_evsel;
struct perf_sample;
struct perf_tool;
struct machine;

typedef int (*event_sample)(struct perf_tool *tool, union perf_event *event,
			    struct perf_sample *sample,
			    struct perf_evsel *evsel, struct machine *machine);

typedef int (*event_op)(struct perf_tool *tool, union perf_event *event,
			struct perf_sample *sample, struct machine *machine);

typedef int (*event_attr_op)(struct perf_tool *tool,
			     union perf_event *event,
			     struct perf_evlist **pevlist);

typedef int (*event_op2)(struct perf_tool *tool, union perf_event *event,
			 struct perf_session *session);

typedef s64 (*event_op3)(struct perf_tool *tool, union perf_event *event,
			 struct perf_session *session);

struct perf_tool {
	event_sample	sample,
			read;
	event_op	mmap,
			mmap2,
			comm,
			fork,
			exit,
			lost,
			aux,
			itrace_start,
			throttle,
			unthrottle;
	event_attr_op	attr;
	event_op2	tracing_data;
	event_op2	finished_round,
			build_id,
			id_index,
			itrace_info,
			itrace_error;
	event_op3	itrace;
	bool		ordered_events;
	bool		ordering_requires_timestamps;
};

#endif /* __PERF_TOOL_H */
