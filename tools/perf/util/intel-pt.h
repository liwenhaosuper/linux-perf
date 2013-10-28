/*
 * intel_pt.h: Intel Processor Trace support
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

#ifndef INCLUDE__PERF_INTEL_PT_H__
#define INCLUDE__PERF_INTEL_PT_H__

#define INTEL_PT_PMU_NAME "intel_pt"

struct itrace_record;
struct perf_tool;
union perf_event;
struct perf_session;
struct perf_event_attr;
struct perf_pmu;

struct itrace_record *intel_pt_recording_init(int *err);

int intel_pt_process_itrace_info(struct perf_tool *tool,
				 union perf_event *event,
				 struct perf_session *session);

struct perf_event_attr *intel_pt_pmu_default_config(struct perf_pmu *pmu);

#endif
