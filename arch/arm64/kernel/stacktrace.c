// SPDX-License-Identifier: GPL-2.0-only
/*
 * Stack tracing support
 *
 * Copyright (C) 2012 ARM Ltd.
 */
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>
#include <linux/stacktrace.h>

#include <asm/irq.h>
#include <asm/pointer_auth.h>
#include <asm/stack_pointer.h>
#include <asm/stacktrace.h>

struct code_range {
	unsigned long	start;
	unsigned long	end;
};

static struct code_range	*sym_code_functions;
static int			num_sym_code_functions;

int __init init_sym_code_functions(void)
{
	size_t size = (unsigned long)__sym_code_functions_end -
		      (unsigned long)__sym_code_functions_start;

	sym_code_functions = (struct code_range *)__sym_code_functions_start;
	/*
	 * Order it so that sym_code_functions is not visible before
	 * num_sym_code_functions.
	 */
	smp_mb();
	num_sym_code_functions = size / sizeof(struct code_range);

	return 0;
}
early_initcall(init_sym_code_functions);

/*
 * AArch64 PCS assigns the frame pointer to x29.
 *
 * A simple function prologue looks like this:
 * 	sub	sp, sp, #0x10
 *   	stp	x29, x30, [sp]
 *	mov	x29, sp
 *
 * A simple function epilogue looks like this:
 *	mov	sp, x29
 *	ldp	x29, x30, [sp]
 *	add	sp, sp, #0x10
 */

static void notrace unwind_start(struct stackframe *frame,
				 struct task_struct *task,
				 unsigned long fp, unsigned long pc,
				 bool need_reliable)
{
	frame->task = task;
	frame->fp = fp;
	frame->pc = pc;
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	frame->graph = 0;
#endif

	/*
	 * Prime the first unwind.
	 *
	 * In unwind_next() we'll check that the FP points to a valid stack,
	 * which can't be STACK_TYPE_UNKNOWN, and the first unwind will be
	 * treated as a transition to whichever stack that happens to be. The
	 * prev_fp value won't be used, but we set it to 0 such that it is
	 * definitely not an accessible stack address.
	 */
	bitmap_zero(frame->stacks_done, __NR_STACK_TYPES);
	frame->prev_fp = 0;
	frame->prev_type = STACK_TYPE_UNKNOWN;
	frame->failed = false;
	frame->need_reliable = need_reliable;
}

NOKPROBE_SYMBOL(unwind_start);

/*
 * Unwind from one frame record (A) to the next frame record (B).
 *
 * We terminate early if the location of B indicates a malformed chain of frame
 * records (e.g. a cycle), determined based on the location and fp value of A
 * and the location (but not the fp value) of B.
 */
static void notrace unwind_next(struct stackframe *frame)
{
	unsigned long fp = frame->fp;
	struct stack_info info;
	struct task_struct *tsk = frame->task;

	if (fp & 0x7) {
		frame->failed = true;
		return;
	}

	if (!on_accessible_stack(tsk, fp, 16, &info)) {
		frame->failed = true;
		return;
	}

	if (test_bit(info.type, frame->stacks_done)) {
		frame->failed = true;
		return;
	}

	/*
	 * As stacks grow downward, any valid record on the same stack must be
	 * at a strictly higher address than the prior record.
	 *
	 * Stacks can nest in several valid orders, e.g.
	 *
	 * TASK -> IRQ -> OVERFLOW -> SDEI_NORMAL
	 * TASK -> SDEI_NORMAL -> SDEI_CRITICAL -> OVERFLOW
	 *
	 * ... but the nesting itself is strict. Once we transition from one
	 * stack to another, it's never valid to unwind back to that first
	 * stack.
	 */
	if (info.type == frame->prev_type) {
		if (fp <= frame->prev_fp) {
			frame->failed = true;
			return;
		}
	} else {
		set_bit(frame->prev_type, frame->stacks_done);
	}

	/*
	 * Record this frame record's values and location. The prev_fp and
	 * prev_type are only meaningful to the next unwind_next() invocation.
	 */
	frame->fp = READ_ONCE_NOCHECK(*(unsigned long *)(fp));
	frame->pc = READ_ONCE_NOCHECK(*(unsigned long *)(fp + 8));
	frame->prev_fp = fp;
	frame->prev_type = info.type;

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	if (tsk->ret_stack &&
		(ptrauth_strip_insn_pac(frame->pc) == (unsigned long)return_to_handler)) {
		struct ftrace_ret_stack *ret_stack;
		/*
		 * This is a case where function graph tracer has
		 * modified a return address (LR) in a stack frame
		 * to hook a function return.
		 * So replace it to an original value.
		 */
		ret_stack = ftrace_graph_get_ret_stack(tsk, frame->graph++);
		if (WARN_ON_ONCE(!ret_stack)) {
			frame->failed = true;
			return;
		}
		frame->pc = ret_stack->ret;
	}
#endif /* CONFIG_FUNCTION_GRAPH_TRACER */

	frame->pc = ptrauth_strip_insn_pac(frame->pc);
}

NOKPROBE_SYMBOL(unwind_next);

static bool dump_backtrace_entry(void *arg, unsigned long where)
{
	char *loglvl = arg;
	printk("%s %pSb\n", loglvl, (void *)where);
	return true;
}

void dump_backtrace(struct pt_regs *regs, struct task_struct *tsk,
		    const char *loglvl)
{
	pr_debug("%s(regs = %p tsk = %p)\n", __func__, regs, tsk);

	if (regs) {
		if (user_mode(regs))
			return;
	}

	if (!tsk)
		tsk = current;

	if (!try_get_task_stack(tsk))
		return;

	printk("%sCall trace:\n", loglvl);
	arch_stack_walk(dump_backtrace_entry, (void *)loglvl, tsk, regs);

	put_task_stack(tsk);
}

void show_stack(struct task_struct *tsk, unsigned long *sp, const char *loglvl)
{
	dump_backtrace(NULL, tsk, loglvl);
	barrier();
}

/*
 * Check the stack frame for conditions that make further unwinding unreliable.
 */
static bool notrace unwind_is_reliable(struct stackframe *frame)
{
	const struct code_range *range;
	unsigned long pc;
	int i;

	/*
	 * If the PC is not a known kernel text address, then we cannot
	 * be sure that a subsequent unwind will be reliable, as we
	 * don't know that the code follows our unwind requirements.
	 */
	if (!__kernel_text_address(frame->pc))
		return false;

	/*
	 * Check the return PC against sym_code_functions[]. If there is a
	 * match, then the consider the stack frame unreliable.
	 *
	 * As SYM_CODE functions don't follow the usual calling conventions,
	 * we assume by default that any SYM_CODE function cannot be unwound
	 * reliably.
	 *
	 * Note that this includes:
	 *
	 * - Exception handlers and entry assembly
	 * - Trampoline assembly (e.g., ftrace, kprobes)
	 * - Hypervisor-related assembly
	 * - Hibernation-related assembly
	 * - CPU start-stop, suspend-resume assembly
	 * - Kernel relocation assembly
	 */
	pc = frame->pc;
	for (i = 0; i < num_sym_code_functions; i++) {
		range = &sym_code_functions[i];
		if (pc >= range->start && pc < range->end)
			return false;
	}
	return true;
}

NOKPROBE_SYMBOL(unwind_is_reliable);

static bool notrace unwind_consume(struct stackframe *frame,
				   stack_trace_consume_fn consume_entry,
				   void *cookie)
{
	if (frame->failed) {
		/* PC is suspect. Cannot consume it. */
		return false;
	}

	if (!consume_entry(cookie, frame->pc)) {
		/* Caller terminated the unwind. */
		frame->failed = true;
		return false;
	}

	if (frame->fp == (unsigned long)task_pt_regs(frame->task)->stackframe) {
		/* Final frame; nothing to unwind */
		return false;
	}

	if (frame->need_reliable && !unwind_is_reliable(frame)) {
		/* Cannot unwind to the next frame reliably. */
		frame->failed = true;
		return false;
	}
	return true;
}

NOKPROBE_SYMBOL(unwind_consume);

static inline bool unwind_failed(struct stackframe *frame)
{
	return frame->failed;
}

/* Core unwind function */
static bool notrace unwind(stack_trace_consume_fn consume_entry, void *cookie,
			   struct task_struct *task,
			   unsigned long fp, unsigned long pc,
			   bool need_reliable)
{
	struct stackframe frame;

	unwind_start(&frame, task, fp, pc, need_reliable);
	while (unwind_consume(&frame, consume_entry, cookie))
		unwind_next(&frame);
	return !unwind_failed(&frame);
}

NOKPROBE_SYMBOL(unwind);

#ifdef CONFIG_STACKTRACE

noinline notrace void arch_stack_walk(stack_trace_consume_fn consume_entry,
			      void *cookie, struct task_struct *task,
			      struct pt_regs *regs)
{
	unsigned long fp, pc;

	if (!task)
		task = current;

	if (regs) {
		fp = regs->regs[29];
		pc = regs->pc;
	} else if (task == current) {
		/* Skip arch_stack_walk() in the stack trace. */
		fp = (unsigned long)__builtin_frame_address(1);
		pc = (unsigned long)__builtin_return_address(0);
	} else {
		/* Caller guarantees that the task is not running. */
		fp = thread_saved_fp(task);
		pc = thread_saved_pc(task);
	}
	unwind(consume_entry, cookie, task, fp, pc, false);
}

/*
 * arch_stack_walk_reliable() may not be used for livepatch until all of
 * the reliability checks are in place in unwind_consume(). However,
 * debug and test code can choose to use it even if all the checks are not
 * in place.
 */
noinline int notrace arch_stack_walk_reliable(stack_trace_consume_fn consume_fn,
					      void *cookie,
					      struct task_struct *task)
{
	unsigned long fp, pc;

	if (!task)
		task = current;

	if (task == current) {
		/* Skip arch_stack_walk_reliable() in the stack trace. */
		fp = (unsigned long)__builtin_frame_address(1);
		pc = (unsigned long)__builtin_return_address(0);
	} else {
		/* Caller guarantees that the task is not running. */
		fp = thread_saved_fp(task);
		pc = thread_saved_pc(task);
	}
	if (unwind(consume_fn, cookie, task, fp, pc, true))
		return 0;
	return -EINVAL;
}

#endif
