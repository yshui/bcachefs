
#include <linux/log2.h>
#include <linux/osq_optimistic_spin.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>

#include "six.h"

#define six_acquire(l, t)	lock_acquire(l, 0, t, 0, 0, NULL, _RET_IP_)
#define six_release(l)		lock_release(l, 0, _RET_IP_)

struct six_lock_vals {
	/* Value we add to the lock in order to take the lock: */
	u64			lock_val;

	/* If the lock has this value (used as a mask), taking the lock fails: */
	u64			lock_fail;

	/* Value we add to the lock in order to release the lock: */
	u64			unlock_val;

	/* Mask that indicates lock is held for this type: */
	u64			held_mask;

	/* Waitlist we wakeup when releasing the lock: */
	enum six_lock_type	unlock_wakeup;
};

#define __SIX_LOCK_HELD_read	__SIX_VAL(read_lock, ~0)
#define __SIX_LOCK_HELD_intent	__SIX_VAL(intent_lock, ~0)
#define __SIX_LOCK_HELD_write	__SIX_VAL(seq, 1)

#define LOCK_VALS {							\
	[SIX_LOCK_read] = {						\
		.lock_val	= __SIX_VAL(read_lock, 1),		\
		.lock_fail	= __SIX_LOCK_HELD_write,		\
		.unlock_val	= -__SIX_VAL(read_lock, 1),		\
		.held_mask	= __SIX_LOCK_HELD_read,			\
		.unlock_wakeup	= SIX_LOCK_write,			\
	},								\
	[SIX_LOCK_intent] = {						\
		.lock_val	= __SIX_VAL(intent_lock, 1),		\
		.lock_fail	= __SIX_LOCK_HELD_intent,		\
		.unlock_val	= -__SIX_VAL(intent_lock, 1),		\
		.held_mask	= __SIX_LOCK_HELD_intent,		\
		.unlock_wakeup	= SIX_LOCK_intent,			\
	},								\
	[SIX_LOCK_write] = {						\
		.lock_val	= __SIX_VAL(seq, 1),			\
		.lock_fail	= __SIX_LOCK_HELD_read,			\
		.unlock_val	= __SIX_VAL(seq, 1),			\
		.held_mask	= __SIX_LOCK_HELD_write,		\
		.unlock_wakeup	= SIX_LOCK_read,			\
	},								\
}

static inline void six_set_owner(struct six_lock *lock, enum six_lock_type type,
				 union six_lock_state old)
{
	if (type != SIX_LOCK_intent)
		return;

	if (!old.intent_lock) {
		EBUG_ON(lock->owner);
		lock->owner = current;
	} else {
		EBUG_ON(lock->owner != current);
	}
}

static inline void six_clear_owner(struct six_lock *lock, enum six_lock_type type)
{
	if (type != SIX_LOCK_intent)
		return;

	EBUG_ON(lock->owner != current);

	if (lock->state.intent_lock == 1)
		lock->owner = NULL;
}

static __always_inline bool do_six_trylock_type(struct six_lock *lock,
						enum six_lock_type type)
{
	const struct six_lock_vals l[] = LOCK_VALS;
	union six_lock_state old;
	u64 v = READ_ONCE(lock->state.v);

	EBUG_ON(type == SIX_LOCK_write && lock->owner != current);

	do {
		old.v = v;

		EBUG_ON(type == SIX_LOCK_write &&
			((old.v & __SIX_LOCK_HELD_write) ||
			 !(old.v & __SIX_LOCK_HELD_intent)));

		if (old.v & l[type].lock_fail)
			return false;
	} while ((v = atomic64_cmpxchg_acquire(&lock->state.counter,
				old.v,
				old.v + l[type].lock_val)) != old.v);

	six_set_owner(lock, type, old);
	return true;
}

__always_inline __flatten
static bool __six_trylock_type(struct six_lock *lock, enum six_lock_type type)
{
	if (!do_six_trylock_type(lock, type))
		return false;

	six_acquire(&lock->dep_map, 1);
	return true;
}

__always_inline __flatten
static bool __six_relock_type(struct six_lock *lock, enum six_lock_type type,
			      unsigned seq)
{
	const struct six_lock_vals l[] = LOCK_VALS;
	union six_lock_state old;
	u64 v = READ_ONCE(lock->state.v);

	do {
		old.v = v;

		if (old.seq != seq || old.v & l[type].lock_fail)
			return false;
	} while ((v = atomic64_cmpxchg_acquire(&lock->state.counter,
				old.v,
				old.v + l[type].lock_val)) != old.v);

	six_set_owner(lock, type, old);
	six_acquire(&lock->dep_map, 1);
	return true;
}

struct six_lock_waiter {
	struct list_head	list;
	struct task_struct	*task;
};

/* This is probably up there with the more evil things I've done */
#define waitlist_bitnr(id) ilog2((((union six_lock_state) { .waiters = 1 << (id) }).l))

static inline struct task_struct *six_osq_get_owner(struct optimistic_spin_queue *osq)
{
	struct six_lock *lock = container_of(osq, struct six_lock, osq);

	return lock->owner;
}

static inline bool six_osq_trylock_read(struct optimistic_spin_queue *osq)
{
	struct six_lock *lock = container_of(osq, struct six_lock, osq);

	return do_six_trylock_type(lock, SIX_LOCK_read);
}

static inline bool six_osq_trylock_intent(struct optimistic_spin_queue *osq)
{
	struct six_lock *lock = container_of(osq, struct six_lock, osq);

	return do_six_trylock_type(lock, SIX_LOCK_intent);
}

noinline
static void __six_lock_type_slowpath(struct six_lock *lock, enum six_lock_type type)
{
	const struct six_lock_vals l[] = LOCK_VALS;
	union six_lock_state old, new;
	struct six_lock_waiter wait;
	u64 v;

	switch (type) {
	case SIX_LOCK_read:
		if (osq_optimistic_spin(&lock->osq, six_osq_get_owner,
					six_osq_trylock_read))
			return;
		break;
	case SIX_LOCK_intent:
		if (osq_optimistic_spin(&lock->osq, six_osq_get_owner,
					six_osq_trylock_intent))
			return;
		break;
	case SIX_LOCK_write:
		break;
	}

	lock_contended(&lock->dep_map, _RET_IP_);

	INIT_LIST_HEAD(&wait.list);
	wait.task = current;

	while (1) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (type == SIX_LOCK_write)
			EBUG_ON(lock->owner != current);
		else if (list_empty_careful(&wait.list)) {
			raw_spin_lock(&lock->wait_lock);
			list_add_tail(&wait.list, &lock->wait_list[type]);
			raw_spin_unlock(&lock->wait_lock);
		}

		v = READ_ONCE(lock->state.v);
		do {
			new.v = old.v = v;

			if (!(old.v & l[type].lock_fail))
				new.v += l[type].lock_val;
			else if (!(new.waiters & (1 << type)))
				new.waiters |= 1 << type;
			else
				break; /* waiting bit already set */
		} while ((v = atomic64_cmpxchg_acquire(&lock->state.counter,
					old.v, new.v)) != old.v);

		if (!(old.v & l[type].lock_fail))
			break;

		schedule();
	}

	six_set_owner(lock, type, old);

	__set_current_state(TASK_RUNNING);

	if (!list_empty_careful(&wait.list)) {
		raw_spin_lock(&lock->wait_lock);
		list_del_init(&wait.list);
		raw_spin_unlock(&lock->wait_lock);
	}
}

__always_inline
static void __six_lock_type(struct six_lock *lock, enum six_lock_type type)
{
	six_acquire(&lock->dep_map, 0);

	if (!do_six_trylock_type(lock, type))
		__six_lock_type_slowpath(lock, type);

	lock_acquired(&lock->dep_map, _RET_IP_);
}

static inline void six_lock_wakeup(struct six_lock *lock,
				   union six_lock_state state,
				   unsigned waitlist_id)
{
	struct list_head *wait_list = &lock->wait_list[waitlist_id];
	struct six_lock_waiter *w, *next;

	if (waitlist_id == SIX_LOCK_write && state.read_lock)
		return;

	if (!(state.waiters & (1 << waitlist_id)))
		return;

	clear_bit(waitlist_bitnr(waitlist_id),
		  (unsigned long *) &lock->state.v);

	if (waitlist_id == SIX_LOCK_write) {
		struct task_struct *p = READ_ONCE(lock->owner);

		if (p)
			wake_up_process(p);
		return;
	}

	raw_spin_lock(&lock->wait_lock);

	list_for_each_entry_safe(w, next, wait_list, list) {
		list_del_init(&w->list);

		if (wake_up_process(w->task) &&
		    waitlist_id != SIX_LOCK_read) {
			if (!list_empty(wait_list))
				set_bit(waitlist_bitnr(waitlist_id),
					(unsigned long *) &lock->state.v);
			break;
		}
	}

	raw_spin_unlock(&lock->wait_lock);
}

__always_inline __flatten
static void __six_unlock_type(struct six_lock *lock, enum six_lock_type type)
{
	const struct six_lock_vals l[] = LOCK_VALS;
	union six_lock_state state;

	EBUG_ON(!(lock->state.v & l[type].held_mask));
	EBUG_ON(type == SIX_LOCK_write &&
		!(lock->state.v & __SIX_LOCK_HELD_intent));

	six_clear_owner(lock, type);

	state.v = atomic64_add_return_release(l[type].unlock_val,
					      &lock->state.counter);
	six_release(&lock->dep_map);
	six_lock_wakeup(lock, state, l[type].unlock_wakeup);
}

#ifdef SIX_LOCK_SEPARATE_LOCKFNS

#define __SIX_LOCK(type)						\
bool six_trylock_##type(struct six_lock *lock)				\
{									\
	return __six_trylock_type(lock, SIX_LOCK_##type);		\
}									\
									\
bool six_relock_##type(struct six_lock *lock, u32 seq)			\
{									\
	return __six_relock_type(lock, SIX_LOCK_##type, seq);		\
}									\
									\
void six_lock_##type(struct six_lock *lock)				\
{									\
	__six_lock_type(lock, SIX_LOCK_##type);				\
}									\
									\
void six_unlock_##type(struct six_lock *lock)				\
{									\
	__six_unlock_type(lock, SIX_LOCK_##type);			\
}

__SIX_LOCK(read)
__SIX_LOCK(intent)
__SIX_LOCK(write)

#undef __SIX_LOCK

#else

bool six_trylock_type(struct six_lock *lock, enum six_lock_type type)
{
	return __six_trylock_type(lock, type);
}

bool six_relock_type(struct six_lock *lock, enum six_lock_type type,
		     unsigned seq)
{
	return __six_relock_type(lock, type, seq);

}

void six_lock_type(struct six_lock *lock, enum six_lock_type type)
{
	__six_lock_type(lock, type);
}

void six_unlock_type(struct six_lock *lock, enum six_lock_type type)
{
	__six_unlock_type(lock, type);
}

#endif

/* Convert from intent to read: */
void six_lock_downgrade(struct six_lock *lock)
{
	six_lock_increment(lock, SIX_LOCK_read);
	six_unlock_intent(lock);
}

bool six_lock_tryupgrade(struct six_lock *lock)
{
	const struct six_lock_vals l[] = LOCK_VALS;
	union six_lock_state old, new;
	u64 v = READ_ONCE(lock->state.v);

	do {
		new.v = old.v = v;

		EBUG_ON(!(old.v & l[SIX_LOCK_read].held_mask));

		new.v += l[SIX_LOCK_read].unlock_val;

		if (new.v & l[SIX_LOCK_intent].lock_fail)
			return false;

		new.v += l[SIX_LOCK_intent].lock_val;
	} while ((v = atomic64_cmpxchg_acquire(&lock->state.counter,
				old.v, new.v)) != old.v);

	six_set_owner(lock, SIX_LOCK_intent, old);
	six_lock_wakeup(lock, new, l[SIX_LOCK_read].unlock_wakeup);

	return true;
}

bool six_trylock_convert(struct six_lock *lock,
			 enum six_lock_type from,
			 enum six_lock_type to)
{
	EBUG_ON(to == SIX_LOCK_write || from == SIX_LOCK_write);

	if (to == from)
		return true;

	if (to == SIX_LOCK_read) {
		six_lock_downgrade(lock);
		return true;
	} else {
		return six_lock_tryupgrade(lock);
	}
}

/*
 * Increment read/intent lock count, assuming we already have it read or intent
 * locked:
 */
void six_lock_increment(struct six_lock *lock, enum six_lock_type type)
{
	const struct six_lock_vals l[] = LOCK_VALS;

	EBUG_ON(type == SIX_LOCK_write);
	six_acquire(&lock->dep_map, 0);

	/* XXX: assert already locked, and that we don't overflow: */

	atomic64_add(l[type].lock_val, &lock->state.counter);
}
