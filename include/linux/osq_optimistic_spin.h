#ifndef __LINUX_OSQ_OPTIMISTIC_SPIN_H
#define __LINUX_OSQ_OPTIMISTIC_SPIN_H

#include <linux/sched.h>
#include <linux/sched/rt.h>

#ifdef CONFIG_LOCK_SPIN_ON_OWNER

typedef struct task_struct *(*osq_get_owner_fn)(struct optimistic_spin_queue *osq);
typedef bool (*osq_trylock_fn)(struct optimistic_spin_queue *osq);

#define OWNER_NO_SPIN		((struct task_struct *) 1UL)

static inline bool osq_owner_on_cpu(struct task_struct *owner)
{
	/*
	 * As lock holder preemption issue, we both skip spinning if
	 * task is not on cpu or its cpu is preempted
	 */
	return owner->on_cpu && !vcpu_is_preempted(task_cpu(owner));
}

static inline bool osq_can_spin_on_owner(struct optimistic_spin_queue *lock,
					 osq_get_owner_fn get_owner)
{
	struct task_struct *owner;
	bool ret;

	if (need_resched())
		return false;

	rcu_read_lock();
	owner = get_owner(lock);
	/*
	 * if lock->owner is not set, the lock owner may have just acquired
	 * it and not set the owner yet, or it may have just been unlocked
	 */
	if (!owner)
		ret = true;
	else if (owner == OWNER_NO_SPIN)
		ret = false;
	else
		ret = osq_owner_on_cpu(owner);
	rcu_read_unlock();

	return ret;
}

static inline bool osq_spin_on_owner(struct optimistic_spin_queue *lock,
				     struct task_struct *owner,
				     osq_get_owner_fn get_owner)
{
	if (!owner)
		return true;

	if (owner == OWNER_NO_SPIN)
		return false;

	while (1) {
		/*
		 * Ensure we emit the owner->on_cpu, dereference _after_
		 * checking lock->owner still matches owner. If that fails,
		 * owner might point to freed memory. If it still matches,
		 * the rcu_read_lock() ensures the memory stays valid.
		 */
		barrier();
		if (get_owner(lock) != owner)
			return true;

		if (need_resched() || !osq_owner_on_cpu(owner))
			return false;

		cpu_relax();
	}
}

static inline bool osq_optimistic_spin(struct optimistic_spin_queue *lock,
				       osq_get_owner_fn get_owner,
				       osq_trylock_fn trylock)
{
	struct task_struct *task = current;

	preempt_disable();
	if (!osq_can_spin_on_owner(lock, get_owner))
		goto fail;

	if (!osq_lock(lock))
		goto fail;

	while (1) {
		struct task_struct *owner;

		/*
		 * If there's an owner, wait for it to either
		 * release the lock or go to sleep.
		 */
		rcu_read_lock();
		owner = get_owner(lock);
		if (!osq_spin_on_owner(lock, owner, get_owner)) {
			rcu_read_unlock();
			break;
		}
		rcu_read_unlock();

		if (trylock(lock)) {
			osq_unlock(lock);
			preempt_enable();
			return true;
		}

		/*
		 * When there's no owner, we might have preempted between the
		 * owner acquiring the lock and setting the owner field. If
		 * we're an RT task that will live-lock because we won't let
		 * the owner complete.
		 */
		if (!owner && (need_resched() || rt_task(task)))
			break;

		/*
		 * The cpu_relax() call is a compiler barrier which forces
		 * everything in this loop to be re-loaded. We don't need
		 * memory barriers as we'll eventually observe the right
		 * values at the cost of a few extra spins.
		 */
		cpu_relax();
	}

	osq_unlock(lock);
fail:
	preempt_enable();

	/*
	 * If we fell out of the spin path because of need_resched(),
	 * reschedule now, before we try-lock again. This avoids getting
	 * scheduled out right after we obtained the lock.
	 */
	if (need_resched())
		schedule();

	return false;
}

static inline bool osq_has_spinner(struct optimistic_spin_queue *lock)
{
	return osq_is_locked(lock);
}

#else /* CONFIG_LOCK_SPIN_ON_OWNER */

static inline bool osq_optimistic_spin(struct six_lock *lock, enum six_lock_type type)
{
	return false;
}

static inline bool osq_has_spinner(struct optimistic_spin_queue *lock)
{
	return false;
}

#endif

#endif /* __LINUX_OSQ_OPTIMISTIC_SPIN_H */
