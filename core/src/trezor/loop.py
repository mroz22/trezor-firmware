"""
Implements an event loop with cooperative multitasking and async I/O.  Tasks in
the form of python coroutines (either plain generators or `async` functions) are
stepped through until completion, and can get asynchronously blocked by
`yield`ing or `await`ing a syscall.

See `schedule`, `run`, and syscalls `sleep`, `wait`, `signal` and `race`.
"""

import utime
import utimeq

from trezor import io, log

if False:
    from typing import (
        Any,
        Awaitable,
        Callable,
        Coroutine,
        Dict,
        Generator,
        List,
        Optional,
        Set,
        Tuple,
    )

    Task = Coroutine
    Finalizer = Callable[[Task, Any], None]

# function to call after every task step
after_step_hook = None  # type: Optional[Callable[[], None]]

# tasks scheduled for execution in the future
_queue = utimeq.utimeq(64)

# tasks paused on I/O
_paused = {}  # type: Dict[int, Set[Task]]

# functions to execute after a task is finished
_finalizers = {}  # type: Dict[int, Finalizer]

if __debug__:
    # synthetic event queue
    synthetic_events = []  # type: List[Tuple[int, Any]]


class SyscallTimeout(Exception):
    pass


_TIMEOUT_ERROR = SyscallTimeout()


def schedule(
    task: Task, value: Any = None, *, deadline: int = None, finalizer: Finalizer = None
) -> None:
    """
    Schedule task to be executed with `value` on given `deadline` (in
    microseconds).  Does not start the event loop itself, see `run`.
    Usually done in very low-level cases, see `race` for more user-friendly
    and correct concept.
    """
    if deadline is None:
        deadline = utime.ticks_us()
    if finalizer is not None:
        _finalizers[id(task)] = finalizer
    _queue.push(deadline, task, value)


def pause(task: Task, iface: int) -> None:
    """
    Block task on given message interface.  Task is resumed when the interface
    is activated.  It is most probably wrong to call `pause` from user code,
    see the `wait` syscall for the correct concept.
    """
    tasks = _paused.get(iface, None)
    if tasks is None:
        tasks = _paused[iface] = set()
    tasks.add(task)


def finalize(task: Task, value: Any) -> None:
    """Call and remove any finalization callbacks registered for given task."""
    fn = _finalizers.pop(id(task), None)
    if fn is not None:
        fn(task, value)


def close(task: Task) -> None:
    """
    Unschedule and unblock a task, close it so it can release all resources, and
    call its finalizer.
    """
    for iface in _paused:
        _paused[iface].discard(task)
    _queue.discard(task)
    task.close()
    finalize(task, GeneratorExit())


def run() -> None:
    """
    Loop forever, stepping through scheduled tasks and awaiting I/O events
    in between.  Use `schedule` first to add a coroutine to the task queue.
    Tasks yield back to the scheduler on any I/O, usually by calling `await` on
    a `Syscall`.
    """
    task_entry = [0, 0, 0]  # deadline, task, value
    msg_entry = [0, 0]  # iface | flags, value
    while _queue or _paused:
        # compute the maximum amount of time we can wait for a message
        if _queue:
            delay = utime.ticks_diff(_queue.peektime(), utime.ticks_us())
        else:
            delay = 1000000  # wait for 1 sec maximum if queue is empty

        if __debug__:
            # process synthetic events
            if synthetic_events:
                iface, event = synthetic_events[0]
                msg_tasks = _paused.pop(iface, ())
                if msg_tasks:
                    synthetic_events.pop(0)
                    for task in msg_tasks:
                        _step(task, event)

        if io.poll(_paused, msg_entry, delay):
            # message received, run tasks paused on the interface
            msg_tasks = _paused.pop(msg_entry[0], ())
            for task in msg_tasks:
                _step(task, msg_entry[1])
        else:
            # timeout occurred, run the first scheduled task
            if _queue:
                _queue.pop(task_entry)
                _step(task_entry[1], task_entry[2])  # type: ignore
                # error: Argument 1 to "_step" has incompatible type "int"; expected "Coroutine[Any, Any, Any]"
                # rationale: We use untyped lists here, because that is what the C API supports.


def clear() -> None:
    """Clear all queue state.  Any scheduled or paused tasks will be forgotten."""
    _ = [0, 0, 0]
    while _queue:
        _queue.pop(_)
    _paused.clear()
    _finalizers.clear()


def _step(task: Task, value: Any) -> None:
    """
    Step through the task by sending value to it. This can result in either:
    1. The task raises an exception:
        a) StopIteration
            - The Task is completed and we call finalize() to finish it.
        b) Exception
            - An error occurred. We still need to call finalize().
    2. Task does not raise exception and returns either:
        a) Syscall
            - Syscall.handle() is called.
        b) None
            - The Task is simply scheduled to continue.
        c) Something else
            - This should not happen - error.
    """
    try:
        if isinstance(value, BaseException):
            result = task.throw(value)  # type: ignore
            # error: Argument 1 to "throw" of "Coroutine" has incompatible type "Exception"; expected "Type[BaseException]"
            # rationale: In micropython, generator.throw() accepts the exception object directly.
        else:
            result = task.send(value)
    except StopIteration as e:
        if __debug__:
            log.debug(__name__, "finish: %s", task)
        finalize(task, e.value)
    except Exception as e:
        if __debug__:
            log.exception(__name__, e)
        finalize(task, e)
    else:
        if isinstance(result, Syscall):
            result.handle(task)
        else:
            if __debug__:
                log.error(__name__, "unknown syscall: %s", result)
            raise RuntimeError
        if after_step_hook:
            after_step_hook()


class Syscall:
    """
    When tasks want to perform any I/O, or do any sort of communication with the
    scheduler, they do so through instances of a class derived from `Syscall`.
    """

    def __iter__(self) -> Task:  # type: ignore
        # support `yield from` or `await` on syscalls
        return (yield self)

    def __await__(self) -> Generator:
        return self.__iter__()  # type: ignore

    def handle(self, task: Task) -> None:
        pass


class sleep(Syscall):
    """
    Pause current task and resume it after given delay.  Although the delay is
    given in microseconds, sub-millisecond precision is not guaranteed.  Result
    value is the calculated deadline.

    Example:

    >>> planned = await loop.sleep(1000 * 1000)  # sleep for 1ms
    >>> print('missed by %d us', utime.ticks_diff(utime.ticks_us(), planned))
    """

    def __init__(self, delay_us: int) -> None:
        self.delay_us = delay_us

    def handle(self, task: Task) -> None:
        deadline = utime.ticks_add(utime.ticks_us(), self.delay_us)
        schedule(task, deadline, deadline=deadline)

YIELD = sleep(0)


class wait(Syscall):
    """
    Pause current task, and resume only after a message on `msg_iface` is
    received.  Messages are received either from an USB interface, or the
    touch display.  Result value is a tuple of message values.

    Example:

    >>> hid_report, = await loop.wait(0xABCD)  # await USB HID report
    >>> event, x, y = await loop.wait(io.TOUCH)  # await touch event
    """

    # The wait class implements a coroutine interface, so that it can be scheduled
    # as a regular task. When it is resumed, it can perform cleanup and then give
    # control back to the callback task.
    # By returning a Syscall instance that does nothing in its handle() method, it
    # ensures that the wait() instance will never be automatically resumed.
    _DO_NOT_RESCHEDULE = Syscall()
    _TIMEOUT_INDICATOR = object()

    def __init__(self, msg_iface: int, timeout_us: int = None) -> None:
        self.msg_iface = msg_iface
        self.timeout_us = timeout_us
        self.callback = None  # type: Optional[Task]

    def handle(self, task: Task) -> None:
        # We pause (and optionally schedule) ourselves instead of the calling task.
        # When resumed, send() or throw() will give control to the calling task,
        # after performing cleanup.
        pause(self, self.msg_iface)
        if self.timeout_us is not None:
            deadline = utime.ticks_add(utime.ticks_us(), self.timeout_us)
            schedule(self, wait._TIMEOUT_ERROR, deadline=deadline)

    def send(self, value) -> Any:
        assert self.callback is not None
        if value is wait._TIMEOUT_INDICATOR:
            # we were resumed from the timeout
            # discard the i/o wait
            _paused[self.msg_iface].discard(self)
            # convert the value to an exception
            value = _TIMEOUT_ERROR
        elif self.timeout_us is not None:
            # we were resumed from the i/o wait, AND timeout was specified
            # discard the scheduled timeout
            _queue.discard(self)
        _step(self.callback, value)
        return wait._DO_NOT_RESCHEDULE

    def throw(self, exception, _value=None, _traceback=None) -> None:
        assert self.callback is not None
        # An exception was thrown to us.
        # This should not happen unless (a) the i/o sent it, or (b) we were closed
        # externally.
        # Discard both the timeout and the i/o wait, because we don't know which
        # caused this, if any.
        _queue.discard(self)
        _paused[self.msg_iface].discard(self)
        # resume the callback anyway
        _step(self.callback, exception)
        return wait._DO_NOT_RESCHEDULE

    def close(self) -> None:
        pass

    def __iter__(self) -> Task:  # type: ignore
        try:
            return (yield self)
        except:  # noqa: E722
            # exception was raised on the waiting task externally with
            # close() or throw(), kill the children tasks and re-raise
            _queue.discard(self)
            _paused[self.msg_iface].discard(self)
            raise


_type_gen = type((lambda: (yield))())


class race(Syscall):
    """
    Given a list of either children tasks or syscalls, `race` waits until one of
    them completes (tasks are executed in parallel, syscalls are waited upon,
    directly).  Return value of `race` is the return value of the child that
    triggered the  completion.  Other running children are killed (by cancelling
    any pending schedules and raising a `GeneratorExit` by calling `close()`).
    Child that caused the completion is present in `self.finished`.

    Example:

    >>> # async def wait_for_touch(): ...
    >>> # async def animate_logo(): ...
    >>> touch_task = wait_for_touch()
    >>> animation_task = animate_logo()
    >>> racer = loop.race(touch_task, animation_task)
    >>> result = await racer
    >>> if animation_task in racer.finished:
    >>>     print('animation task returned value:', result)
    >>> elif touch_task in racer.finished:
    >>>     print('touch task returned value:', result)

    Note: You should not directly `yield` a `race` instance, see logic in
    `race.__iter__` for explanation.  Always use `await`.
    """

    def __init__(self, *children: Awaitable) -> None:
        self.children = children
        self.scheduled = []  # type: List[Task]  # scheduled wrapper tasks
        self.finished = False

    def handle(self, task: Task) -> None:
        """
        Schedule all children Tasks and set `task` as callback.
        """
        finalizer = self._finish
        scheduled = self.scheduled

        self.callback = task
        scheduled.clear()
        self.finished = False

        for child in self.children:
            # # short-circuit syscalls.
            # if isinstance(child, Syscall):
            #     child_task = self._resume_subtask(child)
            #     # child_task is a coroutine, we must activate it
            #     next(child_task)

            #     scheduled.append(child_task)
            #     child.handle(child_task)
            #     continue

            if isinstance(child, _type_gen):
                child_task = child
            else:
                child_task = iter(child)  # type: ignore
            schedule(child_task, finalizer=finalizer)  # type: ignore
            scheduled.append(child_task)  # type: ignore
            # TODO: document the types here

    def _resume_subtask(self, child: Awaitable) -> None:
        callback = self.callback
        value = yield
        print(hash(self), "subtask", child, "resumed with", value)
        if not self.finished:
            self.finished.append(child)
            if self.exit_others:
                self.exit(child)

            _step(callback, value)

    def exit(self, except_for: Awaitable = None) -> None:
        for task in self.scheduled:
            if task != except_for:
                close(task)

    def _finish(self, task: Task, result: Any) -> None:
        if not self.finished:
            self.finished = True
            self.exit(task)
            # Result can be GeneratorExit (see finalize()), which causes the resumed
            # callback to exit cleanly.
            schedule(self.callback, result)

    def __iter__(self) -> Task:  # type: ignore
        try:
            return (yield self)
        except:  # noqa: E722
            # exception was raised on the waiting task externally with
            # close() or throw(), kill the children tasks and re-raise
            self.exit()
            raise


class chan:
    """
    Two-ended channel.
    The receiving end pauses until a value to be received is available. The sending end
    can choose to wait until the value is received, or it can publish the value without
    waiting.

    Example:

    >>> # in task #1:
    >>> signal = loop.chan()
    >>> while True:
    >>>     result = await signal.take()
    >>>     print("awaited result:", result)

    >>> # in task #2:
    >>> signal.publish("Published without waiting")
    >>> print("publish completed")
    >>> await signal.put("Put with await")
    >>> print("put completed")

    Example Output:

    publish completed
    awaited result: Published without waiting
    awaited result: Put with await
    put completed
    """

    class Put(Syscall):
        def __init__(self, ch: "chan", value: Any) -> None:
            self.ch = ch
            self.value = value
            self.task = None  # type: Optional[Task]

        def handle(self, task: Task) -> None:
            self.task = task
            self.ch._schedule_put(task, self.value)

    class Take(Syscall):
        def __init__(self, ch: "chan") -> None:
            self.ch = ch
            self.task = None  # type: Optional[Task]

        def handle(self, task: Task) -> None:
            self.task = task
            self.ch._schedule_take(task)

    def __init__(self) -> None:
        self.putters = []  # type: List[Tuple[Optional[Task], Any]]
        self.takers = []  # type: List[Task]

    def put(self, value: Any) -> Awaitable[None]:  # type: ignore
        put = chan.Put(self, value)
        try:
            return (yield put)
        except:  # noqa: E722
            entry = (put.task, value)
            if entry in self.putters:
                self.putters.remove(entry)
            raise

    def take(self) -> Awaitable[Any]:  # type: ignore
        take = chan.Take(self)
        try:
            return (yield take)
        except:  # noqa: E722
            if take.task in self.takers:
                self.takers.remove(take.task)
            raise

    def publish(self, value: Any) -> None:
        if self.takers:
            taker = self.takers.pop(0)
            schedule(taker, value)
        else:
            self.putters.append((None, value))

    def _schedule_put(self, putter: Task, value: Any) -> bool:
        if self.takers:
            taker = self.takers.pop(0)
            schedule(taker, value)
            schedule(putter)
            return True
        else:
            self.putters.append((putter, value))
            return False

    def _schedule_take(self, taker: Task) -> None:
        if self.putters:
            putter, value = self.putters.pop(0)
            schedule(taker, value)
            if putter is not None:
                schedule(putter)
        else:
            self.takers.append(taker)
