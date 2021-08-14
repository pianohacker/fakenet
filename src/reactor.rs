/// This module implements a simple, channel-based event loop.
use crossbeam::channel::{after, Receiver};
use std::cell::RefCell;
use std::cmp::{Ord, Ordering, PartialOrd};
use std::collections::{BinaryHeap, HashMap};
use std::rc::Rc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ScheduledHandle(usize);

struct Scheduled<'a, T> {
    handler: Rc<Box<dyn Fn(TimeReactorHandle<'a, T>) + 'a>>,
    cancelled: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct ScheduledInstance {
    at: Instant,
    after_id: ScheduledHandle,
}

impl Ord for ScheduledInstance {
    fn cmp(&self, other: &ScheduledInstance) -> Ordering {
        self.at.cmp(&other.at).reverse()
    }
}

impl PartialOrd<Self> for ScheduledInstance {
    fn partial_cmp(&self, other: &ScheduledInstance) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct TimeReactorState<'a, T> {
    next_handle: usize,
    scheduled: HashMap<ScheduledHandle, Scheduled<'a, T>>,
    upcoming: BinaryHeap<ScheduledInstance>,
    event_handlers: Vec<Rc<Box<dyn Fn(TimeReactorHandle<T>, &T) + 'a>>>,
    running: bool,
}

impl<'a, T> TimeReactorState<'a, T> {
    fn schedule(&mut self, at: Instant, after_id: ScheduledHandle) {
        self.upcoming.push(ScheduledInstance { at, after_id });
    }

    fn at(
        &mut self,
        instant: Instant,
        handler: impl Fn(TimeReactorHandle<'a, T>) + 'a,
    ) -> ScheduledHandle {
        let after_id = ScheduledHandle(self.next_handle);
        self.next_handle += 1;

        self.scheduled.insert(
            after_id,
            Scheduled {
                cancelled: false,
                handler: Rc::new(Box::new(handler)),
            },
        );

        self.schedule(instant, after_id);

        after_id
    }

    fn cancel(&mut self, scheduled_handle: ScheduledHandle) {
        if let Some(scheduled) = self.scheduled.get_mut(&scheduled_handle) {
            scheduled.cancelled = true;
        }
    }
}

pub struct TimeReactor<'a, T> {
    created_at: Instant,
    event_receiver: Receiver<T>,
    state: Rc<RefCell<TimeReactorState<'a, T>>>,
}

impl<'a, T> TimeReactor<'a, T> {
    pub fn new(event_receiver: Receiver<T>) -> Self {
        Self {
            created_at: Instant::now(),
            event_receiver,
            state: Rc::new(RefCell::new(TimeReactorState {
                next_handle: 0,
                scheduled: HashMap::new(),
                upcoming: BinaryHeap::new(),
                event_handlers: Vec::new(),
                running: false,
            })),
        }
    }

    pub fn handle(&self) -> TimeReactorHandle<'a, T> {
        TimeReactorHandle {
            state: self.state.clone(),
        }
    }

    fn get_next_schedule(
        &self,
    ) -> Option<(
        ScheduledInstance,
        bool,
        Rc<Box<dyn Fn(TimeReactorHandle<'a, T>) + 'a>>,
    )> {
        {
            let state = self.state.borrow_mut();

            state.upcoming.peek().map(|n| *n)
        }
        .map(|instance| {
            let state = self.state.borrow();
            let scheduled = state.scheduled.get(&instance.after_id).unwrap();

            (instance, scheduled.cancelled, scheduled.handler.clone())
        })
    }

    fn drop_next(&self, instance: ScheduledInstance) {
        let mut state = self.state.borrow_mut();
        assert!(state.upcoming.pop().unwrap().after_id == instance.after_id);
        state.scheduled.remove(&instance.after_id);
    }

    fn handle_event(&self, event: T) {
        let receivers: Vec<_> = self
            .state
            .borrow()
            .event_handlers
            .iter()
            .map(|h| h.clone())
            .collect();

        for handler in receivers {
            handler(self.handle(), &event);
        }
    }

    pub fn run(&self) {
        self.state.borrow_mut().running = true;

        while self.state.borrow().running {
            let now = Instant::now();
            if let Some((instance, cancelled, handler)) = self.get_next_schedule() {
                crossbeam::select!(
                    recv(after(instance.at.saturating_duration_since(now))) -> fired_at => {
                        assert!(fired_at.unwrap() > instance.at);
                        self.drop_next(instance);
                        if !cancelled {
                            handler(self.handle());
                        }
                    },

                    recv(self.event_receiver) -> event => {
                        match event {
                            Ok(event) => self.handle_event(event),
                            Err(e) => panic!("failed to recv: {}", e)
                        }
                    }
                );
            } else {
                let event = self.event_receiver.recv().expect("failed to receive");
                self.handle_event(event);
            }
        }
    }
}

pub struct TimeReactorHandle<'a, T> {
    state: Rc<RefCell<TimeReactorState<'a, T>>>,
}

impl<'a, T> TimeReactorHandle<'a, T> {
    pub fn after(
        &self,
        duration: Duration,
        handler: impl Fn(TimeReactorHandle<'a, T>) + 'a,
    ) -> ScheduledHandle {
        self.at(Instant::now() + duration, handler)
    }

    pub fn at(
        &self,
        instant: Instant,
        handler: impl Fn(TimeReactorHandle<'a, T>) + 'a,
    ) -> ScheduledHandle {
        self.state.borrow_mut().at(instant, handler)
    }

    pub fn cancel(&self, scheduled_handle: ScheduledHandle) {
        self.state.borrow_mut().cancel(scheduled_handle)
    }

    pub fn on_event(&self, handler: impl Fn(TimeReactorHandle<T>, &T) + 'a) {
        let mut state = self.state.borrow_mut();

        state.event_handlers.push(Rc::new(Box::new(handler)));
    }

    pub fn stop(&self) {
        self.state.borrow_mut().running = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result as AHResult;
    use crossbeam::channel::{never, unbounded};

    #[derive(Clone)]
    struct ShareableQueue(Rc<RefCell<Vec<usize>>>);

    impl ShareableQueue {
        fn new() -> Self {
            Self(Rc::new(RefCell::new(Vec::new())))
        }

        fn push(&self, value: usize) {
            self.0.borrow_mut().push(value);
        }

        fn into_vec(&self) -> Vec<usize> {
            self.0.borrow().clone()
        }

        fn pusher_and_stopper(&self, value: usize) -> impl Fn(TimeReactorHandle<usize>) + '_ {
            move |handle| {
                self.push(value);
                handle.stop();
            }
        }

        fn pusher(&self, value: usize) -> impl Fn(TimeReactorHandle<usize>) + '_ {
            move |_| {
                self.push(value);
            }
        }
    }

    #[test]
    fn time_reactor_handles_one_after() -> AHResult<()> {
        let received = ShareableQueue::new();

        let receiver = never();
        let time_reactor = TimeReactor::new(receiver);

        let handle = time_reactor.handle();
        handle.after(Duration::from_millis(1), received.pusher_and_stopper(1));
        time_reactor.run();

        assert_eq!(received.into_vec(), vec![1]);

        Ok(())
    }

    #[test]
    fn time_reactor_handles_multiple_afters_in_right_order() -> AHResult<()> {
        let received = ShareableQueue::new();

        let receiver = never();
        let time_reactor = TimeReactor::new(receiver);

        let handle = time_reactor.handle();

        let start = Instant::now();
        for ns in (1..10usize).rev() {
            let after_id = handle.at(start + Duration::from_nanos(ns as u64), received.pusher(ns));
            dbg!(ns, after_id);
        }

        handle.after(Duration::from_nanos(10), received.pusher_and_stopper(10));

        time_reactor.run();

        assert_eq!(received.into_vec(), vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        Ok(())
    }

    #[test]
    fn time_reactor_can_add_timeout_inside_timeout() -> AHResult<()> {
        let received = ShareableQueue::new();

        let receiver = never();
        let time_reactor = TimeReactor::new(receiver);

        let handle = time_reactor.handle();
        handle.after(Duration::from_millis(1), |handle| {
            received.push(1);
            handle.after(Duration::from_millis(1), received.pusher_and_stopper(2));
        });

        time_reactor.run();

        assert_eq!(received.into_vec(), vec![1, 2]);

        Ok(())
    }

    #[test]
    fn time_reactor_can_cancel() -> AHResult<()> {
        let received = ShareableQueue::new();

        let receiver = never();
        let time_reactor = TimeReactor::new(receiver);

        let handle = time_reactor.handle();
        let scheduled = handle.after(Duration::from_millis(1), received.pusher_and_stopper(1));
        handle.after(Duration::from_millis(2), received.pusher(2));
        handle.after(Duration::from_millis(3), received.pusher_and_stopper(3));

        handle.cancel(scheduled);

        time_reactor.run();

        assert_eq!(received.into_vec(), vec![2, 3]);

        Ok(())
    }

    #[test]
    fn time_reactor_double_cancel_does_not_panic() -> AHResult<()> {
        let received = ShareableQueue::new();

        let receiver = never();
        let time_reactor = TimeReactor::new(receiver);

        let handle = time_reactor.handle();
        let scheduled = handle.after(Duration::from_millis(1), received.pusher_and_stopper(1));

        handle.cancel(scheduled);
        handle.cancel(scheduled);

        Ok(())
    }

    #[test]
    fn time_reactor_cancel_after_fire_does_not_panic() -> AHResult<()> {
        let received = ShareableQueue::new();

        let receiver = never();
        let time_reactor = TimeReactor::new(receiver);

        let handle = time_reactor.handle();
        let scheduled = handle.after(Duration::from_millis(1), received.pusher(1));
        let s2 = scheduled.clone();
        handle.after(Duration::from_millis(2), move |handle| {
            handle.cancel(s2);
            handle.stop();
        });

        time_reactor.run();

        Ok(())
    }

    #[test]
    fn time_reactor_can_stop() -> AHResult<()> {
        let received = ShareableQueue::new();

        let receiver = never();
        let time_reactor = TimeReactor::new(receiver);

        let handle = time_reactor.handle();
        handle.after(Duration::from_millis(2), received.pusher(2));
        handle.after(Duration::from_millis(1), received.pusher_and_stopper(1));

        time_reactor.run();

        assert_eq!(received.into_vec(), vec![1]);

        Ok(())
    }

    #[test]
    fn time_reactor_forwards_event() -> AHResult<()> {
        let received = ShareableQueue::new();

        let (sender, receiver) = unbounded();
        let time_reactor = TimeReactor::new(receiver);

        let handle = time_reactor.handle();
        handle.on_event(|handle, value| {
            received.push(*value);
            handle.stop();
        });

        sender.send(1).unwrap();
        time_reactor.run();

        assert_eq!(received.into_vec(), vec![1]);

        Ok(())
    }

    #[test]
    #[ntest::timeout(100)]
    fn time_reactor_forwards_events_and_afters() -> AHResult<()> {
        let received = ShareableQueue::new();

        let (sender, receiver) = unbounded();
        let time_reactor = TimeReactor::new(receiver);

        let handle = time_reactor.handle();
        handle.on_event(|_, value| {
            received.push(*value);
        });
        handle.after(Duration::from_millis(2), received.pusher_and_stopper(2));

        sender.send(1).unwrap();
        time_reactor.run();

        assert_eq!(received.into_vec(), vec![1, 2]);

        Ok(())
    }

    #[test]
    #[ntest::timeout(100)]
    fn time_reactor_can_cancel_when_receiving_events() -> AHResult<()> {
        let received = ShareableQueue::new();

        let (sender, receiver) = unbounded();
        let time_reactor = TimeReactor::new(receiver);

        let handle = time_reactor.handle();
        let scheduled = handle.after(Duration::from_millis(2), received.pusher_and_stopper(2));
        let r2 = &received;
        handle.on_event(move |handle, value| {
            r2.push(*value);
            handle.cancel(scheduled);
        });
        handle.after(Duration::from_millis(3), received.pusher_and_stopper(3));

        sender.send(1).unwrap();
        time_reactor.run();

        assert_eq!(received.into_vec(), vec![1, 3]);

        Ok(())
    }
}
