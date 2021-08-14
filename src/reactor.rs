/// This module implements a simple, channel-based event loop.
use anyhow::Result as AHResult;
use crossbeam::channel::{after, Receiver, Select};
use std::cell::RefCell;
use std::cmp::{Ord, Ordering, PartialOrd};
use std::collections::{BinaryHeap, HashMap};
use std::rc::Rc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AfterId(usize);

struct After<'a> {
    handler: Box<dyn FnMut(TimeReactorHandle) + 'a>,
}

#[derive(Eq, PartialEq)]
struct AfterInstance {
    at: Instant,
    after_id: AfterId,
}

impl Ord for AfterInstance {
    fn cmp(&self, other: &AfterInstance) -> Ordering {
        self.at.cmp(&other.at).reverse()
    }
}

impl PartialOrd<Self> for AfterInstance {
    fn partial_cmp(&self, other: &AfterInstance) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct TimeReactorInner<'a> {
    next_handle: usize,
    afters: HashMap<AfterId, After<'a>>,
    upcoming: BinaryHeap<AfterInstance>,
}

pub struct TimeReactor<'a> {
    inner: Rc<RefCell<TimeReactorInner<'a>>>,
}

impl<'a> TimeReactor<'a> {
    pub fn new() -> Self {
        Self {
            inner: Rc::new(RefCell::new(TimeReactorInner {
                next_handle: 0,
                afters: HashMap::new(),
                upcoming: BinaryHeap::new(),
            })),
        }
    }

    pub fn handle(&self) -> TimeReactorHandle<'a> {
        TimeReactorHandle {
            inner: self.inner.clone(),
        }
    }

    pub fn run(&self) {
        let mut inner = self.inner.borrow_mut();

        loop {
            let now = Instant::now();
            if let Some(instance) = inner.upcoming.pop() {
                if now < instance.at {
                    dbg!(instance.at - Instant::now());
                    std::thread::sleep(instance.at - Instant::now());
                }
                (inner.afters.get_mut(&instance.after_id).unwrap().handler)(self.handle());
            } else {
                break;
            }
        }
    }
}

pub struct TimeReactorHandle<'a> {
    inner: Rc<RefCell<TimeReactorInner<'a>>>,
}

impl<'a> TimeReactorHandle<'a> {
    pub fn after(
        &self,
        duration: Duration,
        handler: impl FnMut(TimeReactorHandle) + 'a,
    ) -> AfterId {
        let mut inner = self.inner.borrow_mut();

        let after_id = AfterId(inner.next_handle);
        inner.next_handle += 1;

        inner.afters.insert(
            after_id,
            After {
                handler: Box::new(handler),
            },
        );

        inner.upcoming.push(AfterInstance {
            at: Instant::now() + duration,
            after_id,
        });

        after_id
    }

    pub fn stop(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_reactor_handles_one_after() -> AHResult<()> {
        let received = Rc::new(RefCell::new(false));

        let time_reactor = TimeReactor::new();

        let handle = time_reactor.handle();

        let inner_received = received.clone();

        handle.after(Duration::from_millis(1), move |handle| {
            inner_received.replace(true);
            handle.stop();
        });
        time_reactor.run();

        assert_eq!(*received.borrow(), true);

        Ok(())
    }

    #[test]
    fn time_reactor_handles_two_afters_in_right_order() -> AHResult<()> {
        let received = Rc::new(RefCell::new(Vec::new()));

        let time_reactor = TimeReactor::new();

        let handle = time_reactor.handle();

        let inner_received1 = received.clone();
        handle.after(Duration::from_millis(2), move |handle| {
            inner_received1.borrow_mut().push(2);
            handle.stop();
        });

        let inner_received2 = received.clone();
        handle.after(Duration::from_millis(1), move |handle| {
            inner_received2.borrow_mut().push(1);
            handle.stop();
        });
        time_reactor.run();

        assert_eq!(*received.borrow(), vec![1, 2]);

        Ok(())
    }
}
