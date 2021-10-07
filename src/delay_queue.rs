use crossbeam::channel;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

pub struct DelayQueue<T> {
    items: BTreeMap<Instant, T>,
}

impl<T> DelayQueue<T> {
    pub fn new() -> Self {
        Self {
            items: BTreeMap::new(),
        }
    }

    pub fn push_at(&mut self, t: Instant, i: T) {
        self.items.insert(t, i);
    }

    pub fn push_after(&mut self, d: Duration, i: T) {
        self.push_at(Instant::now() + d, i);
    }

    pub fn pop_at(&mut self, t: Instant) -> Option<T>
    where
        T: Default,
    {
        self.items.remove(&t)
    }

    pub fn pop(&mut self) -> Option<T>
    where
        T: Default,
    {
        let first_key = match self.items.keys().next() {
            Some(k) => *k,
            None => return None,
        };

        Some(self.pop_at(first_key).unwrap())
    }

    pub fn receiver(&self) -> channel::Receiver<Instant> {
        match self.items.keys().next() {
            Some(k) => channel::at(*k),
            None => channel::never(),
        }
    }
}

#[macro_export]
macro_rules! select_queues_internal {
    ( ($($munched:tt)*) (recv_queue($r:expr) -> $x:pat => $handler:block, $($rest:tt)*) ) => {
        $crate::select_queues_internal!(
            ( $($munched)* recv($r.receiver()) -> t_res => {
                let $x = t_res.map(|t| $r.pop_at(t).unwrap());
                $handler
            }, )
            ( $($rest)* )
        )
    };

    ( ($($munched:tt)*) (recv_queue($r:expr) -> $x:pat => $handler:expr, $($rest:tt)*) ) => {
        $crate::select_queues_internal!( ($($munched)*) (recv_queue($r) -> $x => { $handler }, $($rest)* ) );
    };

    ( ($($munched:tt)*) (recv($r:expr) -> $x:pat => $handler:block, $($rest:tt)*) ) => {
        $crate::select_queues_internal!(
            ( $($munched)* recv($r) -> $x => $handler, )
            ( $($rest)* )
        )
    };

    ( ($($munched:tt)*) (recv($r:expr) -> $x:pat => $handler:expr, $($rest:tt)*) ) => {
        $crate::select_queues_internal!( ($($munched)*) (recv($r) -> $x => { $handler }, $($rest)* ) );
    };

    ( ($($munched:tt)*) (default($t:expr) => $handler:block, $($rest:tt)*) ) => {
        $crate::select_queues_internal!(
            ( $($munched)* default($t) => $handler, )
            ( $($rest)* )
        )
    };

    ( ($($munched:tt)*) (default($t:expr) => $handler:expr, $($rest:tt)*) ) => {
        $crate::select_queues_internal!( ($($munched)*) (handler($t) => { $handler }, $($rest)* ) );
    };

    ( ($($munched:tt)*) () ) => {
        crossbeam::select!( $($munched)* )
    };
}

#[macro_export]
macro_rules! select_queues {
    ( $($input:tt)* ) => {
        $crate::select_queues_internal!( () ($($input)*) )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_the_next_entry() {
        let mut dq = DelayQueue::new();

        dq.push_after(Duration::from_millis(2), 2);
        dq.push_after(Duration::from_millis(1), 1);

        assert_eq!(dq.pop(), Some(1));
        assert_eq!(dq.pop(), Some(2));
        assert_eq!(dq.pop(), None);
    }

    #[test]
    fn returns_the_next_entry_from_at() {
        let mut dq = DelayQueue::new();

        let now = Instant::now();
        let t1 = now + Duration::from_millis(1);
        let t2 = now + Duration::from_millis(2);

        dq.push_at(t2, 2);
        dq.push_at(t1, 1);

        assert_eq!(dq.pop(), Some(1));
        assert_eq!(dq.pop(), Some(2));
        assert_eq!(dq.pop(), None);
    }

    #[test]
    fn channel_gives_time_for_next_entry() {
        let mut dq = DelayQueue::new();

        let now = Instant::now();
        let t1 = now + Duration::from_millis(1);
        let t2 = now + Duration::from_millis(2);

        dq.push_at(t2, 2);
        dq.push_at(t1, 1);

        let recv_t1 = dq.receiver().recv().unwrap();
        assert_eq!(recv_t1, t1);
        assert_eq!(dq.pop_at(recv_t1), Some(1));

        let recv_t2 = dq.receiver().recv().unwrap();
        assert_eq!(recv_t2, t2);
        assert_eq!(dq.pop_at(recv_t2), Some(2));
    }

    #[test]
    fn select_queues_unwraps_item() {
        let mut dq = DelayQueue::new();

        dq.push_after(Duration::from_millis(2), 2);
        dq.push_after(Duration::from_millis(1), 1);

        select_queues! {
            recv_queue(dq) -> i => assert_eq!(i.unwrap(), 1),
            default(Duration::from_millis(3)) => { panic!("recv_queue took too long") },
        };

        select_queues! {
            recv_queue(dq) -> i => assert_eq!(i.unwrap(), 2),
            default(Duration::from_millis(2)) => { panic!("recv_queue took too long") },
        };

        select_queues! {
            recv_queue(dq) -> _ => { panic!("recv_queue should have nothing left") },
            default(Duration::from_millis(2)) => {},
        };
    }

    #[test]
    fn select_queues_can_receive_from_normal_channel() {
        let mut dq = DelayQueue::new();

        dq.push_after(Duration::from_millis(2), 2);

        let t1 = Instant::now() + Duration::from_millis(1);
        let at = channel::at(t1);

        select_queues! {
            recv_queue(dq) -> _ => panic!("queue should not receive first"),
            recv(at) -> recv_t => { assert_eq!(recv_t.unwrap(), t1); },
            default(Duration::from_millis(3)) => { panic!("recv_queue took too long") },
        };

        select_queues! {
            recv_queue(dq) -> i => assert_eq!(i.unwrap(), 2),
            recv(at) -> _ => panic!("at should not receive again"),
            default(Duration::from_millis(2)) => { panic!("recv_queue took too long") },
        };

        select_queues! {
            recv_queue(dq) -> _ => panic!("queue should not receive again"),
            recv(at) -> _ => panic!("at should not receive again"),
            default(Duration::from_millis(1)) => {},
        };
    }
}
