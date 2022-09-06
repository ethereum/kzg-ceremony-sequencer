use indexmap::IndexSet;
use std::fmt::Debug;
use std::hash::Hash;

// A simple queue structure
#[derive(Debug)]
pub struct Queue<T: Hash + Eq + Clone + Debug> {
    inner: IndexSet<T>,
}

impl<T: Hash + Eq + Clone + Debug> Default for Queue<T> {
    fn default() -> Self {
        Self {
            inner: Default::default(),
        }
    }
}

impl<T: Hash + Eq + Clone + Debug> Queue<T> {
    pub(crate) fn add_participant(&mut self, participant_id: T) -> Option<usize> {
        let queue_size = self.inner.len();
        if !self.inner.insert(participant_id) {
            return None;
        };
        return Some(queue_size + 1);
    }
    pub(crate) fn remove_participant_at_front(&mut self) -> Option<T> {
        self.inner.shift_remove_index(0)
    }

    pub(crate) fn get_first_n(&self, n: usize) -> Vec<T> {
        let mut participants = Vec::new();
        for i in 0..n {
            match self.inner.get_index(i) {
                Some(p_id) => participants.push(p_id.clone()),
                None => return participants,
            }
        }
        participants
    }

    pub(crate) fn is_already_in_queue(&self, participant_id: &T) -> bool {
        self.inner.get(participant_id).is_some()
    }

    pub(crate) fn find_participant(&self, participant_id: &T) -> Option<usize> {
        self.inner.get_index_of(participant_id)
    }

    pub(crate) fn front(&self) -> Option<&T> {
        self.inner.get_index(0)
    }
    pub(crate) fn num_participants(&self) -> usize {
        self.inner.len()
    }

    pub(crate) fn remove(&mut self, participant_id: &T) {
        self.inner.shift_remove(participant_id);
    }
}

#[test]
fn add_remove() {
    let mut queue = Queue::default();
    let to_add = 32;
    for i in 0..to_add {
        queue.add_participant(i);
    }

    assert_eq!(to_add, queue.num_participants());

    for i in 0..to_add {
        let removed = queue.remove_participant_at_front().unwrap();
        assert_eq!(i, removed)
    }
    assert_eq!(0, queue.num_participants());
}
#[test]
fn add_duplicate() {
    // Since we are using a set, its not possible to
    // add duplicate entries to the queue. The defined
    // behaviour is that the position returned will be None
    // if a duplicate has been added
    let mut queue = Queue::default();

    queue.add_participant(0);
    queue.add_participant(1);

    let position = queue.add_participant(0);
    assert!(position.is_none());

    assert_eq!(2, queue.num_participants());
}

#[test]
fn inclusion() {
    let mut queue = Queue::default();
    let to_add = 320;
    for i in 0..to_add {
        queue.add_participant(i);
    }

    for i in 0..to_add {
        assert!(queue.is_already_in_queue(&i))
    }
}

#[test]
fn remove_order_same() {
    // Removing entries from the queue should not change
    // the relative order of the queue
    let mut queue = Queue::default();
    let to_add = 32;
    for i in 0..to_add {
        queue.add_participant(i);
    }

    // Remove the odd numbers
    for i in 0..to_add {
        if i % 2 == 1 {
            queue.remove(&i);
        }
    }

    // The queue should have half the number of entries
    let num_participants = queue.num_participants();
    assert_eq!(to_add / 2, num_participants);

    let even_numbers = (0..to_add).filter(|i| i % 2 == 0);

    for (entry, expected_entry) in queue
        .get_first_n(num_participants)
        .into_iter()
        .zip(even_numbers)
    {
        assert_eq!(entry, expected_entry)
    }
}
