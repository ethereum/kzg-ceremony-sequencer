use std::{collections::HashMap, time::Duration};

use crate::queue::ActiveZoneCheckPoint;
use indexmap::IndexMap;
use tokio::time::{self, Instant};

pub type ParticipantId = String;

// TODO: change time from usize to Duration so we know the units
pub struct Config {
    // If the queue is larger than this threshold,
    // then participants are added to the dormant zone
    active_zone_threshold: usize,
    // In seconds,
    // This is the amount of time that each participant
    // can take since their last ping
    active_zone_last_ping_deadline: usize,
    // In seconds,
    // This is the the amount of time that a participant
    // has to check-in since they moved into the active zone
    dormant_active_deadline: usize,
    // In seconds,
    // This is the amount of time that a participant
    // has to check-in since they moved into the compute zone
    active_compute_deadline: usize,
}

// Represents the Queue that the coordinator will use to store information about
// contributors
pub struct Queue {
    config: Config,
    // A Map of participants and what zones they are in
    inner: IndexMap<ParticipantId, Zone>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
// The queue is split into three zones
// depending on the zone, the participant
// is required to do different tasks
pub enum Zone {
    // The dormant zone is the part of the queue where participants
    // can go offline and come back. They are not required to ping
    // the co-ordinator
    Dormant,
    // The active zone is the part of the queue where participants
    // need to periodically ping the coordinator until they reach
    // the compute zone.
    //
    // A participant must ping the coordinator when they are entering the
    // active zone
    Active(CheckInReq),
    // The compute zone holds on participant at any given time.
    // Here the participant must ping the co-ordinator once they have completed
    // their task.
    Compute(CheckInReq),
}

impl Zone {
    pub fn request_expired(&self) -> bool {
        match self {
            Zone::Dormant => {
                unreachable!("calling has_expired in dormant zone is indicative of a bug")
            }
            Zone::Active(req) | Zone::Compute(req) => req.expired(),
        }
    }

    pub fn transition(&self) -> Result<Zone, ()> {
        match self {
            Zone::Dormant => Ok(Zone::Active(CheckInReq::transition_expiry())),
            Zone::Active(req) => {
                if req.expired() {
                    return Err(());
                }
                // We should not transition to the next
                // Zone, if they already have a transition request for the current
                // zone
                if req.is_transition_req() {
                    return Err(());
                }
                Ok(Zone::Compute(CheckInReq::transition_expiry()))
            }
            Zone::Compute(_) => unreachable!(),
        }
    }
}

impl Zone {
    fn is_compute(&self) -> bool {
        if let Zone::Compute { .. } = self {
            true
        } else {
            false
        }
    }
    fn is_active(&self) -> bool {
        if let Zone::Active { .. } = self {
            true
        } else {
            false
        }
    }
    fn is_dormant(&self) -> bool {
        if let Zone::Dormant = self {
            true
        } else {
            false
        }
    }
}

impl Queue {
    pub fn new(config: Config) -> Self {
        Queue {
            config,
            inner: Default::default(),
        }
    }
    // Add a participant to the queue and compute their Zone
    pub fn add_participant(&mut self, participant_id: ParticipantId) -> (usize, Zone) {
        let queue_size = self.len();
        let participant_zone = self.compute_zone(queue_size);
        self.inner.insert(participant_id.clone(), participant_zone);

        // TODO: Maybe we should return the Zone here

        (queue_size, participant_zone)
    }

    // Returns the size of the queue
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    // Computes the zone that this position in the queue
    // will be at.
    // Plus the request
    fn compute_zone(&self, position: usize) -> Zone {
        if position == 0 {
            Zone::Compute(CheckInReq::imalive_expiry())
        } else if position <= self.config.active_zone_threshold {
            Zone::Active(CheckInReq::imalive_expiry())
        } else {
            Zone::Dormant
        }
    }

    // Gets the participant at `position` in queue
    // Returns None if there is no-one at that position
    fn get_participant_at_position(&self, position: usize) -> Option<(&ParticipantId, &Zone)> {
        self.inner.get_index(position)
    }
    fn get_mut_participant_at_position(
        &mut self,
        position: usize,
    ) -> Option<(&mut ParticipantId, &mut Zone)> {
        self.inner.get_index_mut(position)
    }
    fn get_mut_participant_at_front(&mut self) -> Option<(&mut ParticipantId, &mut Zone)> {
        self.get_mut_participant_at_position(0)
    }
    fn get_mut_participant_at_end_of_active_zone(
        &mut self,
    ) -> Option<(&mut ParticipantId, &mut Zone)> {
        self.get_mut_participant_at_position(self.config.active_zone_threshold)
    }

    // Check if any of the participants have extended the deadline
    async fn dormant_to_active_cleanse(&mut self) {
        // Check every `deadline` seconds. This does mean that some participants
        // will have more time, if they expire just after this function has finished
        // checking.
        //
        // TODO: we can fix this by having a handler for each participant that
        // TODO: references the queue and it will delete that person from the queue
        // TODO: if they do not call a function to stop it
        let deadline = Duration::from_secs(self.config.dormant_active_deadline as u64);
        let mut interval = time::interval(deadline);
        loop {
            interval.tick().await;
            let mut participants = Vec::new();
            // This is all of the people in the compute and active zone
            let queue = self
                .inner
                .iter()
                .take(self.config.active_zone_threshold + 1);

            for (id, zone) in queue {
                if zone.request_expired() {
                    participants.push(id.clone())
                }
            }
            self.remove_participants_from_active_zone(participants);
        }
    }
    // Advance the queue by removing the person in the compute zone
    // and moving everyone up one.
    // Two people should changes zones after this function has executed
    pub fn advance_queue(&mut self) {
        // First remove the participant in the active zone
        self.remove_participant_in_active_zone();

        // change the person who was at the front of the active zone
        // to now be in the compute zone
        self.entered_compute_zone();

        // change the person who was at the front of the dormant zone
        // to be in the active zone
        self.entered_active_zone();
    }

    // Precondition: A person has just been moved into the compute zone
    //
    // This method will then change their state to match this
    // and set any deadlines that are necessary
    //
    // In  particular, we set a transition check-in request
    // and check that they came from the active zone
    fn entered_compute_zone(&mut self) -> Option<ParticipantId> {
        self.maybe_entered_compute_zone(true)
    }
    fn maybe_entered_compute_zone(&mut self, assert_active: bool) -> Option<ParticipantId> {
        // Change the zone of the new person at the top
        let (id, zone) = match self.get_mut_participant_at_front() {
            Some(participant) => participant,
            None => {
                // This is the case where there is no-one else left in the queue
                //
                // We can simply return here
                return None;
            }
        };
        if assert_active {
            assert!(zone.is_active());
        }
        *zone = Zone::Compute(CheckInReq::transition_expiry());
        Some(id.clone())
    }

    // Change a participant from being a dormant to active
    // if:
    // - The participant is not in the queue
    // Panics if:
    // - The participant was not dormant
    fn entered_active_zone(&mut self) -> Option<ParticipantId> {
        let (id, zone) = match self.get_mut_participant_at_end_of_active_zone() {
            Some(participant) => participant,
            None => {
                // This would mean that we have less than `active_zone_threshold` people
                // in the queue
                //
                return None;
            }
        };

        debug_assert!(zone.is_dormant());
        *zone = Zone::Active(CheckInReq::transition_expiry());
        Some(id.clone())
    }

    // Removes the participant at `position`. The queue order is conserved
    fn remove_participant_at_position(&mut self, position: usize) -> Option<(ParticipantId, Zone)> {
        self.inner.shift_remove_index(position)
    }
    fn remove_participant_in_active_zone(&mut self) -> Option<(ParticipantId, Zone)> {
        self.remove_participant_at_position(0)
    }

    fn remove_participants_from_active_zone(&mut self, participants: Vec<ParticipantId>) {
        // TODO: what we can do is just do the removing then iterate the
        // TODO active zone and set all Dormant people to Active
        let num_to_remove = participants.len();
        for id in participants {
            self.remove_participant(&id)
        }

        // We should now have `num_to_remove` participants in the
        // active zone whom are dormant and need to be set to active
        // One of them maybe need to be put into the compute zone though
        //
        // Check if the person at the front needs to be changed to compute
        match self.get_mut_participant_at_front() {
            Some((_, zone)) => {
                if !zone.is_compute() {
                    assert!(zone.is_active());
                    *zone = Zone::Compute(CheckInReq::transition_expiry())
                }
            }
            None => {
                // So we can get here if we've just removed everyone from the queue
                //
                // Do nothing
            }
        }
    }

    fn remove_participant(&mut self, participant_id: &ParticipantId) {
        // Remove from Queue
        self.inner.shift_remove(participant_id);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Participants much check-in when they transition
// from one zone to another, and they must also check-in
// while in the active or compute zone periodically
//
// The queue manager keeps track of all check-ins
// for the active and compute zone
// Participants must check in by the expiry time
// There is a slight leeway since we check periodically
pub enum CheckInReq {
    Transition { expiry: Instant },
    ImAlive { expiry: Instant },
}

impl CheckInReq {
    pub fn expired(&self) -> bool {
        let expiry = match self {
            CheckInReq::Transition { expiry } => expiry,
            CheckInReq::ImAlive { expiry } => expiry,
        };
        // For Instant, we can check if it has
        // expired by checking how much time has elapsed.
        // If it is in the future and this not elapsed, it will return 0
        expiry.elapsed() != Duration::ZERO
    }

    pub fn transition_expiry() -> CheckInReq {
        CheckInReq::Transition {
            expiry: Instant::now() + Duration::from_secs(10),
        }
    }

    pub fn imalive_expiry() -> CheckInReq {
        CheckInReq::ImAlive {
            expiry: Instant::now() + Duration::from_secs(20),
        }
    }

    pub fn is_transition_req(&self) -> bool {
        match self {
            CheckInReq::Transition { .. } => true,
            CheckInReq::ImAlive { .. } => false,
        }
    }
    pub fn is_imalive_req(&self) -> bool {
        match self {
            CheckInReq::Transition { .. } => false,
            CheckInReq::ImAlive { .. } => true,
        }
    }
}

const TEST_CONFIG: Config = Config {
    active_zone_threshold: 100,
    active_zone_last_ping_deadline: 10,
    dormant_active_deadline: 10,
    active_compute_deadline: 10,
};

fn rand_participant_id() -> ParticipantId {
    String::from(uuid::Uuid::new_v4().to_string())
}

#[test]
fn queue_size() {
    let mut queue = Queue::new(TEST_CONFIG);

    let to_add = 25;
    for _ in 0..to_add {
        queue.add_participant(rand_participant_id());
    }

    assert_eq!(queue.len(), to_add);
}
#[test]
fn queue_dormant_active_compute_check() {
    let mut queue = Queue::new(TEST_CONFIG);

    let to_add = queue.config.active_zone_threshold * 2;
    for _ in 0..to_add {
        queue.add_participant(rand_participant_id());
    }
    let mut counter = (0..to_add);

    // The first person should be in the compute zone
    let position = counter.next().unwrap();
    let (_, zone) = queue.get_participant_at_position(position).unwrap();
    assert!(zone.is_compute());

    // The next `active_zone_threshold` people should be in the active zone
    for _ in 0..queue.config.active_zone_threshold {
        let position = counter.next().unwrap();
        let (_, zone) = queue.get_participant_at_position(position).unwrap();
        assert!(zone.is_active());
    }

    // The rest of the queue should be in the dormant zone
    for position in counter {
        let (_, zone) = queue.get_participant_at_position(position).unwrap();
        assert!(zone.is_dormant());
    }
}

#[test]
fn dormant_to_active() {}
