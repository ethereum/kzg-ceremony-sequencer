// TODO: should we change all of the time related ones to type `Duration`?

// In seconds, This is the amount of time that
// a contributor has to complete their contribution
// TODO: When contributor gets  first into the queue
// TODO: spawn another thread which removes them
// TODO after 180 seconds no matter what
pub const COMPUTE_DEADLINE: usize = 180;

// In seconds, This is the amount of time that
// a contributor has to ping the coordinator
// once they move into the active zone
pub const ACTIVE_ZONE_CHECKIN_DEADLINE: usize = 30;

// This is the threshold at which users
// should start pinging that they are online
//
// In documents, we may refer to this as the constant
// that denotes the active zone
pub const MAX_QUEUE_SIZE: usize = 100;

// Value needed to convert seconds to milliseconds
pub const SECS_TO_MILLISECS: usize = 1000;

// The number of receipts to return when the
// history endpoint is called
pub const HISTORY_RECEIPTS_COUNT: usize = 20;

// Periodically, we check whether the participants
// have not pinged the coordinator on time.
// This constant defines how often we check, In seconds
pub const QUEUE_FLUSH_INTERVAL: usize = 5;

pub const OAUTH_REDIRECT_URL: &str = "http://127.0.0.1:3002/auth/authorized";
pub const OAUTH_AUTH_URL: &str = "https://kev-kzg-ceremony.eu.auth0.com/authorize";
pub const OAUTH_TOKEN_URL: &str = "https://kev-kzg-ceremony.eu.auth0.com/oauth/token";
