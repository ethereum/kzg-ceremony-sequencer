// In seconds, This is the amount of time that
// a contributor has to complete their contribution
pub const COMPUTE_DEADLINE: usize = 180;

// In seconds, This is the amount of time that
// a contributor can go without pinging the sequencer
// while in the lobby. Contributors will be kicked
// from the lobby if they exceed this deadline.
pub const LOBBY_CHECKIN_DEADLINE: usize = 30;

// This is the maximum amount of people that can be held in the
// lobby. Users in the lobby are allowed to ping to contribute
pub const MAX_LOBBY_SIZE: usize = 1_000;

// The number of receipts to return when the
// history endpoint is called
pub const HISTORY_RECEIPTS_COUNT: usize = 20;

// Periodically, we check whether the participants
// have not pinged the sequencer on time.
// This constant defines how often we check, In seconds
pub const LOBBY_FLUSH_INTERVAL: usize = 5;

pub const OAUTH_REDIRECT_URL: &str = "http://127.0.0.1:3002/auth/authorized";
pub const OAUTH_AUTH_URL: &str = "https://kev-kzg-ceremony.eu.auth0.com/authorize";
pub const OAUTH_TOKEN_URL: &str = "https://kev-kzg-ceremony.eu.auth0.com/oauth/token";
