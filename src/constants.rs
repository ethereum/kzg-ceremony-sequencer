// In seconds, This is the amount of time that
// a contributor has to complete their contribution
pub const COMPUTE_DEADLINE: usize = 180;

// In seconds, This is the expected amout of time
// between calls to /lobby/try_contribute
// Contributors will be kicked from the lobby if they
// exceed this deadline, and rate limited if they
// call too often
pub const LOBBY_CHECKIN_FREQUENCY_SEC: usize = 30;

// This is the allowed deviation from the FREQUENCY
// constant. (e.g FREQUENCY = 30, TOLERANCE = 2 means
// participants MUST call every 28-32 seconds).
pub const LOBBY_CHECKIN_TOLERANCE_SEC: usize = 2;

// This is the maximum amount of people that can be held in the
// lobby. Users in the lobby are allowed to ping to contribute
pub const MAX_LOBBY_SIZE: usize = 1_000;

// Periodically, we check whether the participants
// have not pinged the sequencer on time.
// This constant defines how often we check, In seconds
pub const LOBBY_FLUSH_INTERVAL: usize = 5;

pub const SIWE_OAUTH_REDIRECT_URL: &str = "http://127.0.0.1:3000/auth/callback/siwe";
pub const SIWE_OAUTH_AUTH_URL: &str = "https://oidc.signinwithethereum.org/authorize";
pub const SIWE_OAUTH_TOKEN_URL: &str = "https://oidc.signinwithethereum.org/token";

pub const GITHUB_OAUTH_REDIRECT_URL: &str = "http://127.0.0.1:3000/auth/callback/github";
pub const GITHUB_OAUTH_AUTH_URL: &str = "https://github.com/login/oauth/authorize";
pub const GITHUB_OAUTH_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";

// The latest time for creating a Github account eligible for participation
pub const GITHUB_ACCOUNT_CREATION_DEADLINE: &str = "2022-08-01T00:00:00Z";

// The hex block number at which we require participants to have a certain nonce
pub const ETH_CHECK_NONCE_AT_BLOCK: &str = "0xE4D540";

// The minimum nonce we require from eligible participants
pub const ETH_MIN_NONCE: i64 = 4;
