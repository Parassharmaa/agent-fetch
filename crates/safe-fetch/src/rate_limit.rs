use std::sync::Mutex;
use std::time::Instant;

use tokio::sync::Semaphore;

use crate::error::FetchError;

/// Simple sliding-window rate limiter with a concurrency semaphore.
pub struct RateLimiter {
    global_max_per_minute: u32,
    state: Mutex<Vec<Instant>>,
    concurrency: Semaphore,
}

impl RateLimiter {
    pub fn new(max_per_minute: u32, max_concurrent: usize) -> Self {
        Self {
            global_max_per_minute: max_per_minute,
            state: Mutex::new(Vec::new()),
            concurrency: Semaphore::new(max_concurrent),
        }
    }

    /// Check whether a request to `domain` is allowed.
    /// Returns a permit that must be held for the duration of the request.
    pub async fn acquire(
        &self,
        _domain: &str,
    ) -> Result<tokio::sync::SemaphorePermit<'_>, FetchError> {
        let permit = self
            .concurrency
            .try_acquire()
            .map_err(|_| FetchError::RateLimitExceeded)?;

        {
            let mut timestamps = self.state.lock().unwrap();
            let now = Instant::now();
            let one_minute_ago = now - std::time::Duration::from_secs(60);

            timestamps.retain(|t| *t > one_minute_ago);

            if timestamps.len() as u32 >= self.global_max_per_minute {
                drop(permit);
                return Err(FetchError::RateLimitExceeded);
            }

            timestamps.push(now);
        }

        Ok(permit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_within_limit() {
        let rl = RateLimiter::new(10, 5);
        for _ in 0..10 {
            assert!(rl.acquire("example.com").await.is_ok());
        }
    }

    #[tokio::test]
    async fn rejects_over_limit() {
        let rl = RateLimiter::new(3, 100);
        for _ in 0..3 {
            let _permit = rl.acquire("example.com").await.unwrap();
            // permit is dropped immediately, freeing concurrency slot
        }
        assert!(rl.acquire("example.com").await.is_err());
    }

    #[tokio::test]
    async fn rejects_over_concurrency() {
        let rl = RateLimiter::new(100, 2);
        let _p1 = rl.acquire("a.com").await.unwrap();
        let _p2 = rl.acquire("b.com").await.unwrap();
        // Third should fail — concurrency limit reached
        assert!(rl.acquire("c.com").await.is_err());
    }
}
