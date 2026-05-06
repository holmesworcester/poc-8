//! Protocol-neutral round-robin runtime.
//!
//! Core does not know what a caller's steps mean. It only owns the mechanical
//! loop: run each supplied step once, repeat until the caller says to stop, and
//! sleep between ticks. The caller owns step order, state, and effects.

use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RoundRobinReport {
    pub ticks: usize,
    pub steps: usize,
}

pub fn run_round_robin<S>(
    steps: &[S],
    idle: Duration,
    mut should_stop: impl FnMut() -> bool,
    mut run_step: impl FnMut(&S) -> Result<(), String>,
) -> Result<RoundRobinReport, String> {
    if steps.is_empty() {
        return Err("round robin runtime requires at least one step".to_string());
    }

    let mut report = RoundRobinReport::default();
    loop {
        for step in steps {
            run_step(step)?;
            report.steps += 1;
        }
        report.ticks += 1;

        if should_stop() {
            return Ok(report);
        }
        thread::sleep(idle);
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::time::Duration;

    use super::*;

    #[test]
    fn runs_steps_in_round_robin_order_until_stopped() {
        let steps = ["a", "b", "c"];
        let seen = RefCell::new(Vec::new());

        let report = run_round_robin(
            &steps,
            Duration::from_millis(1),
            || seen.borrow().len() >= 6,
            |step| {
                seen.borrow_mut().push(*step);
                Ok(())
            },
        )
        .expect("run loop");

        assert_eq!(*seen.borrow(), ["a", "b", "c", "a", "b", "c"]);
        assert_eq!(report.ticks, 2);
        assert_eq!(report.steps, 6);
    }

    #[test]
    fn rejects_empty_step_sets() {
        let err = run_round_robin::<u8>(&[], Duration::from_millis(1), || true, |_| Ok(()))
            .expect_err("empty runtime should fail");

        assert!(err.contains("at least one step"));
    }
}
