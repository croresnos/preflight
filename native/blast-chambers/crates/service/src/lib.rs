#![deny(unsafe_op_in_unsafe_fn)]

//! Security-critical service core. The public surface is deliberately small:
//! lifecycle transitions are monotonic and all Win32 ownership lives in RAII
//! wrappers under `windows`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    Authenticated,
    Staged,
    LimitsVerified,
    CreatedSuspended,
    Assigned,
    Resumed,
    Running,
    Terminating,
    Sealed,
}

#[derive(Debug)]
pub struct LifecycleMachine {
    state: Lifecycle,
}

impl LifecycleMachine {
    #[must_use]
    pub const fn authenticated() -> Self {
        Self {
            state: Lifecycle::Authenticated,
        }
    }

    #[must_use]
    pub const fn state(&self) -> Lifecycle {
        self.state
    }

    /// Advance exactly one permitted lifecycle edge.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested edge skips or reverses a state.
    pub fn transition(&mut self, next: Lifecycle) -> Result<(), &'static str> {
        let valid = matches!(
            (self.state, next),
            (Lifecycle::Authenticated, Lifecycle::Staged)
                | (Lifecycle::Staged, Lifecycle::LimitsVerified)
                | (Lifecycle::LimitsVerified, Lifecycle::CreatedSuspended)
                | (Lifecycle::CreatedSuspended, Lifecycle::Assigned)
                | (Lifecycle::Assigned, Lifecycle::Resumed)
                | (Lifecycle::Resumed, Lifecycle::Running)
                | (Lifecycle::Running, Lifecycle::Terminating)
                | (Lifecycle::Terminating, Lifecycle::Sealed)
        );
        if !valid {
            return Err("invalid lifecycle transition");
        }
        self.state = next;
        Ok(())
    }

    pub fn fail_closed(&mut self) {
        self.state = if self.state == Lifecycle::Sealed {
            Lifecycle::Sealed
        } else {
            Lifecycle::Terminating
        };
    }
}

#[cfg(windows)]
pub mod windows;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_cannot_skip_assignment_before_resume() {
        let mut lifecycle = LifecycleMachine::authenticated();
        assert!(lifecycle.transition(Lifecycle::CreatedSuspended).is_err());
        lifecycle.transition(Lifecycle::Staged).unwrap();
        lifecycle.transition(Lifecycle::LimitsVerified).unwrap();
        lifecycle.transition(Lifecycle::CreatedSuspended).unwrap();
        assert!(lifecycle.transition(Lifecycle::Resumed).is_err());
        lifecycle.transition(Lifecycle::Assigned).unwrap();
        lifecycle.transition(Lifecycle::Resumed).unwrap();
    }

    #[test]
    fn failure_moves_to_termination() {
        let mut lifecycle = LifecycleMachine::authenticated();
        lifecycle.fail_closed();
        assert_eq!(lifecycle.state(), Lifecycle::Terminating);
        assert!(lifecycle.transition(Lifecycle::Sealed).is_ok());
    }
}
