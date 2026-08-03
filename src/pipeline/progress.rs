use serde::Serialize;

/// Unit associated with a bounded progress total.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressUnit {
    Bytes,
    Offsets,
    Records,
    Candidates,
    Keys,
    Pages,
    Modules,
    Symbols,
    Sections,
    Blocks,
}

/// Deterministic five-percent progress gate bounded to 21 emissions.
#[derive(Clone, Debug)]
pub struct ProgressMilestones {
    total: u64,
    last_completed: u64,
    last_percent: Option<u8>,
}

impl ProgressMilestones {
    pub const fn new(total: u64) -> Self {
        Self {
            total,
            last_completed: 0,
            last_percent: None,
        }
    }

    pub const fn total(&self) -> u64 {
        self.total
    }

    pub fn should_emit(&mut self, completed: u64) -> bool {
        let completed = completed.min(self.total);
        if self.total == 0 {
            return self.last_percent.replace(100).is_none();
        }
        if completed < self.last_completed {
            return false;
        }
        self.last_completed = completed;
        let percent = ((u128::from(completed) * 100) / u128::from(self.total)) as u8;
        if self.total <= 20 || completed == 0 || completed == self.total {
            return self.last_percent.replace(percent) != Some(percent);
        }
        if self
            .last_percent
            .is_none_or(|previous| percent / 5 > previous / 5)
        {
            self.last_percent = Some(percent);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_milestones_are_monotonic_and_bounded() {
        let mut milestones = ProgressMilestones::new(10_000);
        let emitted = (0..=10_000)
            .filter(|&completed| milestones.should_emit(completed))
            .collect::<Vec<_>>();
        assert_eq!(emitted.first(), Some(&0));
        assert_eq!(emitted.last(), Some(&10_000));
        assert_eq!(emitted.len(), 21);
        assert!(emitted.windows(2).all(|pair| pair[0] < pair[1]));
    }
}
