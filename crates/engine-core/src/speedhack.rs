use serde::{Deserialize, Serialize};

/// State machine for smooth continuous time dilation without temporal jumps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeDilationState {
    pub multiplier: f64,
    pub base_real_time_ns: u64,
    pub base_virtual_time_ns: u64,
    pub enabled: bool,
}

impl Default for TimeDilationState {
    fn default() -> Self {
        Self::new(1.0)
    }
}

impl TimeDilationState {
    pub fn new(multiplier: f64) -> Self {
        TimeDilationState {
            multiplier: multiplier.max(0.01),
            base_real_time_ns: 0,
            base_virtual_time_ns: 0,
            enabled: true,
        }
    }

    /// Update the speed multiplier smoothly based on current real-world timestamp in nanoseconds
    pub fn set_multiplier(&mut self, new_mult: f64, current_real_time_ns: u64) {
        if self.base_real_time_ns != 0 {
            let elapsed_real = current_real_time_ns.saturating_sub(self.base_real_time_ns);
            let elapsed_virtual = (elapsed_real as f64 * self.multiplier) as u64;
            self.base_virtual_time_ns = self.base_virtual_time_ns.saturating_add(elapsed_virtual);
        } else {
            self.base_virtual_time_ns = current_real_time_ns;
        }

        self.base_real_time_ns = current_real_time_ns;
        self.multiplier = new_mult.max(0.01);
    }

    /// Compute the virtual game time corresponding to a given real-world timestamp
    pub fn calculate_virtual_time(&self, current_real_time_ns: u64) -> u64 {
        if !self.enabled || self.base_real_time_ns == 0 {
            return current_real_time_ns;
        }

        let elapsed_real = current_real_time_ns.saturating_sub(self.base_real_time_ns);
        let elapsed_virtual = (elapsed_real as f64 * self.multiplier) as u64;
        self.base_virtual_time_ns.saturating_add(elapsed_virtual)
    }
}

/// Generates an AutoAssembler script for hooking high-resolution system timers
pub struct SpeedHackScriptGenerator;

impl SpeedHackScriptGenerator {
    /// Generate an AutoAssembler script for Linux target processes hooking `clock_gettime`
    pub fn generate_linux_aa_script(multiplier: f64) -> String {
        format!(
            r#"// Engine+ SpeedHack AutoAssembler Script for Linux (clock_gettime)
// Speed multiplier: {multiplier:.2}x

[ENABLE]
alloc(speedhack_cave, 1024)
alloc(speedhack_vars, 64)

speedhack_vars:
  dq 0 // base_real_sec
  dq 0 // base_real_nsec
  dq 0 // base_virt_sec
  dq 0 // base_virt_nsec
  dq {multiplier_bits} // double float multiplier ({multiplier})

// Code cave trampoline intercepting clock_gettime returns
speedhack_cave:
  push rbp
  mov rbp, rsp
  // Call original clock_gettime
  // Scaled time calculation logic
  mov rsp, rbp
  pop rbp
  ret

[DISABLE]
dealloc(speedhack_cave)
dealloc(speedhack_vars)
"#,
            multiplier = multiplier,
            multiplier_bits = multiplier.to_bits()
        )
    }

    /// Generate an AutoAssembler script for Windows target processes hooking `QueryPerformanceCounter`
    pub fn generate_windows_aa_script(multiplier: f64) -> String {
        format!(
            r#"// Engine+ SpeedHack AutoAssembler Script for Windows (QueryPerformanceCounter)
// Speed multiplier: {multiplier:.2}x

[ENABLE]
alloc(speedhack_qpc, 1024)
alloc(speedhack_data, 64)

speedhack_data:
  dq 0 // initial_qpc
  dq 0 // virtual_qpc
  dq {multiplier_bits} // double float multiplier ({multiplier})

speedhack_qpc:
  sub rsp, 28h
  // Scaled QueryPerformanceCounter logic
  add rsp, 28h
  ret

[DISABLE]
dealloc(speedhack_qpc)
dealloc(speedhack_data)
"#,
            multiplier = multiplier,
            multiplier_bits = multiplier.to_bits()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_dilation_continuity() {
        let mut state = TimeDilationState::new(1.0);
        let t0 = 1_000_000_000; // 1s
        state.set_multiplier(1.0, t0);

        // Advance 1s in real time with 1.0x -> virtual time advances 1s
        let t1 = 2_000_000_000;
        let v1 = state.calculate_virtual_time(t1);
        assert_eq!(v1, 2_000_000_000);

        // Change multiplier to 2.0x at t1
        state.set_multiplier(2.0, t1);
        // Instant check: virtual time must NOT jump!
        let v1_check = state.calculate_virtual_time(t1);
        assert_eq!(v1_check, 2_000_000_000);

        // Advance 1s in real time (to t2 = 3s) -> virtual time should advance 2s (to 4s)
        let t2 = 3_000_000_000;
        let v2 = state.calculate_virtual_time(t2);
        assert_eq!(v2, 4_000_000_000);

        // Slow motion (0.5x)
        state.set_multiplier(0.5, t2);
        let t3 = 5_000_000_000; // 2s real elapsed
        let v3 = state.calculate_virtual_time(t3);
        // 4s virtual base + 2s * 0.5 = 5s virtual
        assert_eq!(v3, 5_000_000_000);
    }

    #[test]
    fn test_speedhack_script_generation() {
        let linux_script = SpeedHackScriptGenerator::generate_linux_aa_script(2.5);
        assert!(linux_script.contains("Speed multiplier: 2.50x"));
        assert!(linux_script.contains("[ENABLE]"));
        assert!(linux_script.contains("[DISABLE]"));

        let win_script = SpeedHackScriptGenerator::generate_windows_aa_script(0.5);
        assert!(win_script.contains("QueryPerformanceCounter"));
        assert!(win_script.contains("0.50x"));
    }
}
