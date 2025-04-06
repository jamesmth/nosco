/// Trait providing functions for working with traced threads.
pub trait Thread {
    /// Error returned by this trait.
    type Error;

    /// Returns the thread's ID.
    fn id(&self) -> u64;

    /// Returns the thread's instruction address.
    fn instr_addr(&self) -> u64;

    /// Returns whether the thread is in single-step.
    fn is_single_step(&self) -> bool;

    /// Enables or disables single-step for this thread.
    fn set_single_step(&mut self, enable: bool);
}
