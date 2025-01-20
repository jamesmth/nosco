/// Trait providing functions for working with traced threads.
pub trait Thread {
    /// Error returned by this trait.
    type Error;

    /// Returns the thread's ID.
    fn id(&self) -> u64;

    /// Returns the thread's instruction address.
    fn instr_addr(&self) -> u64;

    /// Returns the thread's return address.
    fn ret_addr(&self) -> u64;

    /// Returns a mutable reference over the single-step state
    /// of the thread.
    fn single_step_mut(&mut self) -> &mut bool;
}
