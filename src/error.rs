use std::{fmt::Display, panic::Location, rc::Rc};

#[derive(Clone)]
pub struct Error(Rc<dyn std::error::Error>, &'static Location<'static>);

impl<E> From<E> for Error
where
    E: std::error::Error + 'static,
{
    #[track_caller]
    fn from(value: E) -> Self {
        let caller = Location::caller();
        Self(Rc::new(value), caller)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}\nat {}", self.0, self.1)
    }
}
