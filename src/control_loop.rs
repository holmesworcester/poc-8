use std::fmt;

pub type EventId = [u8; 32];
pub type ConnectionId = Vec<u8>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    pub ready_event_fuel: usize,
    pub due_job_fuel: usize,
    pub outbox_connection_fuel: usize,
    pub max_idle_ticks: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ready_event_fuel: 128,
            due_job_fuel: 32,
            outbox_connection_fuel: 128,
            max_idle_ticks: 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueJob {
    pub module: String,
    pub name: String,
    pub payload: Vec<u8>,
}

impl DueJob {
    pub fn new(module: impl Into<String>, name: impl Into<String>, payload: Vec<u8>) -> Self {
        Self {
            module: module.into(),
            name: name.into(),
            payload,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JobOutcome {
    pub emitted_events: usize,
}

impl JobOutcome {
    pub fn no_op() -> Self {
        Self { emitted_events: 0 }
    }

    pub fn emitted_events(emitted_events: usize) -> Self {
        Self { emitted_events }
    }
}

pub trait ControlLoopBackend {
    type Error;

    fn drain_ready(&mut self, limit: usize) -> Result<usize, Self::Error>;
    fn due_jobs(&mut self, limit: usize) -> Result<Vec<DueJob>, Self::Error>;
    fn run_due_job(&mut self, job: DueJob) -> Result<JobOutcome, Self::Error>;
    fn pending_outbox_connections(
        &mut self,
        limit: usize,
    ) -> Result<Vec<ConnectionId>, Self::Error>;
}

pub trait NetworkWake {
    type Error;

    fn wake_connection_sender(&mut self, connection_id: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TickSummary {
    pub projected_events: usize,
    pub due_jobs_ran: usize,
    pub emitted_events: usize,
    pub woken_senders: usize,
    pub ticks: usize,
}

impl TickSummary {
    pub fn did_pipeline_work(&self) -> bool {
        self.projected_events > 0 || self.due_jobs_ran > 0 || self.emitted_events > 0
    }

    fn add_tick(&mut self, tick: TickSummary) {
        self.projected_events += tick.projected_events;
        self.due_jobs_ran += tick.due_jobs_ran;
        self.emitted_events += tick.emitted_events;
        self.woken_senders += tick.woken_senders;
        self.ticks += tick.ticks;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlLoopError<BackendError, NetworkError> {
    Backend(BackendError),
    Network(NetworkError),
    IdleTickLimitReached(TickSummary),
}

impl<BackendError: fmt::Display, NetworkError: fmt::Display> fmt::Display
    for ControlLoopError<BackendError, NetworkError>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(err) => write!(f, "control loop backend error: {err}"),
            Self::Network(err) => write!(f, "control loop network error: {err}"),
            Self::IdleTickLimitReached(summary) => {
                write!(
                    f,
                    "control loop reached idle tick limit after {} ticks",
                    summary.ticks
                )
            }
        }
    }
}

impl<BackendError, NetworkError> std::error::Error for ControlLoopError<BackendError, NetworkError>
where
    BackendError: fmt::Debug + fmt::Display,
    NetworkError: fmt::Debug + fmt::Display,
{
}

pub struct ControlLoop<Backend, Network> {
    backend: Backend,
    network: Network,
    config: Config,
}

impl<Backend, Network> ControlLoop<Backend, Network> {
    pub fn new(backend: Backend, network: Network, config: Config) -> Self {
        Self {
            backend,
            network,
            config,
        }
    }

    pub fn config(&self) -> Config {
        self.config
    }

    pub fn into_parts(self) -> (Backend, Network, Config) {
        (self.backend, self.network, self.config)
    }
}

impl<Backend, Network> ControlLoop<Backend, Network>
where
    Backend: ControlLoopBackend,
    Network: NetworkWake,
{
    pub fn tick_once(
        &mut self,
    ) -> Result<TickSummary, ControlLoopError<Backend::Error, Network::Error>> {
        let projected_events = if self.config.ready_event_fuel == 0 {
            0
        } else {
            self.backend
                .drain_ready(self.config.ready_event_fuel)
                .map_err(ControlLoopError::Backend)?
        };

        let mut due_jobs_ran = 0;
        let mut emitted_events = 0;
        if self.config.due_job_fuel > 0 {
            for job in self
                .backend
                .due_jobs(self.config.due_job_fuel)
                .map_err(ControlLoopError::Backend)?
            {
                let outcome = self
                    .backend
                    .run_due_job(job)
                    .map_err(ControlLoopError::Backend)?;
                due_jobs_ran += 1;
                emitted_events += outcome.emitted_events;
            }
        }

        let mut woken_senders = 0;
        if self.config.outbox_connection_fuel > 0 {
            for connection_id in self
                .backend
                .pending_outbox_connections(self.config.outbox_connection_fuel)
                .map_err(ControlLoopError::Backend)?
            {
                self.network
                    .wake_connection_sender(&connection_id)
                    .map_err(ControlLoopError::Network)?;
                woken_senders += 1;
            }
        }

        Ok(TickSummary {
            projected_events,
            due_jobs_ran,
            emitted_events,
            woken_senders,
            ticks: 1,
        })
    }

    pub fn run_until_idle(
        &mut self,
    ) -> Result<TickSummary, ControlLoopError<Backend::Error, Network::Error>> {
        let mut total = TickSummary::default();

        loop {
            if total.ticks >= self.config.max_idle_ticks {
                return Err(ControlLoopError::IdleTickLimitReached(total));
            }

            let tick = self.tick_once()?;
            let should_continue = tick.did_pipeline_work();
            total.add_tick(tick);

            if !should_continue {
                return Ok(total);
            }
        }
    }
}
