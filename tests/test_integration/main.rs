use libtest_mimic as test;
use tokio::{runtime, task::LocalSet};

// TODOs:
// * Run sshd on background (with graceful shutdown)

fn main() -> anyhow::Result<()> {
    let mut rt = runtime::Builder::new()
        .basic_scheduler()
        .enable_all()
        .build()?;
    let locals = LocalSet::new();
    locals.block_on(&mut rt, async {
        let args = test::Arguments::from_args();
        let tests = collect_tests();
        let conclusion = test::run_tests(&args, tests, |case| (case.data)());
        if conclusion.has_failed() {
            return Err(anyhow::anyhow!("Test failed"));
        }
        Ok(())
    })?;
    Ok(())
}

fn collect_tests() -> Vec<test::Test<Box<dyn Fn() -> test::Outcome>>> {
    vec![
        test_case("case1", case1),
        test_case("case2", case2),
    ]
}

trait TestCase {
    fn run_test(&self) -> anyhow::Result<()>;
}

impl<F, E> TestCase for F
where
    F: Fn() -> Result<(), E>,
    E: Into<anyhow::Error>,
{
    fn run_test(&self) -> anyhow::Result<()> {
        (*self)().map_err(Into::into)
    }
}

fn test_case<T: TestCase + 'static>(
    name: impl Into<String>,
    case: T,
) -> test::Test<Box<dyn Fn() -> test::Outcome>> {
    let data = Box::new(move || match case.run_test() {
        Ok(()) => test::Outcome::Passed,
        Err(err) => test::Outcome::Failed {
            msg: Some(err.to_string()),
        },
    });
    test::Test {
        name: name.into(),
        kind: String::new(),
        is_ignored: false,
        is_bench: false,
        data,
    }
}

fn case1() -> anyhow::Result<()> {
    Ok(())
}

fn case2() -> anyhow::Result<()> {
    Err(anyhow::anyhow!("failed"))
}
