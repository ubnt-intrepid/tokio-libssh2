use std::net::TcpStream;
use tokio::task::LocalSet;
use tokio_libssh2::Session;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let mut rt = tokio::runtime::Runtime::new()?;
    let local = LocalSet::new();
    local.block_on(&mut rt, main_local())?;

    Ok(())
}

async fn main_local() -> anyhow::Result<()> {
    let mut session = Session::new()?;

    let stream = TcpStream::connect("127.0.0.1:22")?;
    session.handshake(stream).await?;

    let list = session.list_userauth("testuser").await?;
    println!("listed userauth: {:?}", std::str::from_utf8(&list));

    Ok(())
}
