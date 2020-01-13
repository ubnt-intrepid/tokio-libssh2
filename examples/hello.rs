use std::net::TcpStream;
use tokio::{io::AsyncReadExt, task::LocalSet};
use tokio_libssh2::{auth, Session};

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

    session
        .authenticate("testuser", auth::password("testuser"))
        .await?;

    let mut channel = session.open_channel_session().await?;
    channel.exec("env").await?;

    let mut buf = String::new();
    channel.read_to_string(&mut buf).await?;
    println!("stdout:\n{}", buf);

    let status = channel.exit_status()?;
    println!("exit status: {}", status);

    Ok(())
}
