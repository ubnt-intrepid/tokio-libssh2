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

    let mut sftp = session.sftp().await?;

    {
        let mut file = sftp.open(".bash_profile").await?;
        let mut content = String::new();
        file.read_to_string(&mut content).await?;
        println!(".bash_profile:\n{}", content);
    }

    let mut dir = sftp.opendir(".").await?;
    while let Some(entry) = dir.readdir().await {
        let entry = entry?;
        println!("entry = {:?}", entry);
    }

    Ok(())
}
