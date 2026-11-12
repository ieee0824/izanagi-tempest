//! Sequential client for the pinned JSON-lines protocol. Errors are terminal.
use serde_json::{Value, json};
use std::{io, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

pub(crate) struct Rpc<R, W> {
    reader: BufReader<R>,
    pub writer: W,
    next_id: u64,
    poisoned: bool,
}
impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> Rpc<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
            next_id: 0,
            poisoned: false,
        }
    }
    pub async fn request(
        &mut self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> io::Result<Value> {
        if self.poisoned {
            return Err(io::Error::other("RPC is uncertain; reconnect forbidden"));
        }
        let result = self.request_once(method, params, timeout).await;
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    async fn request_once(
        &mut self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> io::Result<Value> {
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("RPC ID exhausted"))?;
        let id = self.next_id;
        let mut encoded =
            serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))?;
        encoded.push(b'\n');
        if encoded.len() > 4 * 1024 * 1024 {
            return Err(io::Error::other("RPC request too large"));
        }
        tokio::time::timeout(timeout, async {
            self.writer.write_all(&encoded).await?;
            self.writer.flush().await?;
            let bytes = crate::relay::frame(&mut self.reader, &mut Vec::new(), 8 * 1024 * 1024)
                .await?
                .ok_or_else(|| io::Error::other("RPC disconnected"))?;
            let response: Value = serde_json::from_slice(&bytes)?;
            if response["id"] != id
                || response["jsonrpc"] != "2.0"
                || response.get("result").is_some() == response.get("error").is_some()
            {
                return Err(io::Error::other("RPC response mismatch"));
            }
            Ok(response)
        })
        .await
        .map_err(|_| io::Error::other("RPC deadline; state uncertain"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn mismatched_response_poisoned_without_second_write() {
        let (client, server) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(client);
        let (server_read, mut server_write) = tokio::io::split(server);
        let peer = tokio::spawn(async move {
            let mut lines = BufReader::new(server_read).lines();
            assert!(lines.next_line().await.unwrap().is_some());
            server_write
                .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{}}\n")
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_millis(50), lines.next_line())
                .await
                .is_err()
        });
        let mut rpc = Rpc::new(read, write);
        assert!(
            rpc.request("one", json!({}), Duration::from_secs(1))
                .await
                .is_err()
        );
        assert!(
            rpc.request("two", json!({}), Duration::from_secs(1))
                .await
                .is_err()
        );
        assert!(peer.await.unwrap(), "poisoned RPC sent a second request");
    }
}
