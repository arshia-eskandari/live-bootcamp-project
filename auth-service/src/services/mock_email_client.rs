use crate::domain::{Email, EmailClient};

#[derive(Clone, Default)]
pub struct MockEmailClient;

impl MockEmailClient {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl EmailClient for MockEmailClient {
    async fn send_email(
        &self,
        recipient: &Email,
        subject: &str,
        content: &str,
    ) -> color_eyre::eyre::Result<()> {
        // Our mock email client will simply log the recipient, subject, and content to standard output
        tracing::info!(
            "Sending email to {} with subject: {} and content: {}",
            recipient.as_ref(),
            subject,
            content
        );

        Ok(())
    }
}
