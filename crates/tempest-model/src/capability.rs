//! Static API catalog derived from pinned upstream source, not a live contract test.
pub const LWS_COMMIT: &str = "2c0ea463f334f10a562e54f1cdc7ba8a474029e2";
pub const LQS_COMMIT: &str = "ebbe2ad5bdf58fc24849e8486559b50e5590c1d8";
pub const LES_COMMIT: &str = "5c7c3bb07d589f38863fce32695a03c882c0a73e";
pub const REGION: &str = "us-east-1";
pub const ACCOUNT: &str = "000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    Global,
    Bucket,
    Object,
    Queue,
    Identity,
}
#[derive(Debug, Clone, Copy)]
pub enum Support {
    Static,
    /// LWS supports the operation, but Check cannot supply required parameters.
    Unrepresentable(&'static str),
    Unsupported(&'static str),
}
#[derive(Debug, Clone, Copy)]
pub struct Capability {
    pub api: &'static str,
    pub action: &'static str,
    pub resource: ResourceKind,
    pub support: Support,
    pub source_commit: &'static str,
    pub source: &'static str,
}
macro_rules! entry {
    ($api:literal, $kind:ident, $support:expr, $commit:ident, $source:literal) => {
        Capability {
            api: $api,
            action: $api,
            resource: ResourceKind::$kind,
            support: $support,
            source_commit: $commit,
            source: $source,
        }
    };
}
use Support::{Static, Unrepresentable, Unsupported};
/// api/action are LWS authorization names (HeadObject is GetObject, for example).
pub const CAPABILITIES: &[Capability] = &[
    entry!(
        "s3:ListAllMyBuckets",
        Global,
        Static,
        LWS_COMMIT,
        "src/main.rs:378-402"
    ),
    entry!(
        "s3:CreateBucket",
        Bucket,
        Static,
        LWS_COMMIT,
        "src/main.rs:380"
    ),
    entry!(
        "s3:DeleteBucket",
        Bucket,
        Static,
        LWS_COMMIT,
        "src/main.rs:381"
    ),
    entry!(
        "s3:ListBucket",
        Bucket,
        Static,
        LWS_COMMIT,
        "src/main.rs:382"
    ),
    entry!(
        "s3:PutObject",
        Object,
        Static,
        LWS_COMMIT,
        "src/main.rs:383"
    ),
    entry!(
        "s3:GetObject",
        Object,
        Static,
        LWS_COMMIT,
        "src/main.rs:384-391"
    ),
    entry!(
        "s3:DeleteObject",
        Object,
        Static,
        LWS_COMMIT,
        "src/main.rs:392-399"
    ),
    entry!(
        "s3:GetObjectVersion",
        Object,
        Unrepresentable("versionId is not represented by Check"),
        LWS_COMMIT,
        "src/main.rs:384-391"
    ),
    entry!(
        "s3:DeleteObjectVersion",
        Object,
        Unrepresentable("versionId is not represented by Check"),
        LWS_COMMIT,
        "src/main.rs:392-399"
    ),
    entry!(
        "s3:PutBucketNotification",
        Bucket,
        Unsupported("S3 notifications are unavailable in strict mode (501)"),
        LWS_COMMIT,
        "src/main.rs:349-371"
    ),
    entry!(
        "s3:CopyObject",
        Object,
        Unsupported("copy and compound writes are unavailable in strict mode (501)"),
        LWS_COMMIT,
        "src/main.rs:345-347"
    ),
    entry!(
        "sqs:ListQueues",
        Global,
        Static,
        LQS_COMMIT,
        "src/http_server.rs:1072; LWS src/main.rs:114-125"
    ),
    entry!(
        "sqs:CreateQueue",
        Queue,
        Static,
        LQS_COMMIT,
        "src/http_server.rs:1077; LWS src/main.rs:114-125"
    ),
    entry!(
        "sqs:GetQueueUrl",
        Queue,
        Static,
        LQS_COMMIT,
        "src/http_server.rs:1072"
    ),
    entry!(
        "sqs:DeleteQueue",
        Queue,
        Static,
        LQS_COMMIT,
        "src/http_server.rs:1072"
    ),
    entry!(
        "sqs:PurgeQueue",
        Queue,
        Static,
        LQS_COMMIT,
        "src/http_server.rs:1072"
    ),
    entry!(
        "sqs:ListQueueTags",
        Queue,
        Static,
        LQS_COMMIT,
        "src/http_server.rs:1073"
    ),
    entry!(
        "sqs:GetQueueAttributes",
        Queue,
        Static,
        LQS_COMMIT,
        "src/http_server.rs:1082"
    ),
    entry!(
        "sqs:ListDeadLetterSourceQueues",
        Queue,
        Static,
        LQS_COMMIT,
        "src/http_server.rs:1083"
    ),
    entry!(
        "sqs:ReceiveMessage",
        Queue,
        Static,
        LQS_COMMIT,
        "src/http_server.rs:639-659"
    ),
    entry!(
        "sqs:SendMessage",
        Queue,
        Unrepresentable("MessageBody is not represented by Check"),
        LQS_COMMIT,
        "src/http_server.rs:1078"
    ),
    entry!(
        "sqs:DeleteMessage",
        Queue,
        Unrepresentable("ReceiptHandle is not represented by Check"),
        LQS_COMMIT,
        "src/http_server.rs:1079"
    ),
    entry!(
        "sqs:ChangeMessageVisibility",
        Queue,
        Unrepresentable("ReceiptHandle and VisibilityTimeout are not represented by Check"),
        LQS_COMMIT,
        "src/http_server.rs:1080"
    ),
    entry!(
        "sqs:SetQueueAttributes",
        Queue,
        Unrepresentable("Attributes are not represented by Check"),
        LQS_COMMIT,
        "src/http_server.rs:1081"
    ),
    entry!(
        "sqs:TagQueue",
        Queue,
        Unrepresentable("Tags are not represented by Check"),
        LQS_COMMIT,
        "src/http_server.rs:1072"
    ),
    entry!(
        "sqs:UntagQueue",
        Queue,
        Unrepresentable("TagKeys are not represented by Check"),
        LQS_COMMIT,
        "src/http_server.rs:1072"
    ),
    entry!(
        "sqs:AddPermission",
        Queue,
        Unrepresentable("permission parameters are not represented by Check"),
        LQS_COMMIT,
        "src/http_server.rs:1071"
    ),
    entry!(
        "sqs:RemovePermission",
        Queue,
        Unrepresentable("Label is not represented by Check"),
        LQS_COMMIT,
        "src/http_server.rs:1071"
    ),
    entry!(
        "sqs:SendMessageBatch",
        Queue,
        Unrepresentable("batch entries are not represented by Check"),
        LQS_COMMIT,
        "src/http_server.rs:1074-1075"
    ),
    entry!(
        "sqs:DeleteMessageBatch",
        Queue,
        Unrepresentable("batch entries are not represented by Check"),
        LQS_COMMIT,
        "src/http_server.rs:1074-1075"
    ),
    entry!(
        "sqs:ChangeMessageVisibilityBatch",
        Queue,
        Unrepresentable("batch entries are not represented by Check"),
        LQS_COMMIT,
        "src/http_server.rs:1074-1075"
    ),
    entry!(
        "ses:ListIdentities",
        Global,
        Static,
        LES_COMMIT,
        "src/server.rs:155-174; LWS src/main.rs:309-350"
    ),
    entry!(
        "ses:SendEmail",
        Identity,
        Unrepresentable(
            "sender identity setup, destination and message are not represented by ScenarioInput"
        ),
        LES_COMMIT,
        "src/server.rs:175-233; LWS src/main.rs:334-350"
    ),
    entry!(
        "ses:VerifyEmailIdentity",
        Global,
        Unrepresentable("EmailAddress is not represented by Check"),
        LES_COMMIT,
        "src/server.rs:135-142"
    ),
    entry!(
        "ses:VerifyDomainIdentity",
        Global,
        Unrepresentable("Domain is not represented by Check"),
        LES_COMMIT,
        "src/server.rs:143-150"
    ),
    entry!(
        "ses:DeleteIdentity",
        Global,
        Unrepresentable("Identity is not represented by Check"),
        LES_COMMIT,
        "src/server.rs:151-154"
    ),
    entry!(
        "ses:CreateEmailIdentity",
        Global,
        Unrepresentable("EmailIdentity is not represented by Check"),
        LES_COMMIT,
        "src/server.rs:314-326"
    ),
    entry!(
        "ses:GetEmailIdentity",
        Global,
        Unrepresentable("EmailIdentity is not represented by Check"),
        LES_COMMIT,
        "src/server.rs:327-344"
    ),
    entry!(
        "ses:DeleteEmailIdentity",
        Global,
        Unrepresentable("EmailIdentity is not represented by Check"),
        LES_COMMIT,
        "src/server.rs:345-357"
    ),
];
pub fn lookup(api: &str) -> Option<&'static Capability> {
    CAPABILITIES.iter().find(|c| c.api == api)
}
