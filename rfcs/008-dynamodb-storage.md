# RFC 008: DynamoDB Storage Provider

| Date       | Author       | Status   |
| ---------- | ------------ | -------- |
| 2025-02-19 | @cmackenzie1 | 📝 Draft |

## Summary

Add Amazon DynamoDB support as a storage provider for Torii, leveraging its serverless nature, auto-scaling capabilities, and strong consistency model. This implementation will maintain compatibility with the storage interface defined in RFC 0002 while taking advantage of DynamoDB-specific features.

## Motivation

DynamoDB offers several advantages as a storage backend:

1. **Serverless**: No infrastructure management required
2. **Auto-scaling**: Automatic capacity adjustment
3. **Performance**: Single-digit millisecond latency
4. **Durability**: Multi-AZ replication
5. **Cost-effective**: Pay-per-request pricing
6. **Integration**: Native AWS service integration

## Design

### Table Schemas

```typescript
// Users table
{
  TableName: 'torii_users',
  KeySchema: [
    { AttributeName: 'id', KeyType: 'HASH' }
  ],
  AttributeDefinitions: [
    { AttributeName: 'id', AttributeType: 'S' },
    { AttributeName: 'email', AttributeType: 'S' }
  ],
  GlobalSecondaryIndexes: [
    {
      IndexName: 'email-index',
      KeySchema: [
        { AttributeName: 'email', KeyType: 'HASH' }
      ],
      Projection: { ProjectionType: 'ALL' }
    }
  ],
  BillingMode: 'PAY_PER_REQUEST'
}

// Sessions table
{
  TableName: 'torii_sessions',
  KeySchema: [
    { AttributeName: 'id', KeyType: 'HASH' }
  ],
  AttributeDefinitions: [
    { AttributeName: 'id', AttributeType: 'S' },
    { AttributeName: 'user_id', AttributeType: 'S' },
    { AttributeName: 'expires_at', AttributeType: 'N' }
  ],
  GlobalSecondaryIndexes: [
    {
      IndexName: 'user-sessions-index',
      KeySchema: [
        { AttributeName: 'user_id', KeyType: 'HASH' },
        { AttributeName: 'expires_at', KeyType: 'RANGE' }
      ],
      Projection: { ProjectionType: 'ALL' }
    }
  ],
  BillingMode: 'PAY_PER_REQUEST',
  TimeToLiveSpecification: {
    AttributeName: 'expires_at',
    Enabled: true
  }
}
```

### Storage Implementation

```rust
use aws_sdk_dynamodb as dynamodb;
use aws_config::Config;

#[derive(Debug, Clone)]
pub struct DynamoDbConfig {
    pub region: String,
    pub endpoint_url: Option<String>,
    pub table_prefix: String,
    pub consistent_reads: bool,
    pub retry_attempts: u32,
}

pub struct DynamoDbStorage {
    client: dynamodb::Client,
    config: DynamoDbConfig,
}

#[derive(Clone)]
pub struct DynamoDbHandle {
    client: dynamodb::Client,
    config: DynamoDbConfig,
}

#[async_trait]
impl StoragePlugin for DynamoDbStorage {
    type Config = DynamoDbConfig;
    type Handle = DynamoDbHandle;

    async fn initialize(&self, config: Self::Config) -> Result<Self::Handle, Error> {
        // Create tables if they don't exist
        self.ensure_tables().await?;

        Ok(DynamoDbHandle {
            client: self.client.clone(),
            config,
        })
    }
}

impl DynamoDbHandle {
    fn table_name(&self, base: &str) -> String {
        format!("{}_{}", self.config.table_prefix, base)
    }

    async fn put_item<T: Serialize>(
        &self,
        table: &str,
        item: &T,
        condition: Option<String>,
    ) -> Result<(), Error> {
        let item = serde_dynamo::to_item(item)?;

        let mut req = self.client
            .put_item()
            .table_name(self.table_name(table))
            .set_item(Some(item));

        if let Some(condition) = condition {
            req = req.condition_expression(condition);
        }

        req.send()
            .await
            .map_err(Error::from)?;

        Ok(())
    }

    async fn get_item<T: DeserializeOwned>(
        &self,
        table: &str,
        key: HashMap<String, AttributeValue>,
    ) -> Result<Option<T>, Error> {
        let result = self.client
            .get_item()
            .table_name(self.table_name(table))
            .set_key(Some(key))
            .consistent_read(self.config.consistent_reads)
            .send()
            .await?;

        match result.item {
            Some(item) => Ok(Some(serde_dynamo::from_item(item)?)),
            None => Ok(None),
        }
    }
}
```

### User Storage Implementation

```rust
#[async_trait]
impl UserStorage for DynamoDbHandle {
    async fn create_user(&self, new_user: &NewUser) -> Result<User, Error> {
        let user = User {
            id: new_user.id.clone(),
            email: new_user.email.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: new_user.metadata.clone().unwrap_or_default(),
        };

        self.put_item(
            "users",
            &user,
            Some("attribute_not_exists(id)".to_string()),
        )
        .await?;

        Ok(user)
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Error> {
        let result = self.client
            .query()
            .table_name(self.table_name("users"))
            .index_name("email-index")
            .key_condition_expression("email = :email")
            .expression_attribute_values(":email", AttributeValue::S(email.to_string()))
            .send()
            .await?;

        match result.items.and_then(|mut items| items.pop()) {
            Some(item) => Ok(Some(serde_dynamo::from_item(item)?)),
            None => Ok(None),
        }
    }

    async fn update_user(&self, user: &User) -> Result<User, Error> {
        let mut updated = user.clone();
        updated.updated_at = Utc::now();

        self.put_item(
            "users",
            &updated,
            Some("attribute_exists(id)".to_string()),
        )
        .await?;

        Ok(updated)
    }
}
```

### Session Storage Implementation

```rust
#[async_trait]
impl SessionStorage for DynamoDbHandle {
    async fn create_session(&self, session: &Session) -> Result<Session, Error> {
        let item = SessionItem {
            id: session.id.clone(),
            user_id: session.user_id.clone(),
            expires_at: session.expires_at.timestamp(),
            created_at: Utc::now(),
            metadata: session.metadata.clone(),
        };

        self.put_item("sessions", &item, None).await?;
        Ok(session.clone())
    }

    async fn get_session(&self, id: &SessionId) -> Result<Option<Session>, Error> {
        let key = HashMap::from([
            ("id".to_string(), AttributeValue::S(id.to_string())),
        ]);

        let item: Option<SessionItem> = self.get_item("sessions", key).await?;
        Ok(item.map(Session::from))
    }

    async fn cleanup_expired_sessions(&self) -> Result<(), Error> {
        // DynamoDB handles TTL automatically
        Ok(())
    }
}
```

### Batch Operations

```rust
impl DynamoDbHandle {
    pub async fn batch_get_users(&self, ids: &[UserId]) -> Result<Vec<User>, Error> {
        let keys: Vec<HashMap<String, AttributeValue>> = ids
            .iter()
            .map(|id| {
                HashMap::from([
                    ("id".to_string(), AttributeValue::S(id.to_string())),
                ])
            })
            .collect();

        let result = self.client
            .batch_get_item()
            .request_items(self.table_name("users"), keys)
            .send()
            .await?;

        let items = result
            .responses
            .and_then(|mut resp| resp.remove(&self.table_name("users")))
            .unwrap_or_default();

        items
            .into_iter()
            .map(|item| serde_dynamo::from_item(item).map_err(Error::from))
            .collect()
    }
}
```

## Features

### 1. Transactions

```rust
impl DynamoDbHandle {
    pub async fn transact_write<F>(&self, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut TransactWriteItemsInput) -> &mut TransactWriteItemsInput,
    {
        let mut tx = TransactWriteItemsInput::builder();
        f(&mut tx);

        self.client
            .transact_write_items()
            .set_transact_items(tx.build().transact_items)
            .send()
            .await?;

        Ok(())
    }
}
```

### 2. Auto-scaling Configuration

```rust
impl DynamoDbStorage {
    async fn configure_autoscaling(&self, table_name: &str) -> Result<(), Error> {
        let application_auto_scaling = ApplicationAutoScalingClient::new(&self.config.region);

        application_auto_scaling
            .register_scalable_target()
            .service_namespace("dynamodb")
            .resource_id(format!("table/{}", table_name))
            .scalable_dimension("dynamodb:table:ReadCapacityUnits")
            .min_capacity(1)
            .max_capacity(10)
            .send()
            .await?;

        Ok(())
    }
}
```

## Benefits

1. **Serverless**: No infrastructure management
2. **Auto-scaling**: Automatic capacity adjustment
3. **Cost-effective**: Pay-per-request pricing
4. **Durability**: Built-in replication
5. **Performance**: Consistent low latency

## Migration Guide

1. **Install Dependencies**:

```toml
[dependencies]
aws-sdk-dynamodb = "0.28"
aws-config = "0.55"
serde_dynamo = "4"
```

2. **Configure Storage**:

```rust
let config = DynamoDbConfig {
    region: "us-west-2".to_string(),
    endpoint_url: None,
    table_prefix: "torii".to_string(),
    consistent_reads: true,
    retry_attempts: 3,
};

let storage = DynamoDbStorage::new(config).await?;
```

## DynamoDB-Specific Considerations

1. **Item Size Limit**: 400KB per item
2. **Eventual Consistency**: Optional strong consistency
3. **Capacity Planning**: On-demand vs provisioned
4. **Cost Model**: Pay per request/capacity unit
5. **Query Patterns**: Design around access patterns

## Questions

1. Should we support DynamoDB Streams?
2. How should we handle backup/restore?
3. Should we support Global Tables?
4. How do we handle throttling/backoff?

## Alternatives Considered

1. **Single Table Design**

   - More complex queries
   - Better performance
   - Higher maintenance

2. **Multiple Tables**

   - Simpler queries
   - Higher cost
   - More flexibility

3. **Hybrid Approach**
   - DynamoDB + Redis cache
   - More complex implementation
   - Better performance

## References

- [RFC 0002: Plugin Interfaces](./002-plugin-interfaces.md)
- [DynamoDB Developer Guide](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/)
- [AWS SDK for Rust](https://docs.aws.amazon.com/sdk-for-rust/)
- [DynamoDB Best Practices](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/best-practices.html)
