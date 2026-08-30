"""
common/mock_provider.py

Mock providers for Boto3 clients and Neo4j Graph database.
Allows running the Cloud Security Kill-Switch & IAM permission graph locally without AWS or Neo4j.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.parse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

# Global Mock Mode Flag
MOCK_MODE = os.environ.get("MOCK_MODE", "false").lower() == "true"

WORKSPACE_ROOT = Path(__file__).parent.parent
LOCAL_CACHE_DIR = WORKSPACE_ROOT / "local_cache"

# Ensure local cache dir exists
LOCAL_CACHE_DIR.mkdir(parents=True, exist_ok=True)

# File paths for mock persistent states
DYNAMODB_STATE_PATH = LOCAL_CACHE_DIR / "dynamodb_state.json"
IAM_STATE_PATH = LOCAL_CACHE_DIR / "iam_state.json"
S3_STATE_PATH = LOCAL_CACHE_DIR / "s3_state.json"
CLOUDWATCH_LOGS_PATH = LOCAL_CACHE_DIR / "cloudwatch_logs.json"
NEO4J_STATE_PATH = LOCAL_CACHE_DIR / "neo4j_state.json"


# ─────────────────────────────────────────────────────────────────────────────
# Helper state persistence
# ─────────────────────────────────────────────────────────────────────────────

def _load_json_state(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def _save_json_state(path: Path, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Mock Boto3 Clients
# ─────────────────────────────────────────────────────────────────────────────

class MockSTSClient:
    def get_caller_identity(self) -> dict[str, Any]:
        return {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:root",
            "UserId": "AIDAODHJF9283JHDF9"
        }

class MockS3Client:
    def __init__(self):
        # Initialize bucket state if not exists
        if not S3_STATE_PATH.exists():
            _save_json_state(S3_STATE_PATH, {"buckets": {}, "objects": {}})

    def create_bucket(self, Bucket: str, CreateBucketConfiguration: dict = None) -> dict:
        state = _load_json_state(S3_STATE_PATH, {"buckets": {}, "objects": {}})
        state["buckets"][Bucket] = {"created_at": datetime.now(timezone.utc).isoformat()}
        _save_json_state(S3_STATE_PATH, state)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def put_bucket_versioning(self, Bucket: str, VersioningConfiguration: dict) -> dict:
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def put_public_access_block(self, Bucket: str, PublicAccessBlockConfiguration: dict) -> dict:
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def put_bucket_policy(self, Bucket: str, Policy: str) -> dict:
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def put_object(self, Bucket: str, Key: str, Body: bytes = b"test", Metadata: dict = None) -> dict:
        # Check if key is deleted or blocked in IAM state
        iam_state = _load_json_state(IAM_STATE_PATH, {})
        attacker_keys = iam_state.get("users", {}).get("killswitch-attacker", {}).get("access_keys", {})
        
        # Check if the attacker is blocked/revoked
        # If the attacker has no active keys, or has a deny policy on s3:PutObject, raise ClientError
        user_policies = iam_state.get("users", {}).get("killswitch-attacker", {}).get("policies", {})
        blocked = False
        
        # If keys are deleted or inactive
        active_keys = [k for k, v in attacker_keys.items() if v == "Active"]
        # In mock mode, we assume attacker key was used if the request is done by attacker.
        # But simulator uses key directly. Let's see if active keys exist.
        # If we deleted keys in revoke.py, active_keys will be empty.
        if not active_keys and "burst" in Key:  # Simulate attack block
            blocked = True

        for p_name, policy_doc in user_policies.items():
            statements = policy_doc.get("Statement", [])
            for stmt in statements:
                if stmt.get("Effect") == "Deny":
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if "s3:*" in actions or "s3:PutObject" in actions:
                        # Check condition
                        cond = stmt.get("Condition", {})
                        if cond:
                            expiry_str = cond.get("DateGreaterThan", {}).get("aws:CurrentTime")
                            if expiry_str:
                                expiry = datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                                if datetime.now(timezone.utc) < expiry:
                                    blocked = True
                        else:
                            blocked = True

        if blocked:
            from botocore.exceptions import ClientError
            raise ClientError(
                error_response={"Error": {"Code": "AccessDenied", "Message": "Access Denied by Kill-Switch"}},
                operation_name="PutObject"
            )

        state = _load_json_state(S3_STATE_PATH, {"buckets": {}, "objects": {}})
        state["objects"][f"{Bucket}/{Key}"] = {
            "size": len(Body),
            "uploaded_at": datetime.now(timezone.utc).isoformat()
        }
        _save_json_state(S3_STATE_PATH, state)

        # Trigger rate monitor Lambda locally
        self._trigger_rate_monitor("PutObject", Bucket, Key)

        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def delete_object(self, Bucket: str, Key: str) -> dict:
        # Check if blocked
        iam_state = _load_json_state(IAM_STATE_PATH, {})
        user_policies = iam_state.get("users", {}).get("killswitch-attacker", {}).get("policies", {})
        blocked = False
        
        for p_name, policy_doc in user_policies.items():
            statements = policy_doc.get("Statement", [])
            for stmt in statements:
                if stmt.get("Effect") == "Deny":
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if "s3:*" in actions or "s3:DeleteObject" in actions:
                        blocked = True

        if blocked:
            from botocore.exceptions import ClientError
            raise ClientError(
                error_response={"Error": {"Code": "AccessDenied", "Message": "Access Denied by Kill-Switch"}},
                operation_name="DeleteObject"
            )

        state = _load_json_state(S3_STATE_PATH, {"buckets": {}, "objects": {}})
        obj_key = f"{Bucket}/{Key}"
        if obj_key in state["objects"]:
            del state["objects"][obj_key]
        _save_json_state(S3_STATE_PATH, state)

        # Trigger rate monitor Lambda locally
        self._trigger_rate_monitor("DeleteObject", Bucket, Key)

        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def _trigger_rate_monitor(self, event_name: str, bucket: str, key: str) -> None:
        """Trigger the Lambda handler locally to simulate EventBridge delivery."""
        event = {
            "source": "aws.s3",
            "detail-type": "AWS API Call via CloudTrail",
            "detail": {
                "eventSource": "s3.amazonaws.com",
                "eventName": event_name,
                "eventTime": datetime.now(timezone.utc).isoformat(),
                "userIdentity": {
                    "arn": "arn:aws:iam::123456789012:user/killswitch-attacker",
                    "type": "IAMUser",
                    "principalId": "killswitch-attacker"
                },
                "requestParameters": {
                    "bucketName": bucket,
                    "key": key
                },
                "sourceIPAddress": "127.0.0.1",
                "userAgent": "local-attacker-simulator"
            }
        }
        
        # Import rate_monitor handler dynamically to avoid circular imports
        try:
            from detector.rate_monitor import handler as rate_monitor_handler
            rate_monitor_handler(event, None)
        except Exception as e:
            import traceback
            print(f"[MOCK S3] Error triggering rate monitor: {e}", file=sys.stderr)
            traceback.print_exc()


class MockDynamoDBClient:
    def __init__(self):
        if not DYNAMODB_STATE_PATH.exists():
            _save_json_state(DYNAMODB_STATE_PATH, {})

    def create_table(self, **kwargs) -> dict:
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_waiter(self, waiter_name: str) -> Any:
        class TableWaiter:
            def wait(self, **kwargs):
                return True
        return TableWaiter()

    def get_item(self, TableName: str, Key: dict, ConsistentRead: bool = False) -> dict:
        state = _load_json_state(DYNAMODB_STATE_PATH, {})
        principal_arn = Key.get("principal_arn", {}).get("S", "")
        item = state.get(principal_arn, {})
        if not item:
            return {}
        
        # Convert flat representation to DynamoDB types
        db_item = {}
        for k, v in item.items():
            if isinstance(v, (int, float)):
                db_item[k] = {"N": str(v)}
            else:
                db_item[k] = {"S": str(v)}
        return {"Item": db_item}

    def put_item(self, TableName: str, Item: dict) -> dict:
        state = _load_json_state(DYNAMODB_STATE_PATH, {})
        principal_arn = Item.get("principal_arn", {}).get("S", "")
        
        # Convert DDB types to flat
        flat_item = {}
        for k, v in Item.items():
            if "S" in v:
                flat_item[k] = v["S"]
            elif "N" in v:
                # parse as float or int
                val = v["N"]
                if "." in val:
                    flat_item[k] = float(val)
                else:
                    flat_item[k] = int(val)
        
        state[principal_arn] = flat_item
        _save_json_state(DYNAMODB_STATE_PATH, state)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def update_item(self, TableName: str, Key: dict, UpdateExpression: str, ExpressionAttributeValues: dict) -> dict:
        state = _load_json_state(DYNAMODB_STATE_PATH, {})
        principal_arn = Key.get("principal_arn", {}).get("S", "")
        
        if principal_arn not in state:
            state[principal_arn] = {"principal_arn": principal_arn}

        # Handle simple SET risk_score = :score, risk_scored_at = :ts
        # Parse ExpressionAttributeValues
        for k, v in ExpressionAttributeValues.items():
            # e.g. ":score"
            field = None
            if k == ":score":
                field = "risk_score"
            elif k == ":ts":
                field = "risk_scored_at"
            
            if field:
                val = v.get("S") or v.get("N")
                if v.get("N"):
                    state[principal_arn][field] = int(val)
                else:
                    state[principal_arn][field] = val
                    
        _save_json_state(DYNAMODB_STATE_PATH, state)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


class MockIAMClient:
    def __init__(self):
        if not IAM_STATE_PATH.exists():
            # Initialize with default users and roles for patterns.py matching
            default_state = {
                "users": {
                    "killswitch-attacker": {
                        "arn": "arn:aws:iam::123456789012:user/killswitch-attacker",
                        "policies": {
                            "killswitch-attacker-toxic-privs": {
                                "Version": "2012-10-17",
                                "Statement": [{
                                    "Sid": "KillSwitchToxicPrivs",
                                    "Effect": "Allow",
                                    "Action": [
                                        "iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"
                                    ],
                                    "Resource": ["*"]
                                }]
                            }
                        },
                        "access_keys": {}
                    },
                    "admin-user": {
                        "arn": "arn:aws:iam::123456789012:user/admin-user",
                        "policies": {
                            "AdministratorAccess": {
                                "Version": "2012-10-17",
                                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                            }
                        },
                        "access_keys": {}
                    }
                },
                "roles": {
                    "killswitch-lambda-role": {
                        "arn": "arn:aws:iam::123456789012:role/killswitch-lambda-role",
                        "trust_policy": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }]
                        },
                        "policies": {
                            "killswitch-lambda-exec-policy": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {"Effect": "Allow", "Action": ["logs:*", "dynamodb:*", "iam:*", "sns:*"], "Resource": "*"}
                                ]
                            }
                        }
                    }
                }
            }
            _save_json_state(IAM_STATE_PATH, default_state)

    def create_user(self, UserName: str) -> dict:
        state = _load_json_state(IAM_STATE_PATH, {})
        if UserName not in state["users"]:
            state["users"][UserName] = {
                "arn": f"arn:aws:iam::123456789012:user/{UserName}",
                "policies": {},
                "access_keys": {}
            }
        _save_json_state(IAM_STATE_PATH, state)
        return {"User": {"UserName": UserName, "Arn": state["users"][UserName]["arn"]}}

    def put_user_policy(self, UserName: str, PolicyName: str, PolicyDocument: str) -> dict:
        state = _load_json_state(IAM_STATE_PATH, {})
        doc = json.loads(PolicyDocument)
        if UserName in state["users"]:
            state["users"][UserName]["policies"][PolicyName] = doc
        _save_json_state(IAM_STATE_PATH, state)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def list_access_keys(self, UserName: str) -> dict:
        state = _load_json_state(IAM_STATE_PATH, {})
        user = state.get("users", {}).get(UserName, {})
        keys = user.get("access_keys", {})
        
        metadata = []
        for key_id, status in keys.items():
            metadata.append({
                "UserName": UserName,
                "AccessKeyId": key_id,
                "Status": status,
                "CreateDate": datetime.now(timezone.utc).isoformat()
            })
        return {"AccessKeyMetadata": metadata}

    def delete_access_key(self, UserName: str, AccessKeyId: str) -> dict:
        state = _load_json_state(IAM_STATE_PATH, {})
        if UserName in state["users"] and AccessKeyId in state["users"][UserName]["access_keys"]:
            del state["users"][UserName]["access_keys"][AccessKeyId]
        _save_json_state(IAM_STATE_PATH, state)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def create_access_key(self, UserName: str) -> dict:
        state = _load_json_state(IAM_STATE_PATH, {})
        import secrets
        key_id = "AKIA" + secrets.token_hex(8).upper()
        secret = secrets.token_urlsafe(30)
        if UserName in state["users"]:
            state["users"][UserName]["access_keys"][key_id] = "Active"
        _save_json_state(IAM_STATE_PATH, state)
        return {
            "AccessKey": {
                "UserName": UserName,
                "AccessKeyId": key_id,
                "SecretAccessKey": secret,
                "Status": "Active"
            }
        }

    def create_role(self, RoleName: str, AssumeRolePolicyDocument: str, **kwargs) -> dict:
        state = _load_json_state(IAM_STATE_PATH, {})
        doc = json.loads(AssumeRolePolicyDocument)
        state["roles"][RoleName] = {
            "arn": f"arn:aws:iam::123456789012:role/{RoleName}",
            "trust_policy": doc,
            "policies": {}
        }
        _save_json_state(IAM_STATE_PATH, state)
        return {"Role": {"RoleName": RoleName, "Arn": state["roles"][RoleName]["arn"]}}

    def get_role(self, RoleName: str) -> dict:
        state = _load_json_state(IAM_STATE_PATH, {})
        role = state.get("roles", {}).get(RoleName, {})
        if not role:
            from botocore.exceptions import ClientError
            raise ClientError(
                error_response={"Error": {"Code": "NoSuchEntity", "Message": "Role not found"}},
                operation_name="GetRole"
            )
        return {"Role": {"RoleName": RoleName, "Arn": role["arn"]}}

    def put_role_policy(self, RoleName: str, PolicyName: str, PolicyDocument: str) -> dict:
        state = _load_json_state(IAM_STATE_PATH, {})
        doc = json.loads(PolicyDocument)
        if RoleName in state["roles"]:
            state["roles"][RoleName]["policies"][PolicyName] = doc
        _save_json_state(IAM_STATE_PATH, state)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_paginator(self, operation_name: str) -> Any:
        if operation_name == "get_account_authorization_details":
            class IAMDetailsPaginator:
                def paginate(self, **kwargs):
                    # Fetch from local state to generate details
                    state = _load_json_state(IAM_STATE_PATH, {})
                    
                    user_details = []
                    for name, details in state.get("users", {}).items():
                        inline_list = []
                        for pname, pdoc in details["policies"].items():
                            inline_list.append({
                                "PolicyName": pname,
                                "PolicyDocument": urllib.parse.quote(json.dumps(pdoc))
                            })
                        user_details.append({
                            "UserName": name,
                            "Arn": details["arn"],
                            "UserPolicyList": inline_list,
                            "AttachedManagedPolicies": [],
                            "GroupList": [],
                            "Path": "/",
                            "CreateDate": datetime.now(timezone.utc).isoformat()
                        })
                        
                    role_details = []
                    for name, details in state.get("roles", {}).items():
                        inline_list = []
                        for pname, pdoc in details["policies"].items():
                            inline_list.append({
                                "PolicyName": pname,
                                "PolicyDocument": urllib.parse.quote(json.dumps(pdoc))
                            })
                        role_details.append({
                            "RoleName": name,
                            "Arn": details["arn"],
                            "AssumeRolePolicyDocument": urllib.parse.quote(json.dumps(details["trust_policy"])),
                            "RolePolicyList": inline_list,
                            "AttachedManagedPolicies": [],
                            "Path": "/",
                            "CreateDate": datetime.now(timezone.utc).isoformat()
                        })
                    
                    # Yield a single page of results
                    yield {
                        "UserDetailList": user_details,
                        "GroupDetailList": [],
                        "RoleDetailList": role_details,
                        "Policies": [
                            {
                                "PolicyName": "AdministratorAccess",
                                "Arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                                "DefaultVersionId": "v1",
                                "PolicyVersionList": [
                                    {
                                        "VersionId": "v1",
                                        "IsDefaultVersion": True,
                                        "Document": urllib.parse.quote(json.dumps({
                                            "Version": "2012-10-17",
                                            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                                        }))
                                    }
                                ]
                            }
                        ]
                    }
            return IAMDetailsPaginator()
        raise NotImplementedError(f"Mock paginator for {operation_name} not built")


class MockSNSClient:
    def create_topic(self, Name: str) -> dict:
        return {"TopicArn": f"arn:aws:sns:us-east-1:123456789012:{Name}"}

    def publish(self, TopicArn: str, Subject: str, Message: str) -> dict:
        print(f"\n[bold magenta][SNS NOTIFICATION RECEIVED][/bold magenta]")
        print(f"Topic:   {TopicArn}")
        print(f"Subject: {Subject}")
        print(f"Message:\n{Message}\n")
        return {"MessageId": "mock-message-id-12345"}


class MockLogsClient:
    def create_log_group(self, logGroupName: str) -> dict:
        return {}

    def put_retention_policy(self, logGroupName: str, retentionInDays: int) -> dict:
        return {}

    def create_log_stream(self, logGroupName: str, logStreamName: str) -> dict:
        return {}

    def put_log_events(self, logGroupName: str, logStreamName: str, logEvents: list[dict]) -> dict:
        state = _load_json_state(CLOUDWATCH_LOGS_PATH, [])
        for ev in logEvents:
            state.append({
                "logGroup": logGroupName,
                "logStream": logStreamName,
                "timestamp": ev["timestamp"],
                "message": ev["message"]
            })
        _save_json_state(CLOUDWATCH_LOGS_PATH, state)
        
        # Also print to stdout for demo tracking
        print(f"\n[dim][CloudWatch Log] {logGroupName} -> {ev['message']}[/dim]")
        return {"nextSequenceToken": "mock-token"}


class MockCloudTrailClient:
    def create_trail(self, **kwargs) -> dict:
        return {"TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/killswitch-trail"}

    def get_trail(self, **kwargs) -> dict:
        return {"Trail": {"TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/killswitch-trail"}}

    def start_logging(self, **kwargs) -> dict:
        return {}

    def put_event_selectors(self, **kwargs) -> dict:
        return {}

    def lookup_events(self, LookupAttributes: list[dict], StartTime: datetime, EndTime: datetime, MaxResults: int = 10) -> dict:
        # Returns a list of events to satisfy verify_pipeline.py and remediate.py
        # Find which bucket and events we look for
        bucket = None
        event_name = None
        for attr in LookupAttributes:
            if attr["AttributeKey"] == "ResourceName":
                bucket = attr["AttributeValue"]
            elif attr["AttributeKey"] == "EventName":
                event_name = attr["AttributeValue"]

        # Generate a list of mock events
        events = []
        
        # If it's a verify_pipeline check, return a matching PutObject event
        if event_name == "PutObject" and bucket:
            # Find the actual verify-pipeline key uploaded to S3
            s3_state = _load_json_state(S3_STATE_PATH, {"buckets": {}, "objects": {}})
            actual_key = "verify-pipeline/canary-1234.txt"
            for obj_key in s3_state.get("objects", {}).keys():
                if obj_key.startswith(f"{bucket}/verify-pipeline/"):
                    actual_key = obj_key[len(bucket)+1:]
                    break
            
            events.append({
                "EventId": "verify-event-id",
                "EventName": "PutObject",
                "EventTime": datetime.now(timezone.utc).isoformat(),
                "Username": "admin-user",
                "Resources": [{"ResourceType": "AWS::S3::Object", "ResourceName": f"{bucket}/{actual_key}"}],
                "CloudTrailEvent": json.dumps({
                    "eventVersion": "1.08",
                    "userIdentity": {
                        "type": "IAMUser",
                        "arn": "arn:aws:iam::123456789012:user/admin-user",
                        "userName": "admin-user"
                    },
                    "eventName": "PutObject",
                    "requestParameters": {
                        "bucketName": bucket,
                        "key": actual_key
                    }
                })
            })
        else:
            # General lookup for remediate.py: return recent s3 actions by the attacker
            events = [
                {
                    "EventId": "event-1",
                    "EventName": "PutObject",
                    "EventTime": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
                    "Username": "killswitch-attacker",
                    "Resources": [{"ResourceType": "AWS::S3::Object", "ResourceName": "killswitch-test-123456789012/attack/burst-1.dat"}],
                    "CloudTrailEvent": json.dumps({"eventName": "PutObject", "requestParameters": {"bucketName": "killswitch-test-123456789012", "key": "attack/burst-1.dat"}})
                },
                {
                    "EventId": "event-2",
                    "EventName": "PutObject",
                    "EventTime": (datetime.now(timezone.utc) - timedelta(minutes=4)).isoformat(),
                    "Username": "killswitch-attacker",
                    "Resources": [{"ResourceType": "AWS::S3::Object", "ResourceName": "killswitch-test-123456789012/attack/burst-2.dat"}],
                    "CloudTrailEvent": json.dumps({"eventName": "PutObject", "requestParameters": {"bucketName": "killswitch-test-123456789012", "key": "attack/burst-2.dat"}})
                }
            ]
        return {"Events": events}


class MockEventBridgeClient:
    def put_rule(self, **kwargs) -> dict:
        return {"RuleArn": "arn:aws:events:us-east-1:123456789012:rule/killswitch-s3-events"}

    def put_targets(self, **kwargs) -> dict:
        return {}


class MockLambdaClient:
    def create_function(self, **kwargs) -> dict:
        return {"FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:killswitch-detector"}

    def update_function_code(self, **kwargs) -> dict:
        return {}

    def update_function_configuration(self, **kwargs) -> dict:
        return {}

    def get_function(self, **kwargs) -> dict:
        return {"Configuration": {"FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:killswitch-detector"}}

    def get_waiter(self, waiter_name: str) -> Any:
        class LambdaWaiter:
            def wait(self, **kwargs):
                return True
        return LambdaWaiter()

    def add_permission(self, **kwargs) -> dict:
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# Central Client Factory
# ─────────────────────────────────────────────────────────────────────────────

def get_mock_client(service_name: str, *args, **kwargs) -> Any:
    services = {
        "sts": MockSTSClient,
        "s3": MockS3Client,
        "dynamodb": MockDynamoDBClient,
        "iam": MockIAMClient,
        "sns": MockSNSClient,
        "logs": MockLogsClient,
        "cloudtrail": MockCloudTrailClient,
        "events": MockEventBridgeClient,
        "lambda": MockLambdaClient,
    }
    if service_name in services:
        return services[service_name]()
    raise NotImplementedError(f"Mock client for AWS service '{service_name}' not implemented")


# ─────────────────────────────────────────────────────────────────────────────
# Mock Neo4j Graph Database
# ─────────────────────────────────────────────────────────────────────────────

class MockNeo4jSession:
    def __init__(self, graph: MockGraph):
        self.graph = graph

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def run(self, query: str, **parameters) -> MockResult:
        return self.graph.execute_query(query, parameters)


class MockResult:
    def __init__(self, records: list[dict]):
        self.records = records
        self._index = 0

    def __iter__(self):
        return iter(self.records)

    def single(self) -> dict | None:
        if self.records:
            return self.records[0]
        return None


class MockGraph:
    def __init__(self):
        self.nodes: dict[str, dict[str, Any]] = {}  # key is node primary ID (arn/name/arn_pattern)
        self.node_labels: dict[str, str] = {}  # key -> label (Principal, Action, Resource, ManagedPolicy)
        self.edges: list[dict[str, Any]] = []
        self.load()

    def load(self):
        data = _load_json_state(NEO4J_STATE_PATH, {"nodes": {}, "node_labels": {}, "edges": []})
        self.nodes = data["nodes"]
        self.node_labels = data["node_labels"]
        self.edges = data["edges"]

    def save(self):
        data = {
            "nodes": self.nodes,
            "node_labels": self.node_labels,
            "edges": self.edges
        }
        _save_json_state(NEO4J_STATE_PATH, data)

    def execute_query(self, query: str, params: dict[str, Any]) -> MockResult:
        query_stripped = " ".join(query.split())
        result = self._execute_query_internal(query_stripped, params)
        
        # Save if modifying
        if any(kw in query_stripped for kw in ["MERGE", "DELETE", "SET", "CREATE"]):
            self.save()
            
        return result

    def _execute_query_internal(self, query_stripped: str, params: dict[str, Any]) -> MockResult:

        # 1. Clear Graph
        if "MATCH (n) DETACH DELETE n" in query_stripped:
            self.nodes.clear()
            self.node_labels.clear()
            self.edges.clear()
            return MockResult([])

        # 2. Constraints (ignore)
        if "CREATE CONSTRAINT" in query_stripped:
            return MockResult([])

        # 3. MERGE Principal
        if "MERGE (p:Principal {arn: $arn})" in query_stripped:
            arn = params["arn"]
            self.nodes[arn] = {
                "arn": arn,
                "name": params["name"],
                "type": params["type"],
                "path": params["path"],
                "risk_score": None
            }
            self.node_labels[arn] = "Principal"
            return MockResult([])

        # 4. MERGE Action
        if "MERGE (a:Action {name: $name})" in query_stripped:
            name = params["name"]
            self.nodes[name] = {
                "name": name,
                "is_high_privilege": params["is_high_priv"]
            }
            self.node_labels[name] = "Action"
            return MockResult([])

        # 5. MERGE Resource
        if "MERGE (r:Resource {arn_pattern: $arn_pattern})" in query_stripped:
            arn_pattern = params["arn_pattern"]
            self.nodes[arn_pattern] = {
                "arn_pattern": arn_pattern,
                "is_wildcard": params["is_wildcard"]
            }
            self.node_labels[arn_pattern] = "Resource"
            return MockResult([])

        # 6. MERGE Edges (CAN_PERFORM, ON, MEMBER_OF, CAN_ASSUME)
        if "MERGE (p)-[:CAN_PERFORM" in query_stripped:
            p_arn = params["principal_arn"]
            a_name = params["action_name"]
            r_arn = params["resource_arn"]
            effect = params["effect"]
            via_policy = params["via_policy"]
            
            # Create nodes if not exist (fail-safe)
            if p_arn not in self.nodes:
                self.nodes[p_arn] = {"arn": p_arn, "name": p_arn, "type": "inferred", "path": "/"}
                self.node_labels[p_arn] = "Principal"
            if a_name not in self.nodes:
                self.nodes[a_name] = {"name": a_name, "is_high_privilege": False}
                self.node_labels[a_name] = "Action"
            if r_arn not in self.nodes:
                self.nodes[r_arn] = {"arn_pattern": r_arn, "is_wildcard": "*" in r_arn}
                self.node_labels[r_arn] = "Resource"

            # Principal -> Action
            self.edges.append({
                "from": p_arn, "to": a_name, "type": "CAN_PERFORM",
                "properties": {"effect": effect, "via_policy": via_policy}
            })
            # Action -> Resource
            self.edges.append({
                "from": a_name, "to": r_arn, "type": "ON", "properties": {}
            })
            return MockResult([])

        if "MERGE (u)-[:MEMBER_OF]->(g)" in query_stripped:
            u_arn = params["user_arn"]
            g_arn = params["group_arn"]
            self.edges.append({
                "from": u_arn, "to": g_arn, "type": "MEMBER_OF", "properties": {}
            })
            return MockResult([])

        if "MERGE (t)-[:CAN_ASSUME" in query_stripped:
            t_arn = params["trustee_arn"]
            r_arn = params["role_arn"]
            cond = params["has_condition"]
            
            if t_arn not in self.nodes:
                self.nodes[t_arn] = {"arn": t_arn, "name": t_arn, "type": "inferred"}
                self.node_labels[t_arn] = "Principal"
                
            self.edges.append({
                "from": t_arn, "to": r_arn, "type": "CAN_ASSUME",
                "properties": {"has_condition": cond}
            })
            return MockResult([])

        # 7. Write Risk Score
        if "SET p.risk_score = $score" in query_stripped:
            arn = params["arn"]
            if arn in self.nodes:
                self.nodes[arn]["risk_score"] = params["score"]
            return MockResult([])

        # 8. Summary Query
        if "MATCH (p:Principal) WITH count(p)" in query_stripped:
            principals = sum(1 for label in self.node_labels.values() if label == "Principal")
            actions = sum(1 for label in self.node_labels.values() if label == "Action")
            resources = sum(1 for label in self.node_labels.values() if label == "Resource")
            return MockResult([{
                "principals": principals,
                "actions": actions,
                "resources": resources
            }])

        # 9. Shortest Path To Admin
        if "MATCH path = shortestPath(" in query_stripped:
            # BFS to find shortest path from principal to any admin Action node
            p_arn = params["principal_arn"]
            admin_actions = params["admin_actions"]
            
            queue = [(p_arn, 0)]
            visited = {p_arn}
            
            shortest = None
            while queue:
                curr, dist = queue.pop(0)
                
                # Check if current node is an Action and is admin-equivalent
                if self.node_labels.get(curr) == "Action":
                    node_props = self.nodes[curr]
                    if curr in admin_actions or node_props.get("is_high_privilege"):
                        shortest = dist
                        break
                
                # Expand neighbors
                for edge in self.edges:
                    if edge["from"] == curr:
                        nxt = edge["to"]
                        if nxt not in visited:
                            visited.add(nxt)
                            queue.append((nxt, dist + 1))
                            
            if shortest is not None:
                return MockResult([{"path_length": shortest}])
            return MockResult([])

        # 10. Blast Radius Count
        if "count(DISTINCT r.arn_pattern) AS resource_count" in query_stripped:
            p_arn = params["principal_arn"]
            # BFS to find all reachable resources
            queue = [p_arn]
            visited = {p_arn}
            resources = set()
            
            while queue:
                curr = queue.pop(0)
                if self.node_labels.get(curr) == "Resource":
                    resources.add(curr)
                
                for edge in self.edges:
                    if edge["from"] == curr:
                        nxt = edge["to"]
                        if nxt not in visited:
                            visited.add(nxt)
                            queue.append(nxt)
            return MockResult([{"resource_count": len(resources)}])

        # 11. Escalation Chain RSL-01 Cypher Query
        if "RSL-01" in query_stripped:
            # Find principals with ALLOW for PassRole, CreateFunction, InvokeFunction
            flagged = []
            for p_arn, node in self.nodes.items():
                if self.node_labels.get(p_arn) != "Principal":
                    continue
                allowed_actions = self._get_allowed_actions(p_arn)
                if (self._has_action(allowed_actions, "iam:PassRole") and 
                    self._has_action(allowed_actions, "lambda:CreateFunction") and 
                    self._has_action(allowed_actions, "lambda:InvokeFunction")):
                    flagged.append({
                        "principal_arn": p_arn,
                        "principal_name": node.get("name", ""),
                        "principal_type": node.get("type", ""),
                        "chain_id": "RSL-01",
                        "matched_actions": "iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction"
                    })
            return MockResult(flagged)

        # 12. Escalation Chain RSL-02 Cypher Query
        if "RSL-02" in query_stripped:
            # PassRole + ec2:RunInstances
            flagged = []
            for p_arn, node in self.nodes.items():
                if self.node_labels.get(p_arn) != "Principal":
                    continue
                allowed_actions = self._get_allowed_actions(p_arn)
                if self._has_action(allowed_actions, "iam:PassRole") and self._has_action(allowed_actions, "ec2:RunInstances"):
                    flagged.append({
                        "principal_arn": p_arn,
                        "principal_name": node.get("name", ""),
                        "principal_type": node.get("type", ""),
                        "chain_id": "RSL-02",
                        "matched_actions": "iam:PassRole + ec2:RunInstances"
                    })
            return MockResult(flagged)

        # 13. Escalation Chain RSL-03 Cypher Query
        if "RSL-03" in query_stripped:
            # iam:CreatePolicyVersion
            flagged = []
            for p_arn, node in self.nodes.items():
                if self.node_labels.get(p_arn) != "Principal":
                    continue
                allowed_actions = self._get_allowed_actions(p_arn)
                if self._has_action(allowed_actions, "iam:CreatePolicyVersion"):
                    flagged.append({
                        "principal_arn": p_arn,
                        "principal_name": node.get("name", ""),
                        "principal_type": node.get("type", ""),
                        "chain_id": "RSL-03",
                        "matched_actions": "iam:CreatePolicyVersion"
                    })
            return MockResult(flagged)

        # 14. Escalation Chain RSL-04 Cypher Query
        if "RSL-04" in query_stripped:
            # iam:SetDefaultPolicyVersion
            flagged = []
            for p_arn, node in self.nodes.items():
                if self.node_labels.get(p_arn) != "Principal":
                    continue
                allowed_actions = self._get_allowed_actions(p_arn)
                if self._has_action(allowed_actions, "iam:SetDefaultPolicyVersion"):
                    flagged.append({
                        "principal_arn": p_arn,
                        "principal_name": node.get("name", ""),
                        "principal_type": node.get("type", ""),
                        "chain_id": "RSL-04",
                        "matched_actions": "iam:SetDefaultPolicyVersion"
                    })
            return MockResult(flagged)

        # 15. Escalation Chain RSL-05 Cypher Query
        if "RSL-05" in query_stripped:
            # Attach policy to self
            flagged = []
            risky = ['iam:AttachUserPolicy', 'iam:AttachRolePolicy', 'iam:PutUserPolicy', 'iam:PutRolePolicy', 'iam:*', '*']
            for p_arn, node in self.nodes.items():
                if self.node_labels.get(p_arn) != "Principal":
                    continue
                allowed_actions = self._get_allowed_actions(p_arn)
                matched = any(self._has_action(allowed_actions, a) for a in risky)
                if matched:
                    action_name = next((a for a in risky if self._has_action(allowed_actions, a)), "iam:AttachUserPolicy")
                    flagged.append({
                        "principal_arn": p_arn,
                        "principal_name": node.get("name", ""),
                        "principal_type": node.get("type", ""),
                        "chain_id": "RSL-05",
                        "matched_actions": action_name
                    })
            return MockResult(flagged)

        # 16. Escalation Chain RSL-06 Cypher Query
        if "RSL-06" in query_stripped:
            # Unconstrained assume role on admin role
            # MATCH (trustee:Principal)-[c:CAN_ASSUME {has_condition: false}]->(role:Principal)
            # Find roles that have high privilege, and trustees who can assume them with has_condition = False
            flagged = []
            for edge in self.edges:
                if edge["type"] == "CAN_ASSUME" and edge["properties"].get("has_condition") is False:
                    trustee_arn = edge["from"]
                    role_arn = edge["to"]
                    
                    # Verify role has high privilege actions
                    role_actions = self._get_allowed_actions(role_arn)
                    high_priv = any(self._has_action(role_actions, a) for a in ["*", "iam:*", "iam:PassRole", "iam:CreatePolicyVersion"])
                    
                    if high_priv:
                        trustee_node = self.nodes.get(trustee_arn, {"name": trustee_arn, "type": "inferred"})
                        flagged.append({
                            "principal_arn": trustee_arn,
                            "principal_name": trustee_node.get("name", ""),
                            "principal_type": trustee_node.get("type", ""),
                            "chain_id": "RSL-06",
                            "matched_actions": f"sts:AssumeRole (no Condition) + high-priv role: {role_arn}"
                        })
            return MockResult(flagged)

        # 17. High privilege principals query
        if "a.is_high_privilege = true" in query_stripped:
            flagged = []
            for p_arn, node in self.nodes.items():
                if self.node_labels.get(p_arn) != "Principal":
                    continue
                allowed_actions = self._get_allowed_actions(p_arn)
                # If they have high privilege action
                high_priv = False
                for act in allowed_actions:
                    act_node = self.nodes.get(act, {})
                    if act_node.get("is_high_privilege"):
                        high_priv = True
                        break
                if high_priv:
                    flagged.append({
                        "p": node,
                        "a": {"name": "high_privilege_action"}
                    })
            return MockResult(flagged)

        # 18. Principals with risk score
        if "p.risk_score IS NOT NULL" in query_stripped:
            scored = []
            for p_arn, node in self.nodes.items():
                if self.node_labels.get(p_arn) == "Principal" and node.get("risk_score") is not None:
                    scored.append({
                        "p.name": node.get("name"),
                        "p.risk_score": node.get("risk_score")
                    })
            return MockResult(scored)

        return MockResult([])

    def _has_action(self, allowed: set[str], target: str) -> bool:
        if "*" in allowed:
            return True
        if target in allowed:
            return True
        parts = target.split(":")
        if len(parts) == 2:
            if f"{parts[0]}:*" in allowed:
                return True
        return False

    def _get_allowed_actions(self, principal_arn: str) -> set[str]:
        # Traverses CAN_PERFORM and MEMBER_OF to collect actions
        allowed = set()
        queue = [principal_arn]
        visited = {principal_arn}
        
        while queue:
            curr = queue.pop(0)
            
            # Find direct CAN_PERFORM actions
            for edge in self.edges:
                if edge["from"] == curr:
                    if edge["type"] == "CAN_PERFORM" and edge["properties"].get("effect") == "Allow":
                        allowed.add(edge["to"])
                    elif edge["type"] == "MEMBER_OF":
                        nxt = edge["to"]
                        if nxt not in visited:
                            visited.add(nxt)
                            queue.append(nxt)
                            
        return allowed


class MockNeo4jDriver:
    _global_graph = MockGraph()

    def __init__(self, uri: str, auth: tuple[str, str] = None):
        self.uri = uri
        self.auth = auth

    def verify_connectivity(self) -> None:
        pass

    def session(self, **kwargs) -> MockNeo4jSession:
        return MockNeo4jSession(self._global_graph)

    def close(self) -> None:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Monkey-Patching Entrypoints
# ─────────────────────────────────────────────────────────────────────────────

if MOCK_MODE:
    import boto3
    boto3.client = get_mock_client
    
    try:
        import neo4j
        neo4j.GraphDatabase.driver = lambda uri, auth=None, **kwargs: MockNeo4jDriver(uri, auth)
    except ImportError:
        # If neo4j is not installed in the current env, we define it in sys.modules
        # to prevent import errors in graph_builder.py, patterns.py, etc.
        class FakeNeo4jModule:
            class GraphDatabase:
                @staticmethod
                def driver(uri: str, auth: tuple[str, str] = None, **kwargs):
                    return MockNeo4jDriver(uri, auth)
            class exceptions:
                class ServiceUnavailable(Exception):
                    pass
        sys.modules["neo4j"] = FakeNeo4jModule  # type: ignore[assignment]
        sys.modules["neo4j.exceptions"] = FakeNeo4jModule.exceptions  # type: ignore[assignment]

    print("[MOCK PROVIDER] Mock Mode Activated. AWS and Neo4j API calls will be intercepted.")
