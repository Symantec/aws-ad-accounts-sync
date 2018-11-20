# Automatically disable/delete AWS users when they are inactive in company directory (AD or LDAP)

## Installation
- ### Installation Steps
  - ### In the account where you want to run the lambda function, do these steps:
    1. #### Create this IAM Lambda role "aws-reaper-lambda"
    2. #### Create the below IAM policy "allow-sts-to-aws-iam-user-reaper-role" and attach it to the lambda role "aws-reaper-lambda"
        ```
        {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": [
                    "arn:aws:iam::12345:role/aws-iam-user-reaper-role",
                    "arn:aws:iam::67890:role/aws-iam-user-reaper-role"
                ]
            }
        }
        ```
    3. #### Attach the AWS policy "AWSLambdaVPCAccessExecutionRole" to the lambda role aws-reaper-lambda"
    4. #### Create the lambda function with name "aws-iam-user-reaper" with the following configuration:
        ```
        (py36) ➜  / aws lambda get-function-configuration --function-name aws-iam-user-reaper
        {
            "FunctionName": "aws-iam-user-reaper",
            "FunctionArn": "arn:aws:lambda:us-east-1:<account_id>:function:aws-iam-user-reaper",
            "Runtime": "python3.6",
            "Role": "arn:aws:iam::<account_id>:role/aws-reaper-lambda",
            "Handler": "aws_ad_accounts_sync.main",
            "CodeSize": 1900791,
            "Description": "",
            "Timeout": 120,
            "MemorySize": 512,
            "LastModified": "2018-11-16T02:34:47.612+0000",
            "CodeSha256": "123",
            "Version": "$LATEST",
            "VpcConfig": {
                "SubnetIds": [
                    "subnet-123",
                    "subnet-123",
                    "subnet-123",
                    "subnet-123"
                ],
                "SecurityGroupIds": [
                    "sg-123"
                ],
                "VpcId": "vpc-123"
            },
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "899563"
        }
        ```
    5. #### Copy config.py.example to config.py, modify all the variables the way you want for which accounts you're using, which ldap, which slack notification, etc.
    6. #### Run ./bundle.sh (with python 3.6) then upload bundle.zip as the lambda function.

  - ### In every account you want to remove IAM users that aren't active in LDAP, do these 2 steps:
    1. #### Create this IAM policy: "iam-accountcleanup-policy"
        ```
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Stmt1484183937316",
                    "Action": [
                        "iam:DeleteUser",
                        "iam:DeleteUserPolicy",
                        "iam:DetachUserPolicy",
                        "iam:GetUser",
                        "iam:GetUserPolicy",
                        "iam:List*",
                        "iam:DeleteAccessKey",
                        "iam:DeleteSigningCertificate",
                        "iam:UpdateAccessKey",
                        "iam:UpdateSigningCertificate",
                        "iam:DeleteLoginProfile",
                        "iam:RemoveUserFromGroup",
                        "iam:DeleteSSHPublicKey",
                        "iam:Get*",
                        "iam:DeactivateMFADevice"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                }
            ]
        }
        ```
    2. #### Create this IAM Lambda role: "aws-iam-user-reaper-role". Attach the below trust policy. Note you need to replace the account number with your account number where your lambda function lives.
        ```
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456:role/aws-reaper-lambda"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        ```

License
----

Apache 2.0
