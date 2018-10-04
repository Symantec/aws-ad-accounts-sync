# Automatically disable/delete AWS users when they are inactive in company directory (AD or LDAP)

### Installation
  - deploy this through aws lambda

### AWS IAM Policy for the service account
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
                "iam:Get*"
            ],
            "Effect": "Allow",
            "Resource": "*"
        }
    ]
}
```

License
----

Apache 2.0
