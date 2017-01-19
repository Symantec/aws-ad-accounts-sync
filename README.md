# Automatically disable/delete AWS users when they are inactive in active directory

### Installation
  - For deploying to openshift, cp -r secrets.example secrets, edit the secrets properly
  - oc new-project aws-ad-accounts-sync
  - oc create secret generic aws-ad-secrets --from-file=secrets
  - run ./deploy.sh to deploy to openshift
  - Setup the IAM policy as a service account for each user (policy below)

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

### TODO
- get_account_authorization_details / parallelize to make everything faster

License
----

Apache 2.0
