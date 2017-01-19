#!/bin/bash
[ -z "$OPENSHIFT_URL" ] && echo "Need to set env OPENSHIFT_URL" && exit 1
oc project aws-ad-accounts-sync
echo "Building docker image ..."
docker build -t aws_ad_accounts_sync .
docker tag `docker images|grep aws_ad_accounts_sync|tail -1|awk '{print $3}'` $OPENSHIFT_URL/aws_tools/aws-ad-accounts-sync
echo "Tagging docker image  ..."
docker push $OPENSHIFT_URL/aws_tools/aws-ad-accounts-sync
echo "Pushing docker image  ..."
sed -i.bak -e s/{OPENSHIFT_URL}/$OPENSHIFT_URL/g openshift_template.yml
echo "Deploying to openshift..."
oc process -f openshift_template.yml | oc apply -f -
oc deploy aws-ad-accounts-sync --latest=true
sed -i.bak -e s/$OPENSHIFT_URL/'{OPENSHIFT_URL}'/g openshift_template.yml
rm openshift_template.yml.bak
