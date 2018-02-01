FROM python:2-alpine
RUN apk update && apk add --no-cache openssl ca-certificates strace git g++ libsasl libssl1.0 libldap openldap-dev && update-ca-certificates && echo "TLS_CACERTDIR /etc/ssl/certs" >> /etc/openldap/ldap.conf && pip install python-ldap requests boto3 git+https://github.com/scopely-devops/skew.git@develop && apk del git g++ openldap-dev libsasl && rm -rf /var/cache/apk/* && mkdir /src
ADD aws_ad_accounts_sync.py /src
ADD ad_corp.py /src
CMD ["/src/aws_ad_accounts_sync.py"]