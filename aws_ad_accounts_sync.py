#!/usr/bin/env python

import boto3
import json
import logging
import os
import requests
import time
from ad_corp import get_all_active_ad_users
from datetime import datetime, timedelta
from skew import scan
from skew.config import get_config

logger                       = logging.getLogger('aws_ad_accounts_sync')
aws_ad_sync_run_interval     = int(os.environ.get('AWS_AD_SYNC_RUN_INTERVAL', 1800))
aws_max_delete_failsafe      = float(os.environ.get('AWS_MAX_DELETE_FAILSAFE', 0.2))
slack_aws_token              = os.environ.get('SLACK_AWS_TOKEN')
slack_aws_channel            = os.environ.get('SLACK_AWS_CHANNEL', '#general')
slack_icon_emoji             = os.environ.get('SLACK_ICON_EMOJI', ':scream_cat:')
# If the user is a service account, they get skipped. There is a different process to deal with service accounts.
aws_service_account_prefixes = ('auto-')
# This should be in days, after a user is disabled, there will be this many days since their
# access keys were used for when they get deleted.
aws_delete_grace_period      = os.environ.get('AWS_DELETE_GRACE_PERIOD', '30')
# '{"whitelist_user_1": true, "whitelist_user_2": true }'
aws_users_whitelist          = json.loads(os.environ.get('AWS_USERS_WHITELIST'))


def get_all_aws_users():
  arn = scan('arn:aws:iam::*:user/*')
  resources = []
  for resource in arn:
    resources.append(resource.data)
  return resources


def message_slack(message):
  message = '```%s```' % message
  payload = {
    'channel'   : slack_aws_channel,
    'text'      : message,
    'username'  : 'aws reaper',
    'icon_emoji': slack_icon_emoji
  }
  slack_uri = 'https://hooks.slack.com/services/%s' % slack_aws_token
  http_response = requests.post(slack_uri, data=json.dumps(payload), headers={'content-type': 'application/json'})
  http_response.raise_for_status()


def filter_out_aws_service_accounts(resources):
  human_aws_accounts = []
  for resource in resources:
    if not resource['UserName'].startswith(aws_service_account_prefixes):
      human_aws_accounts.append(resource)
  return human_aws_accounts


def get_arn_account_profile_name(arn):
  config = get_config()
  account_number = arn.split(':')[4]
  return config['accounts'][account_number]['profile']


def delete_user_ssh_keys(iam, user_name):
  action_taken = False

  def delete_user_ssh_key(iam, user_name, ssh_public_key_id):
    iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=ssh_public_key_id)
  while True:
    user_ssh_metadata = iam.list_ssh_public_keys(UserName=user_name)
    for ssh_key in user_ssh_metadata['SSHPublicKeys']:
      delete_user_ssh_key(iam, user_name, ssh_key['SSHPublicKeyId'])
      action_taken = True
    if not user_ssh_metadata['IsTruncated']:
      break
  return action_taken


def delete_user_access_keys(iam, user_name):
  action_taken = False

  def delete_user_access_key(iam, user_name, access_key_id):
    iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
  user_access_key_metadata = iam.list_access_keys(UserName=user_name)
  for user_access_key in user_access_key_metadata['AccessKeyMetadata']:
    delete_user_access_key(iam, user_name, user_access_key['AccessKeyId'])
    action_taken = True
  return action_taken


def remove_user_from_all_groups(iam, user_name):
  action_taken = False

  def remove_user_from_group(iam, user_name, group_name):
    iam.remove_user_from_group(UserName=user_name, GroupName=group_name)
  while True:
    user_group_metadata = iam.list_groups_for_user(UserName=user_name)
    for user_group in user_group_metadata['Groups']:
      remove_user_from_group(iam, user_name, user_group['GroupName'])
      action_taken = True
    if not user_group_metadata['IsTruncated']:
      break
  return action_taken


def delete_user_signing_certificates(iam, user_name):
  action_taken = False

  def delete_user_signing_certificate(iam, user_name, certificate_id):
    iam.delete_signing_certificate(UserName=user_name, CertificateId=certificate_id)
  while True:
    user_signing_certificates = iam.list_signing_certificates(UserName=user_name)
    for user_signing_certificate in user_signing_certificates['Certificates']:
      delete_user_signing_certificate(iam, user_name, user_signing_certificate['CertificateId'])
      action_taken = True
    if not user_signing_certificates['IsTruncated']:
      return action_taken


def user_keys_active_recently(iam, user_name, user_access_key_metadata, days_since_active):
  user_keys_active_recently = False
  for user_access_key in user_access_key_metadata['AccessKeyMetadata']:
    user_access_key_id   = user_access_key['AccessKeyId']
    access_key_last_used = iam.get_access_key_last_used(AccessKeyId=user_access_key_id)
    if 'LastUsedDate' not in access_key_last_used['AccessKeyLastUsed'] or access_key_last_used['AccessKeyLastUsed']['LastUsedDate'] == 'N/A':
      continue
    elif (datetime.now() - timedelta(days=int(aws_delete_grace_period))).date() < access_key_last_used['AccessKeyLastUsed']['LastUsedDate'].date():
      user_keys_active_recently = True
  return user_keys_active_recently


def disable_user_signing_certificates(iam, user_name):
  action_taken = False

  def disable_user_signing_certificate(iam, user_name, certificate_id):
    iam.update_signing_certificate(UserName=user_name, CertificateId=certificate_id, Status='Inactive')
  while True:
    user_signing_certificates = iam.list_signing_certificates(UserName=user_name)
    for user_signing_certificate in user_signing_certificates['Certificates']:
      if user_signing_certificate['Status'] == 'Active':
        disable_user_signing_certificate(iam, user_name, user_signing_certificate['CertificateId'])
        action_taken = True
    if not user_signing_certificates['IsTruncated']:
      break
  return action_taken


def disable_login_profile(iam, user_name):
  try:
    login_profile = iam.get_login_profile(UserName=user_name)
    if login_profile:
      iam.delete_login_profile(UserName=user_name)
      return True
  except:
    pass


def disable_access_keys(iam, user_name, user_access_key_metadata):
  action_taken = False
  for user_access_key in user_access_key_metadata['AccessKeyMetadata']:
    if user_access_key['Status'] == 'Active':
      iam.update_access_key(UserName=user_name, AccessKeyId=user_access_key['AccessKeyId'], Status='Inactive')
      action_taken = True
  return action_taken


def delete_inline_user_policies(iam, user_name):
  action_taken = False

  def delete_inline_user_policy(iam, user_name, inline_user_policy_name):
    iam.delete_user_policy(UserName=user_name, PolicyName=inline_user_policy_name)
  while True:
    user_policies = iam.list_user_policies(UserName=user_name)
    for inline_user_policy_name in user_policies['PolicyNames']:
      delete_inline_user_policy(iam, user_name, inline_user_policy_name)
      action_taken = True
    if not user_policies['IsTruncated']:
      break
  return action_taken


def detach_managed_user_policies(iam, user_name):
  action_taken = False

  def detach_managed_user_policy(iam, user_name, policy_arn):
    iam.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
  while True:
    managed_user_policies = iam.list_attached_user_policies(UserName=user_name)
    for managed_user_policy in managed_user_policies['AttachedPolicies']:
      detach_managed_user_policy(iam, user_name, managed_user_policy['PolicyArn'])
      action_taken = True
    if not managed_user_policies['IsTruncated']:
      break
  return action_taken


def delete_user_mfa_devices(iam, user_name):
  action_taken = False

  def delete_user_mfa_device(iam, user_name, serial_number):
    iam.deactivate_mfa_device(UserName=user_name, SerialNumber=serial_number)
  while True:
    user_mfa_devices = iam.list_mfa_devices(UserName=user_name)
    for user_mfa_device in user_mfa_devices['MFADevices']:
      delete_user_mfa_device(iam, user_name, user_mfa_device['SerialNumber'])
      action_taken = True
    if not user_mfa_devices['IsTruncated']:
      break
  return action_taken


def check_if_active_and_disable_user(iam, user_name, user_access_key_metadata, account):
  changed_attributes = []
  if disable_login_profile(iam, user_name):
    changed_attributes.append('login profile')
  if disable_user_signing_certificates(iam, user_name):
    changed_attributes.append('signing certificate(s)')
  if disable_access_keys(iam, user_name, user_access_key_metadata):
    changed_attributes.append('access key(s)')
  if changed_attributes:
    message = 'account: %s - user: %s has been disabled. These attributes were disabled: %s' % (account, user_name, str(changed_attributes))
    logging.info(message)
    message_slack(message)


def delete_user_permissions_boundary(iam, user_name):
    action_taken = False
    aws_user = iam.get_user(UserName=user_name)
    if 'PermissionsBoundary' in aws_user['User']:
        iam.delete_user_permissions_boundary(UserName=user_name)
        action_taken = True
    return action_taken


def delete_aws_account(iam, user_name, account):
  changed_attributes = []
  if delete_user_ssh_keys(iam, user_name):
    changed_attributes.append('ssh key(s)')
  if delete_user_access_keys(iam, user_name):
    changed_attributes.append('access key(s)')
  if remove_user_from_all_groups(iam, user_name):
    changed_attributes.append('group attachment(s)')
  if delete_user_signing_certificates(iam, user_name):
    changed_attributes.append('signing certificate(s)')
  if delete_inline_user_policies(iam, user_name):
    changed_attributes.append('inline user policy attachment(s)')
  if detach_managed_user_policies(iam, user_name):
    changed_attributes.append('managed user policy attachment(s)')
  if delete_user_mfa_devices(iam, user_name):
    changed_attributes.append('user mfa devices')
  if delete_user_permissions_boundary(iam, user_name):
    changed_attributes.append('permissions boundary')

  iam.delete_user(UserName=user_name)
  delete_message     = 'account: %s - user: %s has been deleted after no activity for %s days.' % (account, user_name, aws_delete_grace_period)
  attributes_message = ' These attributes were deleted: %s' % str(changed_attributes)
  message            = delete_message.ljust(70, ' ') + attributes_message
  message_slack(message)
  logging.info(message)


def sync_aws_ad():
  logger.info('Looking for AWS users to delete that do not exist or are not active in AD')
  human_aws_accounts      = filter_out_aws_service_accounts(get_all_aws_users())
  active_ad_users         = get_all_active_ad_users()
  aws_users_to_be_deleted = []

  for human_aws_account in human_aws_accounts:
    # users on the whitelist will never be disabled or deleted in anyway.
    if human_aws_account['UserName'] in aws_users_whitelist:
      continue
    if human_aws_account['UserName'] not in active_ad_users:
      aws_users_to_be_deleted.append(human_aws_account)

  percent_aws_users_deleted = float(len(aws_users_to_be_deleted)) / len(human_aws_accounts)
  # raise exception if we try to delete too many users as a failsafe.
  if percent_aws_users_deleted > aws_max_delete_failsafe:
    exception_msg = 'No users were deleted. %.1f percent to be deleted is beyond the acceptable threshold: %.1f' % (percent_aws_users_deleted * 100, aws_max_delete_failsafe * 100)
    raise Exception(exception_msg)

  # After the failsafe is over, go through and disable / delete all the users
  for aws_user_to_be_deleted in aws_users_to_be_deleted:
    account                  = get_arn_account_profile_name(aws_user_to_be_deleted['Arn'])
    session                  = boto3.Session(profile_name=account)
    iam                      = session.client('iam')
    user_name                = aws_user_to_be_deleted['UserName']
    user_access_key_metadata = iam.list_access_keys(UserName=user_name)
    check_if_active_and_disable_user(iam, user_name, user_access_key_metadata, account)
    if not user_keys_active_recently(iam, user_name, user_access_key_metadata, days_since_active=int(aws_delete_grace_period)):
      delete_aws_account(iam, user_name, account)


if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
  logging.getLogger('requests').setLevel(logging.ERROR)
  logging.getLogger('botocore').setLevel(logging.ERROR)
  error_counter = 0
  while True:
    try:
      sync_aws_ad()
      error_counter = 0
    except Exception as error:
      logger.exception(error)
      # if we regularly have exceptions, let aws slack know about it once per day.
      error_counter += 1
      if error_counter % 48 == 4:
        slack_error = '```This exception is being sent to slack since it is the 4th one is a row. %s```' % error
        message_slack(slack_error)

    sleep_message = 'Sleeping for %s minutes' % str(int(aws_ad_sync_run_interval) / 60)
    logger.info(sleep_message)
    time.sleep(aws_ad_sync_run_interval)
