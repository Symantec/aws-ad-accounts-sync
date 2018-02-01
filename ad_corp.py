#!/usr/bin/env python

import json
import ldap
import os
try:
  from ldap.controls.pagedresults import SimplePagedResultsControl
except ImportError:
  from ldap.controls.libldap import SimplePagedResultsControl

# 'ldaps://ad.example.com:636', make sure you always use ldaps
ad_url             = os.environ.get('AD_URL')
ad_basedn          = os.environ.get('AD_BASEDN')
ad_binddn          = os.environ.get('AD_BINDDN')
ad_bindpw          = os.environ.get('AD_BINDPW')

# note: make sure you only search the directory for active employees. This step is critical to the sync process.
search_flt         = os.environ.get('AD_SEARCH_FILTER_FOR_ACTIVE_EMPLOYEES_ONLY')
page_size          = 5000
trace_level        = 0
ad_uid_attribute   = os.environ.get('AD_UID_ATTRIBUTE', 'uid')
# '["uid", "active_employee_attribute"]'
searchreq_attrlist = json.loads(os.environ.get('AD_SEARCHREQ_ATTRLIST'))


# Note this ldap code is a bit more complicated than it could be because our AD
# instance has more than 10k records we're querying for. The AD server has a 10k
# query limit. So we're using pagination on the client side to get around this.

def get_all_active_ad_users():
  l = ldap.initialize(ad_url, trace_level=trace_level)
  l.set_option(ldap.OPT_REFERRALS, 0)
  l.set_option(ldap.OPT_X_TLS_DEMAND, True)
  l.protocol_version = 3
  l.simple_bind_s(ad_binddn, ad_bindpw)

  req_ctrl              = SimplePagedResultsControl(True,size=page_size,cookie='')
  known_ldap_resp_ctrls = {SimplePagedResultsControl.controlType:SimplePagedResultsControl}
  attrlist              = [s.encode('utf-8') for s in searchreq_attrlist]
  msgid                 = l.search_ext(ad_basedn, ldap.SCOPE_SUBTREE, search_flt, attrlist=attrlist, serverctrls=[req_ctrl])
  all_ad_users          = {}
  pages                 = 0

  while True:
    pages += 1
    rtype, rdata, rmsgid, serverctrls = l.result3(msgid,resp_ctrl_classes=known_ldap_resp_ctrls)
    for entry in rdata:
      all_ad_users[entry[1][ad_uid_attribute][0].lower()] = ''
    pctrls = [
      c
      for c in serverctrls
      if c.controlType == SimplePagedResultsControl.controlType
    ]
    if pctrls:
      if pctrls[0].cookie:
        # Copy cookie from response control to request control
        req_ctrl.cookie = pctrls[0].cookie
        msgid = l.search_ext(ad_basedn, ldap.SCOPE_SUBTREE, search_flt, attrlist=attrlist, serverctrls=[req_ctrl])
      else:
        break
    else:
      raise Exception("AD query Warning: Server ignores RFC 2696 control.")
      break
  l.unbind_s()
  return all_ad_users
