from ldap3 import Server, Connection, AUTO_BIND_NO_TLS, SUBTREE


class CompanyDirectory(object):

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.vp_map = {}

    def get_all_ldap_users(self):

        with Connection(Server(self.config.ldap_url, port=self.config.ldap_port, use_ssl=True),
        auto_bind=AUTO_BIND_NO_TLS, read_only=True, check_names=True, user=self.config.ldap_binddn,
        password=self.config.ldap_bindpw) as c:

            total_entries = 0
            ldap_paged_search_generator = c.extend.standard.paged_search(search_base=self.config.ldap_basedn,
                     search_filter=self.config.ldap_search_filter, search_scope=SUBTREE, paged_size=5000,
                     attributes=self.config.ldap_searchreq_attrlist, get_operational_attributes=True)
            results = {}
            for entry in ldap_paged_search_generator:
                total_entries += 1
                results[entry['attributes']['sAMAccountName'].lower()] = ''
            self.logger.debug('Refreshed the ldap_users_vp_map, ldap_users_qty: %s' % len(results))
            return results
