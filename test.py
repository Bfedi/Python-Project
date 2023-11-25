from Utils import ldap_conn,make_user




ldap_server = 'ldap://192.168.136.140:389'
ldap_user = 'cn=admin,dc=ssirn,dc=local'  # Replace with your LDAP admin user
ldap_password = 'admin'  # Replace with your LDAP admin password
base_dn = 'dc=ssirn,dc=local'
search_filter = '(objectClass=*)'



make_user(ldap_conn(ldap_server,ldap_user,ldap_password))
