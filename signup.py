from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException, LDAPBindError
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
import ldap
import ldap.modlist as modlist

""""""


#Cette fonction permet la connection a un serveur ldap
def connect_ldap_server():
    try:
        server_uri = f"ldap://LDAP-SERVER:389"
        server = Server(server_uri, get_info=ALL)
        connection = Connection(server,
                                user='cn=admin,dc=ssirn,dc=local',
                                password='admin')
        bind_response = connection.bind()
        return connection

    except LDAPBindError as e:
        connection = e

#Cette fonction permet de consulté l'annuaire ldap
def get_ldap_users():
    search_base = 'dc=ssirn,dc=local'
    search_filter = '(uidNumber=*)'
    ldap_conn = connect_ldap_server()
    try:
        ldap_conn.search(search_base=search_base,
                         search_filter=search_filter,
                         search_scope=SUBTREE,
                         attributes=['cn', 'sn', 'uid', 'uidNumber','dc'])


        results = ldap_conn.entries
        print(results)
    except LDAPException as e:
        results = e

""" Create a new group """
#Creation de Groupe
def add_ldap_group(Gname,Gid):

    ldap_attr = {}

    ldap_attr['objectClass'] = ['top', 'posixGroup']
    ldap_attr['gidNumber'] = Gid

    # Connection Au serveur
    ldap_conn = connect_ldap_server()

    try:
        # Ajout du Gname au liste de Groupe
        response = ldap_conn.add(f'cn={Gname},ou=Group,dc=ssirn,dc=local',
                                  attributes=ldap_attr)

    except LDAPException as e:
        response = (" The error is ", e)
    ldap_conn.unbind()
    return response


""" add method takes a user_dn, objectclass and attributes as    dictionary  """


def add_new_user_to_group():
    # sample attributes
    ldap_attr = {}
    ldap_attr['cn'] = "Fedi"
    ldap_attr['sn'] = "Brichni"

    # Connection
    ldap_conn = connect_ldap_server()

    # this will create testuser inside group1
    user_dn = "cn=Fedi,cn=ssirn,dc=ssirn,dc=local"

    try:
        # object class for a user is inetOrgPerson
        response = ldap_conn.add(dn=user_dn,
                                 object_class='inetOrgPerson',
                                 attributes=ldap_attr)
    except LDAPException as e:
        response = e
    return response


""" The delete method is used to delete an entry from ldap
     The user/group dn is required to delete an entry"""


def delete_user():
    ldap_conn = connect_ldap_server()
    # Provide the dn of the user to be deleted
    try:

        response = ldap_conn.delete(dn='cn=testuser,cn=group1,dc = testldap, dc = com')
    except LDAPException as e:
        response = e
    return response

# import class and constants

def update_user():
    # define the server
    s = Server('servername', get_info=ALL)  # define an unsecure LDAP server, requesting info on DSE and schema

    # define the connection
    c = Connection(s, user='user_dn', password='user_password')
    c.bind()

    # perform the Modify operation
    c.modify('cn=user1,ou=users,o=company',
         {'givenName': [(MODIFY_REPLACE, ['givenname-1-replaced'])],
          'sn': [(MODIFY_REPLACE, ['sn-replaced'])]})
    print(c.result)

    # close the connection
    c.unbind()


def add_existing_user_to_ldapgroup():

    # all attributes are required to add existing users
    ldap_attr = {}
    ldap_attr['uid'] = b'tuser'
    ldap_attr['cn'] = b'Test User'
    ldap_attr['uidNumber'] = b'1001'
    ldap_attr['gidNumber'] = b'2001'
    ldap_attr['objectClass'] =  [b'top', b'inetOrgPerson',
                                 b'posixAccount']
    ldap_attr['sn'] = b'User'
    ldap_attr['homeDirectory'] = b'/home/users/tuser'

    conn = ldap.initialize('server_uri', bytes_mode=False)
    conn.simple_bind_s("cn=admin,dc=testldap,dc=com", "12345")
    dn_new = "cn=Test user,cn=group1,dc=testldap,dc=com"
    ldif = modlist.addModlist(ldap_attr)
    try:
        response = conn.add_s(dn_new, ldif)
    except ldap.error as e:
        response = e
    finally:
        conn.unbind()
    return response
