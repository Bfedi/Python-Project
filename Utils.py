import hashlib

import ldap

def ldap_conn(ldap_server,ldap_user,ldap_password):
    ldap_conn = ldap.initialize(ldap_server)
    ldap_conn.simple_bind_s(ldap_user, ldap_password)
    """search_scope = ldap.SCOPE_SUBTREE
    result_id = ldap_conn.search(base_dn, search_scope, search_filter)
    result_set = []
    while True:
        result_type, result_data = ldap_conn.result(result_id, 0)
        if result_data == []:
            break
        else:
            if result_type == ldap.RES_SEARCH_ENTRY:
                result_set.append(result_data)
    for entry in result_set:
        print(entry)"""
    return ldap_conn

def make_user(ldap_conn):
    nom=input("entrer votre nom")
    prenom=input("entrer votre prenom")
    email=input("entrer votre adresse email")
    passwd=input("entrer votre password")
    passwd=hashlib.sha256(passwd.encode()).hexdigest()
    uid = nom + '.' + prenom
    new_user_dn = f"uid={uid},ou=tekup,dc=ssirn,dc=local"
    user=[
        ('objectClass', [b'top',b'Person',b'inetOrgPerson', b'posixAccount',b'organizationalPerson']),
        ('uid', [bytes(prenom+'.'+nom,encoding="ascii")]),
        ('cn', [bytes(prenom,encoding="ascii")]),
        ('sn', [bytes(nom,encoding="ascii")]),
        ('uidNumber', [b'10000']),
        ('mail', [bytes(email,encoding="ascii")]),
        ('gidNumber', [b'10000']),
        ('homeDirectory', [bytes(f"/home/{nom}.{prenom}",encoding="ascii")]),
        ('userPassword', [bytes(passwd,encoding="ascii")]),
    ]
    ldap_conn.add_s(new_user_dn, user)
    ldap_conn.unbind()









