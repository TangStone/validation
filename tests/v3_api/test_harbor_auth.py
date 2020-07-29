import pytest
from .entfunc import *

CATTLE_HARBOR_CONFIG_URL = (CATTLE_API_URL + '/users?action=saveharborconfig').replace('//v3','/v3')
CATTLE_HARBOR_SERVER_URL = (CATTLE_API_URL + '/settings/harbor-server-url').replace('//v3','/v3')
CATTLE_HARBOR_ADMIN_AUTH = (CATTLE_API_URL + '/settings/harbor-admin-auth').replace('//v3','/v3')
CATTLE_HARBOR_AUTH_MODE = (CATTLE_API_URL + '/settings/harbor-auth-mode').replace('//v3','/v3')

RANCHER_HARBOR_URL = os.environ.get('RANCHER_HARBOR_URL', 'https://harbor.tangstone.store')
RANCHER_HARBOR_ADMIN = os.environ.get('RANCHER_HARBOR_ADMIN', 'admin')
RANCHER_HARBOR_ADMIN_PASSWORD = os.environ.get('RANCHER_HARBOR_ADMIN_PASSWORD', 'Rancher@123456')

RANCHER_HARBOR2_URL = os.environ.get('RANCHER_HARBOR2_URL', 'https://harbor2.tangstone.store')
RANCHER_HARBOR2_ADMIN = os.environ.get('RANCHER_HARBOR2_ADMIN', 'admin')
RANCHER_HARBOR2_ADMIN_PASSWORD = os.environ.get('RANCHER_HARBOR2_ADMIN_PASSWORD', 'Rancher@123456')

RANCHER_HARBOR_LDAP_URL = os.environ.get('RANCHER_HARBOR_LDAP_URL', 'https://harborldap1.tangstone.store')
RANCHER_HARBOR_LDAP_ADMIN = os.environ.get('RANCHER_HARBOR_LDAP_ADMIN', 'admin')
RANCHER_HARBOR_LDAP_ADMIN_PASSWORD = os.environ.get('RANCHER_HARBOR_LDAP_ADMIN_PASSWORD', 'Rancher@123456')


RANCHER_HARBOR2_LDAP_URL = os.environ.get('RANCHER_HARBOR2_LDAP_URL', 'https://harborldap2.tangstone.store')
RANCHER_HARBOR2_LDAP_ADMIN = os.environ.get('RANCHER_HARBOR2_LDAP_ADMIN', 'admin')
RANCHER_HARBOR2_LDAP_ADMIN_PASSWORD = os.environ.get('RANCHER_HARBOR2_LDAP_ADMIN_PASSWORD', 'Rancher@123456')

RANCHER_HARBOR_AD_URL = os.environ.get('RANCHER_HARBOR_AD_URL', 'https://harborad1.tangstone.store')
RANCHER_HARBOR_AD_ADMIN = os.environ.get('RANCHER_HARBOR_AD_ADMIN', 'admin')
RANCHER_HARBOR_AD_ADMIN_PASSWORD = os.environ.get('RANCHER_HARBOR_AD_ADMIN_PASSWORD', 'Rancher@123456')

RANCHER_HARBOR2_AD_URL = os.environ.get('RANCHER_HARBOR2_AD_URL', 'https://harborad2.tangstone.store')
RANCHER_HARBOR2_AD_ADMIN = os.environ.get('RANCHER_HARBOR2_AD_ADMIN', 'admin')
RANCHER_HARBOR2_AD_ADMIN_PASSWORD = os.environ.get('RANCHER_HARBOR2_AD_ADMIN_PASSWORD', 'Rancher@123456')

#ANCHER_GENERAL_USER_TOKEN = os.environ.get('ANCHER_GENERAL_USER_TOKEN', "")

# AD info
RANCHER_AD_SERVER = os.environ.get('RANCHER_AD_SERVER', "54.206.106.116")
RANCHER_AD_ADMIN_USERNAME = os.environ.get('RANCHER_AD_ADMIN_USERNAME', "dinglu")
RANCHER_AD_ADMIN_PASSWORD = os.environ.get('RANCHER_AD_ADMIN_USERNAME', "Rancher@123")
RANCHER_AD_GENERAL_USERNAME = os.environ.get('RANCHER_AD_GENERAL_USERNAME', "tanglei")
RANCHER_AD_GENERAL_PASSWORD = os.environ.get('RANCHER_AD_GENERAL_PASSWORD', "Rancher@123")

# LDAP info
RANCHER_LDAP_SERVER = os.environ.get('RANCHER_AD_SERVER', "ldap.wujing.site")
RANCHER_LDAP_ADMIN_USERNAME = os.environ.get('RANCHER_AD_ADMIN_USERNAME', "wujing")
RANCHER_LDAP_ADMIN_PASSWORD = os.environ.get('RANCHER_AD_ADMIN_USERNAME', "Rancher@123")
RANCHER_LDAP_GENERAL_USERNAME = os.environ.get('RANCHER_LDAP_GENERAL_USERNAME', 'tanglei')
RANCHER_LDAP_GENERAL_PASSWORD = os.environ.get('RANCHER_LDAP_GENERAL_PASSWORD', 'Rancher@123')

harborcredential = pytest.mark.skipif(not RANCHER_HARBOR_URL and not RANCHER_HARBOR2_URL and not  RANCHER_HARBOR_LDAP_URL and not RANCHER_HARBOR2_LDAP_URL,
                                   reason='HARBOR URL Credentials not provided, '
                                          'cannot set harbor')
harborpwdcredential = pytest.mark.skipif(not RANCHER_HARBOR_ADMIN_PASSWORD and not RANCHER_HARBOR2_ADMIN_PASSWORD and not  RANCHER_HARBOR_LDAP_ADMIN_PASSWORD,
                                   reason='HARBOR Password Credentials not provided, '
                                          'cannot set harbor')


i = os.environ.get("RRNCHER_HARBOR_HOST",0)
namespace = {}
register_name = []
token = {}

params = [
    # {"password":RANCHER_HARBOR_ADMIN_PASSWORD,"serverURL":RANCHER_HARBOR_URL,"version":"","option":"harborV1","authType":"LDAP"}, # harbor v1
     {"password":RANCHER_HARBOR2_ADMIN_PASSWORD,"serverURL":RANCHER_HARBOR2_URL,"version":"v2.0","option":"harborV2","authType":"LDAP"}, # harbor v2
     {"password":RANCHER_HARBOR_LDAP_ADMIN_PASSWORD,"serverURL":RANCHER_HARBOR_LDAP_URL,"version":"","option":"harborLdapV1","authType":"LDAP"}, # LDAP harbor v1
     {"password":RANCHER_HARBOR2_LDAP_ADMIN_PASSWORD,"serverURL":RANCHER_HARBOR2_LDAP_URL,"version":"v2.0","option":"harborLdapV2","authType":"LDAP"},# LDAP harbor v2
    # {"password":RANCHER_HARBOR_ADMIN_PASSWORD,"serverURL":RANCHER_HARBOR_URL,"version":"","option":"harborV1","authType":"AD"}, # harbor v1
     {"password":RANCHER_HARBOR2_ADMIN_PASSWORD,"serverURL":RANCHER_HARBOR2_URL,"version":"v2.0","option":"harborV2","authType":"AD"}, # harbor v2
     {"password":RANCHER_HARBOR_AD_ADMIN_PASSWORD,"serverURL":RANCHER_HARBOR_AD_URL,"version":"","option":"harborAdV1","authType":"AD"}, # LDAP harbor v1
     {"password":RANCHER_HARBOR2_AD_ADMIN_PASSWORD,"serverURL":RANCHER_HARBOR2_AD_URL,"version":"v2.0","option":"harborAdV2","authType":"AD"} # LDAP harbor v2
]

def print_object(obj):
    print('\n'.join(['%s:%s' % item for item in obj.__dict__.items()]))


# to do
def update_syncharboruser(config_json,headers):
    re = requests.post("https://ha.tangstone.store/v3/users?action=syncharboruser",json=config_json,verify=False, headers=headers)
    assert re.status_code in {200, 201}



def get_harbor_systeminfo(harborUrl,harborVersion):
    headers = {"cookie": "R_SESS=" + token["auth_admin_user"],"X-API-Harbor-Admin-Header": "true"}
    reUrl = CATTLE_TEST_URL + "/meta/harbor/" + harborUrl.replace('//', '/') + "/api/systeminfo"
    if harborVersion == "v2.0":
        reUrl = CATTLE_TEST_URL + "/meta/harbor/" + harborUrl.replace('//','/') + "/api/v2.0/systeminfo"
    re = requests.get(reUrl, verify=False, headers=headers)
    harborSystemInfo = json.loads(re.text)
    return harborSystemInfo


# 添加认证
def test_add_auth():
    if "AD" == params[i]["authType"]:
        re = add_ad_auth()
    elif "LDAP" == params[i]["authType"]:
        re = add_ldad_auth()
    assert re.status_code == 200


# 获取认证系统的管理员用户的token
def test_get_admin_token():
    if "AD" == params[i]["authType"]:
        username = RANCHER_AD_ADMIN_USERNAME
        password = RANCHER_AD_ADMIN_PASSWORD
        reUrl = "https://ha.tangstone.store/v3-public/activeDirectoryProviders/activedirectory?action=login"
    elif "LDAP" == params[i]["authType"]:
        username = RANCHER_LDAP_ADMIN_USERNAME
        password = RANCHER_LDAP_ADMIN_PASSWORD
        reUrl = "https://ha.tangstone.store/v3-public/openLdapProviders/openldap?action=login"
    token["auth_admin_user"] = get_auth_token(username, password,reUrl)

# 获取ad的普通用户的token
def test_get_general_token():
    if "AD" == params[i]["authType"]:
        username = RANCHER_AD_GENERAL_USERNAME
        password = RANCHER_AD_GENERAL_PASSWORD
        reUrl = "https://ha.tangstone.store/v3-public/activeDirectoryProviders/activedirectory?action=login"
    elif "LDAP" == params[i]["authType"]:
        username = RANCHER_LDAP_GENERAL_USERNAME
        password = RANCHER_LDAP_GENERAL_PASSWORD
        reUrl = "https://ha.tangstone.store/v3-public/openLdapProviders/openldap?action=login"
    token["auth_general_user"] = get_auth_token(username, password,reUrl)

# 添加ad的普通用户到k8s集群
def test_add_auth_generaluser_cluster():
    re = add_auth_generaluser_cluster()
    assert re.status_code in {200,201}

# 创建项目
def test_create_project_client():
    create_project_client()

# 设置harbor配置
@harborcredential
@harborpwdcredential
def test_set_http_harborconfig():
    set_http_harborconfig()

# 普通用户Harbor账号同步
@harborcredential
@harborpwdcredential
def test_harbor_accout_sync():
    if params[i]["option"] in ["harborV1","harborV2"]:
        authType = "local"
    elif params[i]["option"] in ["harborLdapV1","harborLdapV2"]:
        authType = "openldap"
    elif params[i]["option"] in ["harborAdV1","harborAdV2"]:
        authType = "activedirectory"

    harbor_accout_sync(authType)

# admin用户修改密码
@harborcredential
@harborpwdcredential
def test_admin_user_change_password():
    newPassword = "Rancher@1234"
    oldPassword = RANCHER_HARBOR_ADMIN_PASSWORD
    if params[i]["option"] in ["harborLdapV1","harborLdapV2","harborAdV1","harborAdV2"]:
        pytest.skip("harborLdapV1 or harborLdapV2 or harborAdV1 or harborAdV2 does not run")
    else:
        admin_user_change_password(newPassword,oldPassword)
        admin_user_change_password(oldPassword, newPassword)

# 普通用户修改密码
@harborcredential
@harborpwdcredential
def test_general_user_change_password():
    if params[i]["option"] in ["harborLdapV1","harborLdapV2","harborAdV1","harborAdV2"]:
        commond_credential_general_user_change_password()
    else:
        general_user_change_password()

# 添加用户到私用项目
def test_add_member_to_private_repo():
    add_member_to_private_repo()

# 验证普通用户harbor镜像凭证
@harborcredential
def test_private_image_with_dockercredential():
    private_image_with_dockercredential()

# 验证admin用户跟新harbor镜像凭证
def test_admin_private_image_with_update_dockercredential():
    if params[i]["option"] in ["harborLdapV1", "harborLdapV2", "harborAdV1", "harborAdV2"]:
        pytest.skip("harborLdapV1 or harborLdapV2 or harborAdV1 or harborAdV2 does not run")

    admin_p_client = namespace["admin_p_client"]
    users = namespace["users"]
    for user in users:
        if user.name == "Default Admin":
            admin_user = user
    admin_ns = namespace["admin_ns"]
    harborPwd = RANCHER_HARBOR_ADMIN_PASSWORD
    private_image_with_update_dockercredential(admin_p_client,admin_user,admin_ns,harborPwd)


# 验证普通用户跟新harbor镜像凭证
def test_private_image_with_update_dockercredential():
    if params[i]["option"] in ["harborLdapV1", "harborLdapV2", "harborAdV1", "harborAdV2"]:
        pytest.skip("harborLdapV1 or harborLdapV2 or harborAdV1 or harborAdV2 does not run")

    general_p_client = namespace["general_p_client"]
    general_user = namespace["general_user"]
    general_ns = namespace["general_ns"]
    harborPwd = RANCHER_LDAP_GENERAL_PASSWORD
    private_image_with_update_dockercredential(general_p_client,general_user,general_ns,harborPwd)

# 删除harbor私用项目下同步的用户
def test_delete_harbor_project_member():
    delete_harbor_project_member(RANCHER_LDAP_GENERAL_USERNAME)

# 移除rancher同步的成员
def test_delete_harbor_member():
    if params[i]["option"] in ["harborLdapV1","harborLdapV2","harborAdV1","harborAdV2"]:
        pytest.skip("harborLdapV1 or harborLdapV2 or harborAdV1 or harborAdV2 does not run")
    delete_harbor_member(RANCHER_LDAP_GENERAL_USERNAME)

# 移除harbor配置
def test_remove_harborconfig():
    remove_harborconfig()



# 删除项目
def test_delete_project_client():
    general_client = get_admin_client_byToken(url=CATTLE_API_URL, token=token["auth_general_user"])
    admin_client = get_admin_client_byToken(url=CATTLE_API_URL, token=token["auth_admin_user"])
    time.sleep(30)
    general_client.delete(namespace["general_p"])
    admin_client.delete(namespace["admin_p"])

# 移除认证
def test_remove_auth():
    if "AD" == params[i]["authType"]:
        re = remove_ad_auth()
    elif "LDAP" == params[i]["authType"]:
        re = remove_ldad_auth()
    assert re.status_code == 200

def test_print():
    global i
    i += 1

def get_client_byToken(url,token):
    return rancher.Client(url=url, token=token, verify=False)

def add_ad_auth():
    var = {
        "activeDirectoryConfig":{
            "baseType":"authConfig",
            "connectionTimeout":5000,
            "creatorId":None,
            "enabled":False,
            "groupDNAttribute":"distinguishedName",
            "groupMemberMappingAttribute":"member",
            "groupMemberUserAttribute":"distinguishedName",
            "groupNameAttribute":"name",
            "groupObjectClass":"group",
            "groupSearchAttribute":"sAMAccountName",
            "groupUniqueIdAttribute":"objectGUID",
            "id":"activedirectory",
            "labels":{
                "cattle.io/creator":"norman"
            },
            "name":"activedirectory",
            "nestedGroupMembershipEnabled":False,
            "port":389,
            "tls":False,
            "type":"activeDirectoryConfig",
            "userDisabledBitMask":2,
            "userEnabledAttribute":"userAccountControl",
            "userLoginAttribute":"sAMAccountName",
            "userNameAttribute":"name",
            "userObjectClass":"person",
            "userSearchAttribute":"sAMAccountName|sn|givenName",
            "userUniqueIdAttribute":"objectGUID",
            "servers":[
                RANCHER_AD_SERVER
            ],
            "serviceAccountUsername":"dinglu",
            "serviceAccountPassword":"Rancher@123",
            "defaultLoginDomain":"wujing",
            "userSearchBase":"OU=rancher,DC=wujing,DC=site",
            "accessMode":"unrestricted"
        },
        "enabled":True,
        "username":"dinglu",
        "password":"Rancher@123"
    }
    headers = {"cookie": "R_SESS=" + ADMIN_TOKEN, "X-API-Harbor-Admin-Header": "true"}
    reUrl = "https://ha.tangstone.store/v3/activeDirectoryConfigs/activedirectory?action=testAndApply"
    re = requests.post(reUrl, json=var, verify=False, headers=headers)
    return re

def add_ldad_auth():
    var = {
        "ldapConfig":{
            "actionLinks":{
                "testAndApply":"https://ha.tangstone.store/v3/openLdapConfigs/openldap?action=testAndApply"
            },
            "baseType":"authConfig",
            "connectionTimeout":5000,
            "created":"2020-12-14T06:06:01Z",
            "createdTS":1607925961000,
            "creatorId":None,
            "enabled":True,
            "groupDNAttribute":"entryDN",
            "groupMemberMappingAttribute":"member",
            "groupMemberUserAttribute":"entryDN",
            "groupNameAttribute":"cn",
            "groupObjectClass":"groupOfNames",
            "groupSearchAttribute":"cn",
            "groupUniqueIdAttribute":"entryUUID",
            "id":"openldap",
            "labels":{
                "cattle.io/creator":"norman"
            },
            "links":{
                "self":"https://ha.tangstone.store/v3/openLdapConfigs/openldap",
                "update":"https://ha.tangstone.store/v3/openLdapConfigs/openldap"
            },
            "name":"openldap",
            "nestedGroupMembershipEnabled":False,
            "port":636,
            "tls":True,
            "type":"openLdapConfig",
            "userDisabledBitMask":0,
            "userLoginAttribute":"uid",
            "userMemberAttribute":"memberOf",
            "userNameAttribute":"cn",
            "userObjectClass":"inetOrgPerson",
            "userSearchAttribute":"uid|sn|givenName",
            "userUniqueIdAttribute":"entryUUID",
            "uuid":"f5d33625-e554-4a18-92ce-43eb183d2b05",
            "servers":[
                RANCHER_LDAP_SERVER
            ],
            "certificate":"-----BEGIN CERTIFICATE-----\nMIIEBTCCAu2gAwIBAgIUKsY4BcPbnme8rQ5FQNnv1AjQgc0wDQYJKoZIhvcNAQEL\nBQAwgZExCzAJBgNVBAYTAkNOMREwDwYDVQQIDAhsaWFvbmluZzERMA8GA1UEBwwI\nc2hlbnlhbmcxEDAOBgNVBAoMB1JhbmNoZXIxCzAJBgNVBAsMAnN5MRkwFwYDVQQD\nDBBsZGFwLnd1amluZy5zaXRlMSIwIAYJKoZIhvcNAQkBFhMxODg0NTU5OTY0M0Ax\nNjMuY29tMB4XDTIwMTAxMjAyMjY0N1oXDTIzMDgwMjAyMjY0N1owgZExCzAJBgNV\nBAYTAkNOMREwDwYDVQQIDAhsaWFvbmluZzERMA8GA1UEBwwIc2hlbnlhbmcxEDAO\nBgNVBAoMB1JhbmNoZXIxCzAJBgNVBAsMAnN5MRkwFwYDVQQDDBBsZGFwLnd1amlu\nZy5zaXRlMSIwIAYJKoZIhvcNAQkBFhMxODg0NTU5OTY0M0AxNjMuY29tMIIBIjAN\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm7p/kJDgGXuzeh9th4KgLJzlxOsU\nunTHnr5suYGLGHNmsgQ+3B534D5ynARwnHlW/kRkuPegNQTwAc+LzDlnkRJ77TWx\nP4ag3N0MYAQfDzGiDZ6fIOG9EEmDa94yWB0doAgvmBdGihRueCvS9wLi7cET8cZw\nEu7LzA78CZnE6tyRFsHda6gCmPDHwx7oEs51zzpGj3YaO1VRVaTunbUtDRqFnDPX\nf1kUGbVk7N90aSmi/KyZ9xbuLlGMJPe7g6rcrI85q+R3tBuUv1fiz8AJfxke0cfW\nGoXoBb0ptq/8aLthk0X7MNY3i78dmdsKw9KfZ+tGKB5SjJvEIVi/0ezE2wIDAQAB\no1MwUTAdBgNVHQ4EFgQUE0/f4M1s+GDNK4nMWShmNHLN7X4wHwYDVR0jBBgwFoAU\nE0/f4M1s+GDNK4nMWShmNHLN7X4wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B\nAQsFAAOCAQEAIgSzWRiDt9dB7+9o1b8zxvXJqpGlbXdYBb6yiH8hmM+Z9xWuwLYe\nZNTJzRRNSEVRCRK64nnrTLoVqZyLEB2A/hn6zgGJkyEwD0o0GKbm55j5QyXDVb/h\nAnvxbDB06tx9auinZfG2XeVFvuzmntxPawBke17d4W8W0xsRXS1Rwu7VSTcZs9Zq\npqFl1O/rXYXXwQYv+8KsYOeTr5lR52cqedt8uDPZX5Xz5RbgL165+gjgqQIPsTE/\noBhuocZl77fCR/mzpRlvAOchaQ0NjarkthRQocwYfLVhTCtsp8f4egjGuHVrZgHD\n7rLmFP+kEnnP76Phn6RWDbnylf31OTzR0w==\n-----END CERTIFICATE-----",
            "serviceAccountDistinguishedName":"cn=admin,dc=wujing,dc=site",
            "serviceAccountPassword":"Rancher@123",
            "userSearchBase":"ou=rancher,dc=wujing,dc=site",
            "accessMode":"unrestricted"
        },
        "enabled":True,
        "username":"wujing",
        "password":"Rancher@123"
    }
    headers = {"cookie": "R_SESS=" + ADMIN_TOKEN, "X-API-Harbor-Admin-Header": "true"}
    reUrl = "https://ha.tangstone.store/v3/openLdapConfigs/openldap?action=testAndApply"
    re = requests.post(reUrl, json=var, verify=False, headers=headers)
    return re




def remove_ad_auth():
    headers = {"cookie": "R_SESS=" + ADMIN_TOKEN, "X-API-Harbor-Admin-Header": "true"}
    reUrl = "https://ha.tangstone.store/v3/activeDirectoryConfigs/activedirectory?action=disable"
    re = requests.post(reUrl, json={"active":"disable"}, verify=False, headers=headers)
    return re

def remove_ldad_auth():
    headers = {"cookie": "R_SESS=" + ADMIN_TOKEN, "X-API-Harbor-Admin-Header": "true"}
    reUrl = "https://ha.tangstone.store/v3/openLdapConfigs/openldap?action=disable"
    re = requests.post(reUrl, json={"active":"disable"}, verify=False, headers=headers)
    return re


def get_auth_token(username,password,reUrl):
    headers = {"cookie": "R_SESS=" + ADMIN_TOKEN, "X-API-Harbor-Admin-Header": "true"}
    var = {
        "username": username,
        "password": password,
        "description": "UI Session",
        "responseType": "cookie",
        "ttl": 57600000,
        "labels": {
            "ui-session": "true"
        }
    }
    re = requests.post(reUrl, json=var, verify=False, headers=headers)
    token = re.headers["set-cookie"].replace("; Path=/; HttpOnly; Secure", "").replace("R_SESS=","")
    assert re.status_code == 200
    return token

def create_project_client():
    client = get_client_byToken(url=CATTLE_API_URL, token=token["auth_admin_user"])
    if CLUSTER_NAME == "":
        clusters = client.list_cluster().data
    else:
        clusters = client.list_cluster(name=CLUSTER_NAME).data
    assert len(clusters) > 0
    cluster = clusters[0]
    users = client.list_user()

    admin_p, admin_ns = create_project_and_ns(
        token["auth_admin_user"], cluster, random_test_name("testharbor"))
    admin_p_client = get_project_client_for_token(admin_p, token["auth_admin_user"])

    general_p, general_ns = create_project_and_ns(
        token["auth_general_user"] , cluster, random_test_name("testharbor"))
    general_p_client = get_project_client_for_token(general_p, token["auth_general_user"] )

    general_client = get_client_byToken(url=CATTLE_API_URL, token=token["auth_general_user"] )
    general_user = general_client.list_user().data[0]
    namespace["client"] = client
    namespace["cluster"] = cluster
    namespace["users"] = users
    namespace["general_client"] = general_client
    namespace["general_user"] = general_user
    namespace["general_p"] = general_p
    namespace["general_ns"] = general_ns
    namespace["general_p_client"] = general_p_client
    namespace["admin_p"] = admin_p
    namespace["admin_ns"] = admin_ns
    namespace["admin_p_client"] = admin_p_client

def set_http_harborconfig():
    client = namespace["client"]
    # 把harbor domain添加到白名单
    whitelist = client.by_id_setting(id="whitelist-domain", name="whitelist-domain")
    whitelistValue = whitelist["value"] + "," + params[i]["serverURL"].replace('https://', '')
    client.update_by_id_setting(id="whitelist-domain", name="whitelist-domain",value=whitelistValue)

    user = namespace["users"]
    auth_mode = get_harbor_systeminfo(params[i]["serverURL"],params[i]["version"])["auth_mode"]
    re = client.action(user, action_name="saveharborconfig", password=params[i]["password"],
                       serverURL=params[i]["serverURL"], username=RANCHER_HARBOR_ADMIN, version=params[i]["version"])

    client.update_by_id_setting(id="harbor-server-url", name="harbor-server-url", value=params[i]["serverURL"])
    client.update_by_id_setting(id="harbor-admin-auth", name="harbor-admin-auth", value=RANCHER_HARBOR_ADMIN)
    client.update_by_id_setting(id="harbor-version", name="harbor-version", value=params[i]["version"])
    client.update_by_id_setting(id="harbor-auth-mode", name="harbor-auth-mode", value=auth_mode)
    # 校验
    headers = {"cookie": "R_SESS=" + token["auth_admin_user"],"X-API-Harbor-Admin-Header": "true"}
    re = get_haroborConfig(headers,params[i]["serverURL"],params[i]["version"])
    assert RANCHER_HARBOR_ADMIN in re.text


def add_auth_generaluser_cluster():
    # 获取 userPrincipalId 和 clusters
    generalUserAdToken = token["auth_general_user"]
    client = rancher.Client(url=CATTLE_API_URL, token=generalUserAdToken, verify=False)
    userPrincipalId = client.list_principal().data[0]["id"]

    adAdminUserToken = token["auth_admin_user"]
    client = rancher.Client(url=CATTLE_API_URL, token=adAdminUserToken, verify=False)
    clusters_k8s_id = client.list_cluster(name="k8s").data[0].id

    var = {
        "type": "clusterRoleTemplateBinding",
        "clusterId": clusters_k8s_id,
        "userPrincipalId": userPrincipalId,
        "roleTemplateId": "cluster-owner"
    }
    print("clusterId", clusters_k8s_id)
    print("userPrincipalId", userPrincipalId)
    headers = {"cookie": "R_SESS=" + adAdminUserToken, "X-API-Harbor-Admin-Header": "true"}
    reUrl = "https://ha.tangstone.store/v3/clusterroletemplatebinding"
    re = requests.post(reUrl, json=var, verify=False, headers=headers)
    return re

def harbor_accout_sync(authType):
    # general user create auth
    headers = {"cookie": "R_SESS=" + token["auth_general_user"]}
    config_json = {"username": RANCHER_LDAP_GENERAL_USERNAME,
                   "password": RANCHER_LDAP_GENERAL_PASSWORD,
                   "provider": authType}
    update_syncharboruser(config_json,headers)
    # 普通用户Harbor账号同步
    general_client = namespace["general_client"]
    general_user = namespace["general_user"]
    if params[i]["option"] in ["harborLdapV1","harborLdapV2","harborAdV1","harborAdV2"]:
        general_client.action(general_user, action_name="setharborauth")
    else:
        email = "tanglei@163.com"
        general_client.action(general_user,action_name="setharborauth",email=email)
    # 校验
    headers = {"cookie": "R_SESS=" + token["auth_general_user"]}
    re = get_haroborConfig(headers,params[i]["serverURL"],params[i]["version"])
    assert RANCHER_LDAP_GENERAL_USERNAME in re.text

def get_harbor_members_info_url_and_headers():
    headers = {"cookie": "R_SESS=" + token["auth_admin_user"], "X-API-Harbor-Admin-Header": "true"}
    reUrl = CATTLE_TEST_URL + "/meta/harbor/" + RANCHER_HARBOR_URL.replace('//', '/') + "/api/users"
    if params[i]["version"] == "v2.0":
        reUrl = CATTLE_TEST_URL + "/meta/harbor/" + RANCHER_HARBOR2_URL.replace('//','/') + "/api/v2.0/users"
    return reUrl, headers

def get_harbor_members():
    reUrl, headers = get_harbor_members_info_url_and_headers()
    re = requests.get(reUrl, verify=False,
                      headers=headers)
    assert re.status_code == 200, "得到harbor的成员"
    memberList = json.loads(re.text)
    return memberList

def delete_harbor_member(memberName):
    memberList = get_harbor_members()
    for member in memberList:
        if memberName == member["username"]:
            Url,headers = get_harbor_members_info_url_and_headers()
            deleteUrl = Url + "/" + str(member["user_id"])
            print("delete url ",deleteUrl)
            re = requests.delete(deleteUrl,verify=False,
                       headers=headers)
            assert re.status_code in {200, 201}, "判断harbor删除指定成员"
            return
    print("harbor不存在删除成员")
    return

def get_haroborConfig(headers,harbor_url,api_version):
    reUrl = CATTLE_TEST_URL + "/meta/harbor/" + harbor_url.replace('//', '/') + "/api/users/current"
    if api_version == "v2.0":
        reUrl = CATTLE_TEST_URL + "/meta/harbor/" + harbor_url.replace('//', '/') + "/api/v2.0/users/current"
    re = requests.get(reUrl, verify=False, headers=headers)
    return re

def admin_user_change_password(newPassword,oldPassword):
    headers = {"cookie": "R_SESS=" + token["auth_admin_user"], "X-API-Harbor-Admin-Header": "true"}
    users = namespace["users"]
    for user in users:
        if user.name == "Default Admin":
            admin_user = user
    reUrl = admin_user.actions["updateharborauth"]
    config_json = {"newPassword":newPassword,"oldPassword":oldPassword}
    re =  requests.post(reUrl,json=config_json,verify=False, headers=headers)
    assert re.status_code == 200


def general_user_change_password():
    client = namespace["general_client"]
    user = namespace["general_user"]
    change_harbor_password(client,user,"Rancher@1234",RANCHER_LDAP_GENERAL_PASSWORD)
    # 校验
    headers = {"cookie": "R_SESS=" + token["auth_general_user"]}
    re = get_haroborConfig(headers,params[i]["serverURL"],params[i]["version"])
    assert RANCHER_LDAP_GENERAL_USERNAME in re.text
    # 修改回原密码
    change_harbor_password(client,user,RANCHER_LDAP_GENERAL_PASSWORD,"Rancher@1234")
    re = get_haroborConfig(headers,params[i]["serverURL"],params[i]["version"])
    assert RANCHER_LDAP_GENERAL_USERNAME in re.text

def commond_credential_general_user_change_password():
    client = namespace["general_client"]
    user = namespace["general_user"]
    with pytest.raises(rancher.ApiError,match=".*Unsupport change password.*") as excifo:
        change_harbor_password(client,user,"Rancher@1234",RANCHER_LDAP_GENERAL_PASSWORD)


def change_harbor_password(client,user,newPassword,oldPassword):
    re = client.action(user, action_name="updateharborauth", newPassword=newPassword,
                  oldPassword=oldPassword)



def get_harbor_host(harborUrl):
    if "https" in harborUrl:
        harborHost = harborUrl.replace("https://","http://")

    harborHost = harborHost.replace("http://","")
    return harborHost

def get_harbor_private_image():
    harborHost = get_harbor_host(params[i]["serverURL"])
    return harborHost + '/autotest-private/nginx'


def get_harbor_project_info_url_and_headers(harborUrl,harborOption):
    headers = {"cookie": "R_SESS=" + token["auth_admin_user"], "X-API-Harbor-Admin-Header": "true"}
    if harborOption == "harborV1" or harborOption == "harborLdapV1":
        reUrl = CATTLE_TEST_URL + "/meta/harbor/" + harborUrl.replace('//', '/') + "/api/projects/4/members"
    elif harborOption == "harborV2":
        reUrl = CATTLE_TEST_URL + "/meta/harbor/" + harborUrl.replace('//','/') + "/api/v2.0/projects/2/members"
    elif harborOption == "harborLdapV2":
        reUrl = CATTLE_TEST_URL + "/meta/harbor/" + harborUrl.replace('//', '/') + "/api/v2.0/projects/5/members"
    elif harborOption == "harborAdV1":
        reUrl = CATTLE_TEST_URL + "/meta/harbor/" + harborUrl.replace('//', '/') + "/api/projects/2/members"
    elif harborOption == "harborAdV2":
        reUrl = CATTLE_TEST_URL + "/meta/harbor/" + harborUrl.replace('//', '/') + "/api/v2.0/projects/8/members"
    return reUrl,headers

def get_harbor_project_members():
    reUrl,headers = get_harbor_project_info_url_and_headers(params[i]["serverURL"],params[i]["option"])
    re = requests.get(reUrl,verify=False,
                       headers=headers)
    assert re.status_code == 200,"得到harbor项目下的成员"
    memberList = json.loads(re.text)
    return memberList

def delete_harbor_project_member(memberName):
    memberList = get_harbor_project_members()
    for member in memberList:
        if memberName == member["entity_name"]:
            Url,headers = get_harbor_project_info_url_and_headers(params[i]["serverURL"],params[i]["option"])
            deleteUrl = Url + "/" + str(member["id"])
            re = requests.delete(deleteUrl,verify=False,
                       headers=headers)
            assert re.status_code in {200, 201}, "判断harbor删除指定成员"
            return
    print("harbor的项目下不存在该删除成员")
    return


def add_member_to_private_repo():
    reUrl,headers = get_harbor_project_info_url_and_headers(params[i]["serverURL"],params[i]["option"])
    config_json = {
        "member_user": {
            "username":RANCHER_LDAP_GENERAL_USERNAME
        },
        "role_id": 1}
    re = requests.post(reUrl, json=config_json, verify=False,
                       headers=headers)
    assert re.status_code in {200,201}  ,"判断给harbor私用项目添加成员"


def private_image_with_dockercredential():
    general_p_client = namespace["general_p_client"]
    general_ns = namespace["general_ns"]

    name = random_test_name("registry")
    register_name.append(name)
    registries = {get_harbor_host(params[i]["serverURL"]): {}}
    harbor_dockercredential_label = {"rancher.cn/registry-harbor-auth": "true"}
    general_p_client.create_dockerCredential(registries=registries, name=name, labels=harbor_dockercredential_label)

    privateImage = get_harbor_private_image()
    wl = create_workload(general_p_client, general_ns, privateImage)
    assert wl.state == 'active'

def private_image_with_update_dockercredential(p_client,user,ns,harborPwd):
    # 添加harbor镜像凭证
    name = random_test_name("registry")
    register_name.append(name)
    if user.name == "Default Admin":
        harbor_dockercredential_label = {"rancher.cn/registry-harbor-auth": "true","rancher.cn/registry-harbor-admin-auth":"true"}
        clientHarbor = namespace["client"]

        registries = {get_harbor_host(params[i]["serverURL"]): {}}
        p_client.create_dockerCredential(registries=registries, name=name, labels=harbor_dockercredential_label)
        # 修改harbor密码
        admin_user_change_password("Rancher@1234",harborPwd)
        # 创建work带有私有镜像
        privateImage = get_harbor_private_image()
        wl = create_workload(p_client, ns, privateImage)
        # harbor密码复位
        admin_user_change_password(harborPwd,"Rancher@1234")
        assert wl.state == 'active'

    else:
        harbor_dockercredential_label = {"rancher.cn/registry-harbor-auth": "true"}
        clientHarbor = namespace["general_client"]

        registries = {get_harbor_host(params[i]["serverURL"]): {}}
        p_client.create_dockerCredential(registries=registries, name=name, labels=harbor_dockercredential_label)

        # 修改harbor密码
        change_harbor_password(clientHarbor, user, "Rancher@1234", harborPwd)
        # 创建work带有私有镜像
        privateImage = get_harbor_private_image()
        wl = create_workload(p_client, ns, privateImage)
        # harbor密码复位
        change_harbor_password(clientHarbor, user, harborPwd,"Rancher@1234",)
        assert wl.state == 'active'



def create_workload(p_client, ns, image):
    workload_name = random_test_name("harbor")
    con = [{"name": "test",
            "image": image,
            "runAsNonRoot": False,
            "stdin": True,
            "imagePullPolicy": "Always",
            }]
    workload = p_client.create_workload(name=workload_name,
                                        containers=con,
                                        namespaceId=ns.id)
    workload = wait_for_wl_to_active(p_client, workload, timeout=90)
    return workload

# 移除harbor配置
def remove_harborconfig():

    client = namespace["client"]
    clusters_local = client.list_cluster(name="local").data[0]
    create_kubeconfig(clusters_local)

    # 校验 harbor-config
    cmd = "get secret -n pandaria-global-data"
    result = execute_kubectl_cmd_with_code(cmd, json_out=True, stderr=False, stderrcode=False)
    assert result["items"][1]["metadata"]["name"] == "harbor-config"

    # 校验 普通用户 harbor-config
    generalUserId = namespace["general_user"]["id"]
    generalUserHarborconfig = generalUserId+ "-harbor"

    cmd = "get secret -n " + generalUserId
    result = execute_kubectl_cmd_with_code(cmd, json_out=True, stderr=False, stderrcode=False)
    assert result["items"][1]["metadata"]["name"] == generalUserHarborconfig



    # 移除harbor配置
    client = namespace["client"]
    client.update_by_id_setting(id="harbor-server-url", name="harbor-server-url", value="")
    client.update_by_id_setting(id="harbor-admin-auth", name="harbor-admin-auth", value="")
    client.update_by_id_setting(id="harbor-auth-mode", name="harbor-auth-mode", value="")
    client.update_by_id_setting(id="harbor-version", name="harbor-version", value="")
    # 校验 v3/settings/harbor-* 的value值
    re = client.by_id_setting(id="harbor-server-url", name="harbor-server-url")
    assert "" == re['value']
    re = client.by_id_setting(id="harbor-admin-auth", name="harbor-admin-auth")
    assert "" == re['value']
    re = client.by_id_setting(id="harbor-auth-mode", name="harbor-auth-mode")
    assert "" == re['value']

    # 校验 harbor-config  被清除
    cmd = "get secret -n pandaria-global-data"
    result = execute_kubectl_cmd_with_code(cmd, json_out=True, stderr=False, stderrcode=False)
    assert len(result["items"]) != 2


    # 校验 普通用户的harbor secret 被清除
    cmd = "get secret -n " + generalUserId
    result = execute_kubectl_cmd_with_code(cmd, json_out=True, stderr=False, stderrcode=False)
    assert  len(result["items"]) != 2

    # 验证凭证库保留
    client = namespace["client"]
    clusters_k8s = client.list_cluster(name="k8s").data[0]
    create_kubeconfig(clusters_k8s)
    for register in register_name:
        cmd = "get secret -A"
        result = execute_kubectl_cmd_with_code(cmd, json_out=True, stderr=False, stderrcode=False)
        re = json.dumps(result)
        assert register in re
    register_name.clear()



