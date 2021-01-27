import pystache
import pytest
from .entfunc import *
import yaml

RANCHER_LOCAL_ADMIN_USERNAME = os.environ.get('RANCHER_LOCAL_ADMIN_USERNAME', "admin")
RANCHER_LOCAL_ADMIN_PASSWORD = os.environ.get('RANCHER_LOCAL_ADMIN_PASSWORD', "Nasadmin123!")
RANCHER_LOCAL_GENERAL_USERNAME = os.environ.get('RANCHER_LOCAL_GENERAL_USERNAME', "tanglei")
RANCHER_LOCAL_GENERAL_PASSWORD = os.environ.get('RANCHER_LOCAL_GENERAL_PASSWORD', "Rancher@123")

CATTLE_LOCAL_LOGIN_URL = \
    CATTLE_TEST_URL + \
    "/v3-public/localProviders/local?action=login"



namespace={}


def get_auth_token(username,password,reUrl):
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
    re = requests.post(reUrl, json=var, verify=False)
    token = re.headers["set-cookie"].replace("; Path=/; HttpOnly; Secure", "").replace("R_SESS=","")
    assert re.status_code == 200
    return token

def get_filter(filterName):
    path = os.path.join(os.path.dirname(os.path.realpath(__file__)) + "/resource","filter.yaml")
    with open(path, encoding='utf-8') as f:
        filter = yaml.safe_load(f)
    return filter[filterName]




@pytest.fixture(scope='module', autouse="True")
def get_admin_client():
    # 获取admin的token
    username = RANCHER_LOCAL_ADMIN_USERNAME
    pwd = RANCHER_LOCAL_ADMIN_PASSWORD
    url = CATTLE_LOCAL_LOGIN_URL
    adminToken = get_auth_token(username,pwd,url)
    namespace["admin"] = adminToken
    client = get_client_for_token(adminToken)
    namespace["client"] = client

def delete_general_user(generalUser):
    reUrl = CATTLE_API_URL + "/" + "users/" + generalUser.id
    username = RANCHER_LOCAL_ADMIN_USERNAME
    pwd = RANCHER_LOCAL_ADMIN_PASSWORD
    url = CATTLE_LOCAL_LOGIN_URL
    adminToken = get_auth_token(username, pwd, url)
    headers = {"cookie": "R_SESS=" + adminToken, "X-API-Harbor-Admin-Header": "true"}
    re = requests.delete(reUrl,headers=headers,verify=False)
    assert re.status_code == 200,"delete general user failed"


def create_general_user():
    # 创建普通用户tanglei
    client = namespace["client"]
    user = {
        "enabled": True,
        "mustChangePassword": False,
        "type": "user",
        "username": "tanglei",
        "password": "Rancher@123"
    }
    generalUser = client.create_user(user)
    globalrolebinding = {
        "type": "globalRoleBinding",
        "globalRoleId": "user",
        "userId": generalUser.id
    }
    client.create_globalRoleBinding(globalrolebinding)
    return generalUser

# View Project Catalogs and projectloggings角色
def create_projectCatalogsAndProjectloggings_role():
    client = namespace["client"]
    var = {
        "administrative":False,
        "clusterCreatorDefault":False,
        "external":False,
        "hidden":False,
        "locked":False,
        "projectCreatorDefault":False,
        "type":"roleTemplate",
        "name":"View Project Catalogs and projectloggings",
        "rules":[
            {
                "type":"policyRule",
                "verbs":[
                    "create",
                    "delete",
                    "get",
                    "list",
                    "patch",
                    "update",
                    "watch"
                ],
                "apiGroups":[
                    "*"
                ],
                "resources":[
                    "projectloggings"
                ]
            }
        ],
        "context":"project",
        "roleTemplateIds":[
            "projectcatalogs-view"
        ]
    }
    projectCatalogsAndProjectloggings_role = client.create_roleTemplate(var)
    return projectCatalogsAndProjectloggings_role

# View Project Catalogs and projectloggings角色
def create_viewServiceAndProjectcatalogs_role():
    client = namespace["client"]
    var = {
        "administrative": False,
        "clusterCreatorDefault": False,
        "external": False,
        "hidden": False,
        "locked": False,
        "projectCreatorDefault": False,
        "type": "roleTemplate",
        "name": "view service and projectcatalogs",
        "rules": [
            {
                "type": "policyRule",
                "verbs": [
                    "create",
                    "delete",
                    "get",
                    "list",
                    "patch",
                    "update",
                    "watch"
                ],
                "apiGroups": [
                    "*"
                ],
                "resources": [
                    "projectcatalogs"
                ]
            }
        ],
        "context": "project",
        "roleTemplateIds": [
            "services-view"
        ]
    }
    ViewServiceAndProjectcatalogs_role = client.create_roleTemplate(var)
    return ViewServiceAndProjectcatalogs_role

def add_project_role_to_user(generalUser,roleTemplateId):
    # 添加用户tanglei到k8s的default
    client = namespace["client"]
    clusters_k8s_id = client.list_cluster(name="k8s").data[0].id
    proK8sDefault = client.list_project(name="Default",clusterId=clusters_k8s_id).data[0]

    projectroletemplatebinding = {
        "type": "projectRoleTemplateBinding",
        "projectId": proK8sDefault.id,
        "userPrincipalId":generalUser.principalIds[0],
        "roleTemplateId": roleTemplateId
    }
    resProjectRoleTemplateBinding = client.create_projectRoleTemplateBinding(projectroletemplatebinding)
    return resProjectRoleTemplateBinding

def add_cluster_role_to_user(generalUser,roleTemplateId):
    # 添加用户tanglei到k8s
    client = namespace["client"]
    clusters_k8s_id = client.list_cluster(name="k8s").data[0].id


    clusterRoleTemplateBinding = {
        "type": "clusterRoleTemplateBinding",
        "clusterId": clusters_k8s_id,
        "userPrincipalId":generalUser.principalIds[0],
        "roleTemplateId": roleTemplateId
    }
    resclusterRoleTemplateBinding = client.create_clusterRoleTemplateBinding(clusterRoleTemplateBinding)
    return resclusterRoleTemplateBinding



def add_filter(filterName):
    client = namespace["client"]
    clusters_local = client.list_cluster(name="local").data[0]
    create_kubeconfig(clusters_local)
    yaml = get_filter(filterName)
    clusters_local.importYaml(yaml=yaml)

def delete_filter(*deleteFilterName):
    for filterName in deleteFilterName:
        cmd = "delete SensitiveFilter " + filterName
        result = execute_kubectl_cmd_with_code(cmd, json_out=False, stderr=False, stderrcode=False)
        assert filterName in result


def print_object(obj):
    print('\n'.join(['%s:%s' % item for item in obj.__dict__.items()]))

def check_filter(*fields,resource,generateFilter=True):
    username = RANCHER_LOCAL_GENERAL_USERNAME
    pwd = RANCHER_LOCAL_GENERAL_PASSWORD
    url = CATTLE_LOCAL_LOGIN_URL
    generalToken = get_auth_token(username, pwd, url)
    generalClient = get_client_for_token(generalToken)
    if resource == "projectcatalogs":
        resourceData = generalClient.list_projectCatalog().data[0]
    elif resource == "clusters":
        resourceData = generalClient.list_cluster().data[0]
    elif resource == "projects":
        resourceData = generalClient.list_project().data[0]
    count = 0
    for field in fields:
        fieldList = field.split('.')
        temp = resourceData
        for i in fieldList:
            try:
                temp[i]
            except KeyError:
                count+=1
            else:
                temp = temp[i]
    if generateFilter:
        if count == len(fields):
            return True
        else:
            return False
    else:
        if count == 0:
            return True
        else:
            return False


def create_projectCatalog():
    client = namespace["client"]
    var = {
        "type":"projectcatalog",
        "kind":"helm",
        "branch":"master",
        "projectId":"c-gnkzj:p-qsph7",
        "helmVersion":"rancher-helm",
        "name":"test1",
        "url":"https://github.com/cnrancher/system-charts",
        "username":None,
        "password":None
    }
    projectCatelogs = client.create_projectCatalog(var)
    return projectCatelogs


def test_get_filter_11():
    client = namespace["client"]
    clusters_local = client.list_cluster(name="local").data[0]
    create_kubeconfig(clusters_local)

    path = os.path.join(os.path.dirname(os.path.realpath(__file__)) + "/resource","filter.yaml")
    with open(path, encoding='utf-8') as f:
        filterAll = yaml.safe_load(f)
    # init
    generalUser = create_general_user()
    res = add_project_role_to_user(generalUser, roleTemplateId="project-owner")
    # done
    deleteFilterName = []
    for key,value in filterAll.items():
        nonResourceURLs = []
        if key == "cluster-filter-11":
            for k,v in value.items():
                if k == "filter-11":
                    filter = yaml.safe_load(v)
                    nonResourceURLs = filter["filters"][0]["nonResourceURLs"]
                    clusters_local.importYaml(yaml=v)
                    deleteFilterName.append(filter["metadata"]["name"])
                if k == "isFilter":
                    assert check_filter_url_cluster_11(*nonResourceURLs,generateFilter=v)
            delete_filter(*deleteFilterName)
    # 清除赋予角色权限
    resProjectBindings = []
    resProjectBindings.append(res)
    delete_role(*resProjectBindings)
    delete_general_user(generalUser)

def test_get_filter_12():
    client = namespace["client"]
    clusters_local = client.list_cluster(name="local").data[0]
    create_kubeconfig(clusters_local)

    path = os.path.join(os.path.dirname(os.path.realpath(__file__)) + "/resource","filter.yaml")
    with open(path, encoding='utf-8') as f:
        filterAll = yaml.safe_load(f)
    # init
    generalUser = create_general_user()
    res = add_project_role_to_user(generalUser, roleTemplateId="project-owner")
    # done
    deleteFilterName = []
    for key,value in filterAll.items():
        nonResourceURLs = []
        if key == "cluster-filter-12":
            for k,v in value.items():
                if k == "filter-12":
                    filter = yaml.safe_load(v)
                    nonResourceURLs = filter["filters"][0]["nonResourceURLs"]
                    clusters_local.importYaml(yaml=v)
                    deleteFilterName.append(filter["metadata"]["name"])
                if k == "isFilter":
                    assert check_filter_url_cluster_12(*nonResourceURLs,generateFilter=v)
            delete_filter(*deleteFilterName)
    # 清除赋予角色权限
    resProjectBindings = []
    resProjectBindings.append(res)
    delete_role(*resProjectBindings)
    delete_general_user(generalUser)

def test_get_filter_13():
    client = namespace["client"]
    clusters_local = client.list_cluster(name="local").data[0]
    create_kubeconfig(clusters_local)

    path = os.path.join(os.path.dirname(os.path.realpath(__file__)) + "/resource","filter.yaml")
    with open(path, encoding='utf-8') as f:
        filterAll = yaml.safe_load(f)
    # init
    generalUser = create_general_user()
    res = add_project_role_to_user(generalUser, roleTemplateId="project-owner")
    # done
    deleteFilterName = []
    for key,value in filterAll.items():
        nonResourceURLs = []
        if key == "cluster-filter-13":
            for k,v in value.items():
                if k == "filter-13":
                    filter = yaml.safe_load(v)
                    nonResourceURLs = filter["filters"][0]["nonResourceURLs"]
                    clusters_local.importYaml(yaml=v)
                    deleteFilterName.append(filter["metadata"]["name"])
                if k == "isFilter":
                    assert check_filter_url_cluster_13(*nonResourceURLs,generateFilter=v)
            delete_filter(*deleteFilterName)
    # 清除赋予角色权限
    resProjectBindings = []
    resProjectBindings.append(res)
    delete_role(*resProjectBindings)
    delete_general_user(generalUser)


def check_filter_url_cluster_13(*nonResourceURLs,generateFilter=True):
    username = RANCHER_LOCAL_GENERAL_USERNAME
    pwd = RANCHER_LOCAL_GENERAL_PASSWORD
    url =  CATTLE_LOCAL_LOGIN_URL
    generalToken = get_auth_token(username, pwd, url)
    generalClient = get_client_for_token(generalToken)
    clusterActions = generalClient.list_cluster().data[0].actions
    filterList = ["enableMonitoring","runSecurityScan","saveAsTemplate"]
    for filte in filterList:
        for aciton in clusterActions:
            if aciton == filte and generateFilter:
                return False
    return True

def check_filter_url_cluster_12(*nonResourceURLs,generateFilter=True):
    username = RANCHER_LOCAL_GENERAL_USERNAME
    pwd = RANCHER_LOCAL_GENERAL_PASSWORD
    url =  CATTLE_LOCAL_LOGIN_URL
    generalToken = get_auth_token(username, pwd, url)
    generalClient = get_client_for_token(generalToken)
    clusterLinks = generalClient.list_cluster().data[0].links
    for link in clusterLinks:
        if link == "clusteralertgroups" and generateFilter:
            return False
    return True



def check_filter_url_cluster_11(*nonResourceURLs,generateFilter=True):
    username = RANCHER_LOCAL_GENERAL_USERNAME
    pwd = RANCHER_LOCAL_GENERAL_PASSWORD
    url =  CATTLE_LOCAL_LOGIN_URL
    generalToken = get_auth_token(username, pwd, url)
    generalClient = get_client_for_token(generalToken)
    actionsList = generalClient.list_cluster().data[0].actions
    count = 0
    for nonResourceURL in nonResourceURLs:
        nonResourceURLRes = nonResourceURL.split('=')
        for action in actionsList:
            if nonResourceURLRes[1] == action:
                count += 1
    if count == 0 and generateFilter == True:
        return True
    else:
        return False

def test_get_filter_to_10():
    client = namespace["client"]
    clusters_local = client.list_cluster(name="local").data[0]
    create_kubeconfig(clusters_local)

    path = os.path.join(os.path.dirname(os.path.realpath(__file__)) + "/resource","filter.yaml")
    with open(path, encoding='utf-8') as f:
        filterAll = yaml.safe_load(f)
    # init
    generalUser = create_general_user()
    projectCatalogsAndProjectloggings_role = create_projectCatalogsAndProjectloggings_role()
    viewServiceAndProjectcatalogs_role = create_viewServiceAndProjectcatalogs_role()
    roleIdConfig = {"roles":projectCatalogsAndProjectloggings_role.id}
    create_projectCatalog()

    resProjectBindings = []
    deleteFilterName = []
    resourceList = []
    fieldsList = []
    for key,value in filterAll.items():
        filterName = key
        for k,v in value.items():
            if k == "filter":
                filter = yaml.safe_load(v)
                fields = filter["filters"][0]["fields"]
                fieldsList = list(set(fieldsList + fields))
                # 模板替换角色id
                resource = filter["filters"][0]["resources"][0]
                resourceList.append(resource)
                if resource == "projectcatalogs": # cluster-filter-5,6
                    v = v.replace("{{role}}",projectCatalogsAndProjectloggings_role.id)
                    # 给用户配置角色，赋予权限
                    res = add_project_role_to_user(generalUser, roleTemplateId=projectCatalogsAndProjectloggings_role.id)
                    resProjectBindings.append(res)
                elif filterName == "cluster-filter-7":
                    res = add_project_role_to_user(generalUser, roleTemplateId="project-member")
                    resProjectBindings.append(res)
                    res = add_project_role_to_user(generalUser, roleTemplateId="project-owner")
                    resProjectBindings.append(res)
                else:
                    res = add_project_role_to_user(generalUser, roleTemplateId="project-member")
                    resProjectBindings.append(res)
                clusters_local.importYaml(yaml=v)
                deleteFilterName.append(filter["metadata"]["name"])
            if k == "filter-8-1":
                filter = yaml.safe_load(v)
                fields = filter["filters"][0]["fields"]
                fieldsList = list(set(fieldsList + fields))
                resource = filter["filters"][0]["resources"][0]
                resourceList.append(resource)
                # 给用户配置角色，赋予权限
                res = add_project_role_to_user(generalUser, roleTemplateId="projectcatalogs-view")
                resProjectBindings.append(res)
                clusters_local.importYaml(yaml=v)
                deleteFilterName.append(filter["metadata"]["name"])
            if k == "filter-8-2":
                filter = yaml.safe_load(v)
                fields = filter["filters"][0]["fields"]
                fieldsList = list(set(fieldsList + fields))
                resource = filter["filters"][0]["resources"][0]
                resourceList.append(resource)
                # 给用户配置角色，赋予权限
                v = v.replace("{{role}}", viewServiceAndProjectcatalogs_role.id)
                res = add_project_role_to_user(generalUser, roleTemplateId=viewServiceAndProjectcatalogs_role.id)
                resProjectBindings.append(res)
                clusters_local.importYaml(yaml=v)
                deleteFilterName.append(filter["metadata"]["name"])
            if k == "filter-9-1":
                filter = yaml.safe_load(v)
                fields1 = filter["filters"][0]["fields"]
                resource = filter["filters"][0]["resources"][0]
                resourceList.append(resource)
                # 给用户配置角色，赋予权限
                res = add_project_role_to_user(generalUser, roleTemplateId="projectcatalogs-view")
                resProjectBindings.append(res)
                clusters_local.importYaml(yaml=v)
                deleteFilterName.append(filter["metadata"]["name"])
            if k == "filter-9-2":
                filter = yaml.safe_load(v)
                fields2 = filter["filters"][0]["fields"]
                fieldsList = list(set(fields1) & set(fields2))
                resource = filter["filters"][0]["resources"][0]
                resourceList.append(resource)
                # 给用户配置角色，赋予权限
                v = v.replace("{{role}}", viewServiceAndProjectcatalogs_role.id)
                res = add_project_role_to_user(generalUser, roleTemplateId=viewServiceAndProjectcatalogs_role.id)
                resProjectBindings.append(res)
                clusters_local.importYaml(yaml=v)
                deleteFilterName.append(filter["metadata"]["name"])
            if k == "filter-10-1":
                filter = yaml.safe_load(v)
                fieldsList = list(set(fieldsList + fields))
                resource = filter["filters"][0]["resources"][0]
                resourceList.append(resource)
                # 给用户配置角色，赋予权限
                res = add_project_role_to_user(generalUser, roleTemplateId="projectcatalogs-view")
                resProjectBindings.append(res)
                clusters_local.importYaml(yaml=v)
                deleteFilterName.append(filter["metadata"]["name"])
            if k == "filter-10-2":
                filter = yaml.safe_load(v)
                fieldsList = list(set(fieldsList + fields))
                fieldsList = list(set(fields1) & set(fields2))
                resource = filter["filters"][0]["resources"][0]
                resourceList.append(resource)
                # 给用户配置角色，赋予权限
                v = v.replace("{{role}}", viewServiceAndProjectcatalogs_role.id)
                res = add_project_role_to_user(generalUser, roleTemplateId=viewServiceAndProjectcatalogs_role.id)
                resProjectBindings.append(res)
                clusters_local.importYaml(yaml=v)
                deleteFilterName.append(filter["metadata"]["name"])
            if k == "isFilter":
                for res in resourceList:
                    assert check_filter(*fieldsList,resource=res,generateFilter=v)
                delete_role(*resProjectBindings)
                resProjectBindings.clear()
                resourceList.clear()
                fieldsList.clear()
        delete_filter(*deleteFilterName)
        deleteFilterName.clear()
        delete_general_user(generalUser)

def delete_role(*resProjectBindings):
    # 添加用户tanglei到k8s的default
    client = namespace["client"]
    for resProjectBinding in resProjectBindings:
        if resProjectBinding.baseType == "projectRoleTemplateBinding":
            res = client.by_id_projectRoleTemplateBinding(resProjectBinding.id)
        elif resProjectBinding.baseType == "clusterRoleTemplateBinding":
            res = client.by_id_clusterRoleTemplateBinding(resProjectBinding.id)
        username = RANCHER_LOCAL_ADMIN_USERNAME
        pwd = RANCHER_LOCAL_ADMIN_PASSWORD
        url = CATTLE_LOCAL_LOGIN_URL
        adminToken = get_auth_token(username, pwd, url)
        headers = {"cookie": "R_SESS=" + adminToken, "Accept": "application/json"}
        reUrl = res.links["remove"]
        re = requests.delete(reUrl, verify=False, headers=headers)



















