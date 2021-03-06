import pystache as pystache

from .entfunc import *  # NOQA
import pytest

ACK_ACCESS_KEY = os.environ.get('RANCHER_ALIYUN_ACCESS_KEY', "")
ACK_SECRET_KEY = os.environ.get('RANCHER_ALIYUN_SECRET_KEY', "")


ackcredential = pytest.mark.skipif(not (ACK_ACCESS_KEY and ACK_SECRET_KEY),
                                   reason='ACK Credentials not provided, '
                                          'cannot create cluster')


@ackcredential
def test_create_ack_tg_cluster():
    create_ack_cluster()

@ackcredential
def test_create_ack_zy_cluster():
    create_ack_cluster()

def create_ack_cluster():
    client = get_admin_client()
    ackConfig = get_ack_config()
    print("Cluster creation")
    cluster = client.create_cluster(ackConfig)
    print(cluster)
    cluster = validate_cluster(client, cluster, check_intermediate_state=True,
                               skipIngresscheck=True)

    cluster_cleanup(client, cluster)

def get_ack_config():
    cluster_type = inspect.stack()[2][3]
    if "test_create_ack_tg_cluster" == cluster_type:
        isAlyunKubernetes = False
        name = "tl-ack-tg"
    elif "test_create_ack_zy_cluster" == cluster_type:
        isAlyunKubernetes = True
        name = "tl-ack-zy"
    else:
        return None
    ack_config = {
        "isAlyunKubernetes": isAlyunKubernetes, # False：托管集群 True：专用集群
        "accessKeyId": ACK_ACCESS_KEY,
        "accessKeySecret": ACK_SECRET_KEY,
        "kubernetesVersion": "1.16.9-aliyun.1",
        "proxyMode": "ipvs",
        "name": name
    }

    path = os.path.abspath('.') + "/tests/v3_api/resource/ackTemplate"
    print(path)
    with open(path, "r") as f:  # 用文件作为模板
        ackConfig = pystache.render(f.read(), ack_config)
        ackConfig = json.loads(ackConfig)
    print(ackConfig)
    return ackConfig



