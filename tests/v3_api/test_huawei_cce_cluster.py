from .common import *  # NOQA
import pytest

HUAWEI_CCE_ACCESS_KEY = os.environ.get('RANCHER_HUAWEI_CCE_ACCESS_KEY', "")
HUAWEI_CCE_SECRET_KEY = os.environ.get('RANCHER_HUAWEI_CCE_SECRET_KEY', "")
HUAWEI_CCE_PROJECT = os.environ.get('RANCHER_HUAWEI_CCE_PROJECT', "")
HUAWEI_CCE_AMI = os.environ.get('RANCHER_HUAWEI_CCE_AMI', "")

huaweiccecredential = pytest.mark.skipif(not (HUAWEI_CCE_ACCESS_KEY and HUAWEI_CCE_SECRET_KEY and HUAWEI_CCE_PROJECT),
                                   reason='HUAWEI CCE Credentials not provided, '
                                          'cannot create cluster')

@huaweiccecredential
def test_create_huaei_cce_cluster():

    client = get_admin_client()
    huawei_cceConfig = get_huawei_cce_config()

    print("Cluster creation")
    cluster = client.create_cluster(huawei_cceConfig)
    print(cluster)
    cluster = validate_cluster(client, cluster, check_intermediate_state=True,
                               skipIngresscheck=True)
    print(cluster)
    cluster_cleanup(client, cluster)

def get_huawei_cce_config():

    name = random_test_name("tl-test-auto-huawei-cce")
    huawei_cceConfig =  {
        "accessKey":HUAWEI_CCE_ACCESS_KEY,
        "apiServerElbId":"",
        "authentiactionMode":"rbac",
        "authenticatingProxyCa":None,
        "availableZone":"cn-north-1a",
        "billingMode":0,
        "bmsIsAutoRenew":"false",
        "bmsPeriodNum":1,
        "bmsPeriodType":"month",
        "clusterBillingMode":0,
        "clusterEipId":"",
        "clusterFlavor":"cce.s2.small",
        "clusterType":"VirtualMachine",
        "containerNetworkCidr":"10.0.0.0/16",
        "containerNetworkMode":"overlay_l2",
        "dataVolumeSize":100,
        "dataVolumeType":"SATA",
        "description":"",
        "displayName":"",
        "driverName":"huaweicontainercloudengine",
        "eipBandwidthSize":100,
        "eipChargeMode":"traffic",
        "eipCount":3,
        "eipShareType":"PER",
        "eipType":"5_bgp",
        "externalServerEnabled":False,
        "highwaySubnet":"",
        "masterVersion":"v1.15.6",
        "nodeCount":3,
        "nodeFlavor":"c3.large.2",
        "nodeOperationSystem":"CentOS 7.6",
        "password":"",
        "projectId":HUAWEI_CCE_PROJECT,
        "region":"cn-north-1",
        "rootVolumeSize":40,
        "rootVolumeType":"SATA",
        "secretKey":HUAWEI_CCE_SECRET_KEY,
        "sshKey":"tanglei",
        "subnetId":"c3a34386-5212-4484-be9c-1220807c4cfa",
        "userName":"root",
        "vipSubnetId":"09fb7641-3958-47d7-b5fb-dd92a19ef7ee",
        "vpcId":"d5842876-29a6-4751-87bd-7c4af4cf2f47",
        "type":"huaweiEngineConfig",
        "keypairs":"cn-north-1a",
    }
    if HUAWEI_CCE_AMI is not None:
        huawei_cceConfig.update({"ami": HUAWEI_CCE_AMI})

    # Generate the config for CCE cluster
    huawei_cceConfig = {
        "huaweiEngineConfig": huawei_cceConfig,
        "name": name,
        "type": "cluster"
    }
    print("\nHUAWEI CCE Configuration")
    print(huawei_cceConfig)

    return huawei_cceConfig
