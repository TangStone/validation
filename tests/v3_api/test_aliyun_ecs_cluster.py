from .entfunc import *  # NOQA
import pytest


ALIYUN_ECS_ACCESS_KEY = os.environ.get('RANCHER_ALIYUN_ECS_ACCESS_KEY', "")
ALIYUN_ECS_SECRET_KEY = os.environ.get('RANCHER_ALIYUN_ECS_SECRET_KEY', "")
ALIYUN_ECS_REGION = os.environ.get('RANCHER_ALIYUN_ECS_REGION', "cn-zhangjiakou")
ALIYUN_ECS_ZONE = os.environ.get('RANCHER_ALIYUN_ECS_REGION', "cn-zhangjiakou-a")

aliyunecscredential = pytest.mark.skipif(not (ALIYUN_ECS_ACCESS_KEY and ALIYUN_ECS_SECRET_KEY),
                                   reason='ALIYUN ECS Credentials not provided, '
                                          'cannot create cluster')


@aliyunecscredential
def test_create_aliyun_ecs_cluster():

    client = get_admin_client()
    aliyunecsConfig = get_node_template()
    nodeTemplate = client.create_nodeTemplate(aliyunecsConfig)
    assert nodeTemplate.state == 'active'

    rancherKubernetesEngineConfig = get_rancherK8sEngine_config()
    print("Cluster creation")
    cluster = client.create_cluster(rancherKubernetesEngineConfig)
    print(cluster)
    print("NodePool creation")
    nodePool = get_node_pool(nodeTemplate,cluster)
    node = client.create_nodePool(nodePool)
    print(node)
    assert node.state == 'active'

    cluster = validate_internal_cluster(client, cluster, check_intermediate_state=True,
                               skipIngresscheck=True)
    cluster_cleanup(client, cluster)
    time.sleep(5)
    nodePool_can_delete = wait_for_nodePool_delete(client, nodeTemplate.id)
    assert nodePool_can_delete == []
    client.delete(nodeTemplate)


def get_node_template():
    aliyunecsConfig =  {
        "accessKeyId": ALIYUN_ECS_ACCESS_KEY,
        "accessKeySecret": ALIYUN_ECS_SECRET_KEY,
        "apiEndpoint": "",
        "description": "",
        "diskCategory": "cloud_ssd",
        "diskFs": "ext4",
        "diskSize": "40",
        "imageId": "ubuntu_20_04_x64_20G_alibase_20201120.vhd",
        "instanceType": "ecs.g5.large",
        "internetChargeType": "PayByTraffic",
        "internetMaxBandwidth": "100",
        "ioOptimized": "true",
        "privateAddressOnly": False,
        "privateIp": "",
        "region": ALIYUN_ECS_REGION,
        "resourceGroupId": "",
        "routeCidr": "",
        "securityGroup": "sg-8vb8cjllgpghz8cl38jw",
        "slbId": "",
        "sshKeyContents": "",
        "sshKeypair": "",
        "sshPassword": "",
        "systemDiskCategory": "cloud_ssd",
        "systemDiskSize": "40",
        "upgradeKernel": False,
        "vpcId": "vpc-8vbaylmes0pejd94gnxa1",
        "vswitchId": "vsw-8vbyk12961k62a0erw7hp",
        "zone": "cn-zhangjiakou-a",
        "type": ALIYUN_ECS_ZONE

    }

    # Generate the config for ALIYUN ECS cluster
    nodeTemplate = {
        "aliyunecsConfig": aliyunecsConfig,
        "name": random_test_name("test-auto-aliyunecs-nodeTemplate"),
        "type": "nodeTemplate",
        "useInternalIpAddress": True,
        "engineInstallURL": "https://drivers.rancher.cn/pandaria/docker-install/19.03-aliyun.sh",
    }
    print("\nALIYUN ECS NodeTemplate")
    print(nodeTemplate)

    return nodeTemplate


def get_rancherK8sEngine_config():
    rancherKubernetesEngineConfig = {
        "addonJobTimeout": 30,
        "ignoreDockerVersion": True,
        "sshAgentAuth": False,
        "type": "rancherKubernetesEngineConfig",
        "kubernetesVersion": "v1.18.12-rancher1-1",
        "authentication": {
            "strategy": "x509",
            "type": "authnConfig"
        },
        "dns": {
            "type": "dnsConfig",
            "nodelocal": {
                "type": "nodelocal",
                "ip_address": "",
                "node_selector": None,
                "update_strategy": {

                }
            }
        },
        "network": {
            "mtu": 0,
            "plugin": "canal",
            "type": "networkConfig",
            "options": {
                "flannel_backend_type": "vxlan"
            }
        },
        "ingress": {
            "httpPort": 0,
            "httpsPort": 0,
            "provider": "nginx",
            "type": "ingressConfig"
        },
        "monitoring": {
            "provider": "metrics-server",
            "replicas": 1,
            "type": "monitoringConfig"
        },
        "services": {
            "type": "rkeConfigServices",
            "kubeApi": {
                "alwaysPullImages": False,
                "podSecurityPolicy": False,
                "serviceNodePortRange": "30000-32767",
                "type": "kubeAPIService"
            },
            "etcd": {
                "creation": "12h",
                "extraArgs": {
                    "heartbeat-interval": 500,
                    "election-timeout": 5000
                },
                "gid": 0,
                "retention": "72h",
                "snapshot": False,
                "uid": 0,
                "type": "etcdService",
                "backupConfig": {
                    "enabled": True,
                    "intervalHours": 12,
                    "retention": 6,
                    "safeTimestamp": False,
                    "type": "backupConfig"
                }
            }
        },
        "upgradeStrategy": {
            "maxUnavailableControlplane": "1",
            "maxUnavailableWorker": "10%",
            "drain": "false",
            "nodeDrainInput": {
                "deleteLocalData": False,
                "force": False,
                "gracePeriod": -1,
                "ignoreDaemonSets": True,
                "timeout": 120,
                "type": "nodeDrainInput"
            },
            "maxUnavailableUnit": "percentage"
        }
    }

    rancherK8sEngineConfig = {
        "dockerRootDir": "/var/lib/docker",
        "enableClusterAlerting": False,
        "enableClusterMonitoring": False,
        "enableDualStack": False,
        "enableGPUManagement": False,
        "enableNetworkPolicy": False,
        "fluentdLogDir": "/var/lib/rancher/fluentd/log",
        "gpuSchedulerNodePort": "32666",
        "windowsPreferedCluster": False,
        "rancherKubernetesEngineConfig": rancherKubernetesEngineConfig,
        "name": random_test_name("test-auto-rke-aliyunecs"),
        "type": "cluster",
        "localClusterAuthEndpoint": {
            "enabled": True,
            "type": "localClusterAuthEndpoint"
        },
        "labels": {

        },
        "scheduledClusterScan": {
            "enabled": False,
            "scheduleConfig": None,
            "scanConfig": None
        }
    }
    print("\nRKE ALIYUNECS Configuration")
    print(rancherK8sEngineConfig)

    return rancherK8sEngineConfig


def get_node_pool(nodeTemplate,cluster):
    nodePool = {
        "controlPlane": True,
        "deleteNotReadyAfterSecs": 0,
        "etcd": True,
        "quantity": 1,
        "worker": True,
        "type": "nodePool",
        "nodeTemplateId": nodeTemplate.id,
        "clusterId": cluster.id,
        "hostnamePrefix": random_test_name("test-auto-aliyunecs-nodepool")
    }
    print(nodePool)
    return nodePool