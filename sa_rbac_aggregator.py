#!/usr/bin/env python3
"""Scrape ClusterRole/Binding, ServiceAccount data
   and aggregate it per Pod
"""

import logging
from kubernetes import client, config
from kubernetes.client.rest import ApiException

class GetMetadata:
    """Get metadata via k8s api class"""
    def __init__(self):
        #config.load_incluster_config()
        config.load_kube_config()
        self.v1 = client.CoreV1Api()
        self.v2 = client.RbacAuthorizationV1Api()

    def get_role_list(self):
        """Get Roles list from k8s api"""
        try:
            thread = self.v2.list_role_for_all_namespaces(
                watch=False, async_req=True)
            list_roles = thread.get()
        except ApiException as err:
            logging.debug(f"Exception when calling CoreV1Api->get_api_group: {err}\n")
        return list_roles

    def get_role_binding_list(self):
        """Get Role Binding list from k8s api"""
        try:
            thread = self.v2.list_role_binding_for_all_namespaces(
                watch=False, async_req=True)
            list_role_binding = thread.get()
        except ApiException as err:
            logging.debug(f"Exception when calling CoreV1Api->get_api_group: {err}\n")
        return list_role_binding

    def get_cluster_role_list(self):
        """Get Cluster roles list from k8s api"""
        try:
            thread = self.v2.list_cluster_role(
                watch=False, async_req=True)
            list_cluster_roles = thread.get()
        except ApiException as err:
            logging.debug(f"Exception when calling CoreV1Api->get_api_group: {err}\n")
        return list_cluster_roles

    def get_cluster_role_binding_list(self):
        """Get Cluster role Binding list from k8s api"""
        try:
            thread = self.v2.list_cluster_role_binding(
                watch=False, async_req=True)
            list_cluster_role_binding = thread.get()
        except ApiException as err:
            logging.debug(f"Exception when calling CoreV1Api->get_api_group: {err}\n")
        return list_cluster_role_binding

    def get_pods_list(self):
        """Get Pods list from k8s api"""
        try:
            thread = self.v1.list_pod_for_all_namespaces(
                watch=False, async_req=True)
            list_pods = thread.get()
        except ApiException as err:
            logging.debug(f"Exception when calling CoreV1Api->get_api_group: {err}\n")
            list_pods = {}
        return list_pods

    def get_pod_metadata(self, list_pods):
        """Get Pod's metadata from Pods list"""
        pods_dict = {}
        for i in list_pods.items:
            service_account = i.spec.service_account
            pod_name = i.metadata.name
            if pod_name not in pods_dict:
                pods_dict[pod_name] = service_account
        return pods_dict

    def get_role_binding_metadata(self):
        """Get Role Binding metadata from k8s api"""
        role_binding_metadata_dict = {}
        list_role_binding = self.get_role_binding_list()
        for i in list_role_binding.items:
            crb_role_ref = i.role_ref
            crb_subjects = i.subjects
            role_binding_name = vars(crb_role_ref)
            role_binding_name = role_binding_name['_name']
            if crb_subjects:
                for sa in crb_subjects:
                    crb_service_account = vars(sa)
                    crb_service_account_name = crb_service_account['_name']
                    role_binding_metadata_dict[role_binding_name] = crb_service_account_name
        return role_binding_metadata_dict

    def get_role_metadata(self, list_pods):
        """Aggregate data from RoleBinding and Role,
           then compare this data with Pod's serviceAccount
        """
        pods_dict = self.get_pod_metadata(list_pods)
        list_roles = self.get_role_list()
        role_binding_metadata_dict = self.get_role_binding_metadata()
        for role in list_roles.items:
            role_name = role.metadata.name
            # Check if there is a RoleBinding bind to the Role
            for role_binding_name, crb_service_account_name in role_binding_metadata_dict.items():
                if role_binding_name != role_name:
                    continue
                cr_rules = role.rules
                for rule in cr_rules:
                    rules = vars(rule)
                    for pod_name, pod_service_account_name in pods_dict.items():
                        if pod_name:
                            if pod_service_account_name == crb_service_account_name:
                                print(f"Pod: {pod_name}, ServiceAccount:{crb_service_account_name},Resources:{rules['_resources']},Verbs:{rules['_verbs']}")

    def get_cluster_role_binding_metadata(self):
        """Get Cluster Role Binding metadata from k8s api"""
        cluster_role_binding_metadata_dict = {}
        list_cluster_role_binding = self.get_cluster_role_binding_list()
        for i in list_cluster_role_binding.items:
            crb_role_ref = i.role_ref
            crb_subjects = i.subjects
            role_binding_name = vars(crb_role_ref)
            role_binding_name = role_binding_name['_name']
            if crb_subjects:
                for sa in crb_subjects:
                    crb_service_account = vars(sa)
                    crb_service_account_name = crb_service_account['_name']
                    cluster_role_binding_metadata_dict[role_binding_name] = crb_service_account_name
        return cluster_role_binding_metadata_dict

    def get_cluster_role_metadata(self, list_pods):
        """Aggregate data from ClusterRoleBinding and ClusterRole,
           then compare this data with Pod's serviceAccount
        """
        pods_dict = self.get_pod_metadata(list_pods)
        list_cluster_roles = self.get_cluster_role_list()
        cluster_role_binding_metadata_dict = self.get_cluster_role_binding_metadata()
        for role in list_cluster_roles.items:
            cluster_role_name = role.metadata.name
            # Check if there is a ClusterRoleBinding bind to the ClusterRole
            for role_binding_name, crb_service_account_name in cluster_role_binding_metadata_dict.items():
                if role_binding_name != cluster_role_name:
                    continue
                cr_rules = role.rules
                for rule in cr_rules:
                    rules = vars(rule)
                    for pod_name, pod_service_account_name in pods_dict.items():
                        if pod_name:
                            if pod_service_account_name == crb_service_account_name:
                                print(f"Pod: {pod_name}, ServiceAccount:{crb_service_account_name},Resources:{rules['_resources']},Verbs:{rules['_verbs']}")

def main():
    """ Main function to work with the Class"""
    run = GetMetadata()
    list_pods = run.get_pods_list()
    print(f"####################### Roles and RoleBinding aggregation #######################")
    run.get_role_metadata(list_pods)
    print(f"####################### ClusterRoles and ClusterRoleBinding aggregation #######################")
    run.get_cluster_role_metadata(list_pods)
if __name__ == "__main__":
    main()
