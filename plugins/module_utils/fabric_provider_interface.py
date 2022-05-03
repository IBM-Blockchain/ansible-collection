from abc import ABC, abstractmethod


class IFabricProvider(ABC):

    @abstractmethod
    def login(self, api_authtype, api_key, api_secret):
        pass

    @abstractmethod
    def get_all_components(self, deployment_attrs='omitted'):
        pass

    @abstractmethod
    def get_health(self):
        pass

    @abstractmethod
    def get_settings(self):
        pass

    @abstractmethod
    def get_component_by_id(self, id, deployment_attrs='omitted'):
        pass

    @abstractmethod
    def get_component_by_display_name(self, component_type, display_name, deployment_attrs='omitted'):
        pass

    @abstractmethod
    def get_components_by_cluster_name(self, component_type, cluster_name, deployment_attrs='omitted'):
        pass

    @abstractmethod
    def create_ca(self, data):
        pass

    @abstractmethod
    def update_ca(self, id, data):
        pass

    @abstractmethod
    def delete_ca(self, id):
        pass

    @abstractmethod
    def extract_ca_info(self, ca):
        pass

    @abstractmethod
    def create_ext_ca(self, data):
        pass

    @abstractmethod
    def update_ext_ca(self, id, data):
        pass

    @abstractmethod
    def delete_ext_ca(self, id):
        pass

    @abstractmethod
    def create_peer(self, data):
        pass

    @abstractmethod
    def update_peer(self, id, data):
        pass

    @abstractmethod
    def delete_peer(self, id):
        pass

    @abstractmethod
    def extract_peer_info(self, peer):
        pass

    @abstractmethod
    def create_ext_peer(self, data):
        pass

    @abstractmethod
    def update_ext_peer(self, id, data):
        pass

    @abstractmethod
    def delete_ext_peer(self, id):
        pass

    @abstractmethod
    def create_ordering_service(self, data):
        pass

    @abstractmethod
    def delete_ordering_service(self, cluster_id):
        pass

    @abstractmethod
    def extract_ordering_service_info(self, ordering_service):
        pass

    @abstractmethod
    def delete_ext_ordering_service(self, cluster_id):
        pass

    @abstractmethod
    def edit_ordering_service_node(self, id, data):
        pass

    @abstractmethod
    def update_ordering_service_node(self, id, data):
        pass

    @abstractmethod
    def delete_ordering_service_node(self, id):
        pass

    @abstractmethod
    def extract_ordering_service_node_info(self, ordering_service_node):
        pass

    @abstractmethod
    def create_ext_ordering_service_node(self, data):
        pass

    @abstractmethod
    def update_ext_ordering_service_node(self, id, data):
        pass

    @abstractmethod
    def delete_ext_ordering_service_node(self, id):
        pass

    @abstractmethod
    def edit_admin_certs(self, id, append_admin_certs, remove_admin_certs):
        pass

    @abstractmethod
    def create_organization(self, data):
        pass

    @abstractmethod
    def update_organization(self, id, data):
        pass

    @abstractmethod
    def delete_organization(self, id):
        pass

    @abstractmethod
    def extract_organization_info(self, organization):
        pass

    @abstractmethod
    def submit_config_block(self, id, config_block):
        pass

    @abstractmethod
    def wait_for(self, component):
        pass

    @abstractmethod
    def newPeerConnection(self, component):
        pass
