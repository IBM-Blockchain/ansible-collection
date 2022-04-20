from abc import ABC, abstractmethod


class ConsoleInterface(ABC):

    @abstractmethod
    def login(self, api_authtype, api_key, api_secret):
        pass

    @abstractmethod
    def get_all_components(self):
        pass
